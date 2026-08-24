//! The capability API and its real-Git implementation.

use crate::cas::{CasError, ImmutableCas};
use crate::clone::{guard_repository, PrivateClone};
use crate::generation::{GenerationError, StagedGeneration};
use crate::patch::{validate_batch, PatchHunk, PatchOp};
use crate::safe_git::{FileProtocol, HeadState};
use crate::scope::ScopeGrant;
use crate::status::{parse_status_line, StatusEntry};
use crate::CapabilityError;
use bullet_git_journal::{Checkpoint, DurableJournal, JournalMutation};
use bullet_git_types::{
    AuthorityEnvelope, Candidate, CandidateId, Change, Digest, GitOid, WireAuthorityToken,
};
use std::cell::Cell;
use std::ffi::OsString;
use std::fs::{self, File};
use std::path::Path;

#[path = "repository_ops.rs"]
mod ops;
#[path = "repository_preservation.rs"]
mod preservation;

/// Agent-facing repository capability.
pub trait AgentRepository {
    /// Read the tracked tree listing.
    ///
    /// # Errors
    ///
    /// Returns `UNAUTHORIZED`/`STALE_AUTHORITY` on a bad token.
    fn read_tree(&self, auth: &AuthorityEnvelope) -> Result<Vec<String>, CapabilityError>;

    /// Apply a scoped patch set. Validation is all-or-nothing; a complete
    /// staged generation becomes active through one durable pointer switch.
    ///
    /// # Errors
    ///
    /// Returns authority, scope, symlink, or worktree errors.
    fn apply_change(
        &mut self,
        auth: &AuthorityEnvelope,
        patches: &[PatchHunk],
    ) -> Result<(), CapabilityError>;

    /// Checkpoint the journal and the working tree without touching the live
    /// index (temporary `GIT_INDEX_FILE`).
    ///
    /// # Errors
    ///
    /// Returns authority, sequencer, or git errors.
    fn checkpoint(&mut self, auth: &AuthorityEnvelope) -> Result<Checkpoint, CapabilityError>;

    /// Prepare an exact Candidate from a fresh workspace scan.
    ///
    /// # Errors
    ///
    /// Returns authority, scope, sequencer, or git errors.
    fn prepare_candidate(
        &mut self,
        auth: &AuthorityEnvelope,
        change: &Change,
    ) -> Result<Candidate, CapabilityError>;
}

/// Expected authority captured at workspace creation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedAuthority {
    /// Attempt incarnation.
    pub attempt_id: String,
    /// Permanent fence epoch.
    pub attempt_fence: u64,
    /// Workspace nonce.
    pub workspace_nonce: [u8; 32],
}

impl ExpectedAuthority {
    /// Parse and verify an envelope against the expected authority.
    ///
    /// # Errors
    ///
    /// Returns `UNAUTHORIZED` for empty/unparseable tokens, `STALE_AUTHORITY`
    /// for mismatches.
    pub fn require(&self, auth: &AuthorityEnvelope) -> Result<WireAuthorityToken, CapabilityError> {
        let token = WireAuthorityToken::parse(&auth.token)?;
        token.verify(&self.attempt_id, self.attempt_fence, &self.workspace_nonce)?;
        Ok(token)
    }
}

/// Fixed commit identity for controlled candidate commits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitIdentity {
    /// Author/committer name.
    pub name: String,
    /// Author/committer email.
    pub email: String,
    /// Fixed author/committer date, passed in by the caller.
    pub date: String,
}

impl CommitIdentity {
    /// The Bullet Farm identity with a caller-supplied fixed date.
    #[must_use]
    pub fn farm(date: &str) -> Self {
        Self {
            name: "Bullet Farm".into(),
            email: "farm@bullet.local".into(),
            date: date.into(),
        }
    }

    fn env(&self) -> Vec<(&'static str, OsString)> {
        vec![
            ("GIT_AUTHOR_NAME", OsString::from(&self.name)),
            ("GIT_AUTHOR_EMAIL", OsString::from(&self.email)),
            ("GIT_AUTHOR_DATE", OsString::from(&self.date)),
            ("GIT_COMMITTER_NAME", OsString::from(&self.name)),
            ("GIT_COMMITTER_EMAIL", OsString::from(&self.email)),
            ("GIT_COMMITTER_DATE", OsString::from(&self.date)),
        ]
    }
}

/// Real repository over a private clone: the sole workspace writer.
pub struct RealRepository {
    workspace: PrivateClone,
    grant: ScopeGrant,
    expected: ExpectedAuthority,
    identity: CommitIdentity,
    journal: DurableJournal,
    cas: ImmutableCas,
    checkpoint_count: Cell<u64>,
    healthy: bool,
}

impl RealRepository {
    /// Bind a private clone to a scope grant and expected authority.
    pub fn new(
        mut workspace: PrivateClone,
        grant: ScopeGrant,
        expected: ExpectedAuthority,
        identity: CommitIdentity,
    ) -> Result<Self, CapabilityError> {
        workspace.reopen_generation()?;
        let journal = DurableJournal::open(workspace.journal_dir())?;
        let cas = open_workspace_cas(workspace.runtime_dir())?;
        validate_journal_objects(&journal, &cas)?;
        let repository = Self {
            workspace,
            grant,
            expected,
            identity,
            journal,
            cas,
            checkpoint_count: Cell::new(0),
            healthy: true,
        };
        repository.guard()?;
        repository.require_private_branch()?;
        repository.validate_active_checkpoint()?;
        Ok(repository)
    }

    /// Borrow the underlying workspace.
    #[must_use]
    pub fn workspace(&self) -> &PrivateClone {
        &self.workspace
    }

    pub(crate) fn workspace_mut(&mut self) -> &mut PrivateClone {
        &mut self.workspace
    }

    /// Release the underlying workspace (for cleanup).
    #[must_use]
    pub fn into_workspace(self) -> PrivateClone {
        self.workspace
    }

    /// Journal ops recorded so far (writes and deletions).
    #[must_use]
    pub fn journal_ops(&self) -> &[bullet_git_journal::JournalOp] {
        self.journal.ops()
    }

    fn guard(&self) -> Result<(), CapabilityError> {
        guard_repository(self.workspace.git(), self.workspace.repo_dir())
    }

    fn require_healthy(&self) -> Result<(), CapabilityError> {
        if self.healthy {
            Ok(())
        } else {
            Err(GenerationError::OutcomeUnknown(
                "writer must reopen after an indeterminate generation switch".into(),
            )
            .into())
        }
    }

    fn symlink_check(&self, normalized: &str) -> Result<(), CapabilityError> {
        let mut current = self.workspace.repo_dir().to_path_buf();
        for segment in normalized.split('/') {
            current.push(segment);
            match fs::symlink_metadata(&current) {
                Ok(meta) if meta.file_type().is_symlink() => {
                    return Err(CapabilityError::SymlinkForbidden(normalized.to_string()));
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        Ok(())
    }

    fn validate_patches(&self, patches: &[PatchHunk]) -> Result<Vec<String>, CapabilityError> {
        let repo_dir = self.workspace.repo_dir();
        let normalized = validate_batch(&self.grant, patches, |path| {
            fs::symlink_metadata(repo_dir.join(path)).is_ok_and(|meta| meta.is_file())
        })?;
        for path in &normalized {
            self.symlink_check(path)?;
        }
        Ok(normalized)
    }

    fn status_scan(&self) -> Result<Vec<StatusEntry>, CapabilityError> {
        let out = self.workspace.git().run(
            Some(self.workspace.repo_dir()),
            FileProtocol::Never,
            &["status", "--porcelain=v2", "--untracked-files=all"],
            &[],
        )?;
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let mut entries = Vec::new();
        for line in text.lines() {
            if let Some(entry) = parse_status_line(line) {
                entries.push(entry);
            }
        }
        Ok(entries)
    }

    fn classify_scan(&self, entries: &[StatusEntry]) -> Result<Vec<String>, CapabilityError> {
        let mut touched = Vec::new();
        for entry in entries {
            match entry {
                StatusEntry::Untracked(path) => {
                    let ok = crate::scope::normalize_rel_path(path)
                        .is_ok_and(|n| self.grant.permits(&n));
                    if !ok {
                        return Err(CapabilityError::UnclassifiedUntracked(path.clone()));
                    }
                    touched.push(path.clone());
                }
                StatusEntry::Tracked(path) => {
                    let normalized = crate::scope::normalize_rel_path(path)?;
                    if !self.grant.permits(&normalized) {
                        return Err(CapabilityError::OutOfScope(path.clone()));
                    }
                    touched.push(normalized);
                }
            }
        }
        touched.sort();
        touched.dedup();
        Ok(touched)
    }

    fn prepare_journal_mutations(
        &self,
        patches: &[PatchHunk],
        normalized: &[String],
    ) -> Result<Vec<JournalMutation>, CapabilityError> {
        patches
            .iter()
            .zip(normalized)
            .map(|(patch, path)| {
                let target = self.workspace.repo_dir().join(path);
                let prior = match fs::symlink_metadata(&target) {
                    Ok(metadata) if metadata.is_file() => Some(
                        fs::read(&target)
                            .map_err(|error| crate::io_err("read patch preimage", &error))?,
                    ),
                    Ok(_) => None,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                    Err(error) => return Err(crate::io_err("inspect patch preimage", &error)),
                };
                let before = prior
                    .as_deref()
                    .map(|bytes| self.cas.put(bytes).map(|stored| stored.digest))
                    .transpose()?;
                match &patch.op {
                    PatchOp::Write(contents) => Ok(JournalMutation::write(
                        path,
                        before,
                        self.cas.put(contents)?.digest,
                    )),
                    PatchOp::Delete => Ok(JournalMutation::delete(
                        path,
                        before.expect("validated delete always has before-state bytes"),
                    )),
                }
            })
            .collect()
    }

    fn write_tree_checkpoint(
        &self,
        repo: &Path,
        journal: &DurableJournal,
    ) -> Result<Checkpoint, CapabilityError> {
        let checkpoint_count = self
            .checkpoint_count
            .get()
            .checked_add(1)
            .ok_or_else(|| GenerationError::Corrupt("checkpoint counter overflow".into()))?;
        self.checkpoint_count.set(checkpoint_count);
        let index_path = self
            .workspace
            .runtime_dir()
            .join(format!("generation-index-{checkpoint_count}"));
        let env = [("GIT_INDEX_FILE", OsString::from(&index_path))];
        let git = self.workspace.git();
        let result = (|| {
            git.run(
                Some(repo),
                FileProtocol::Never,
                &["read-tree", "HEAD"],
                &env,
            )?;
            git.run(Some(repo), FileProtocol::Never, &["add", "-A"], &env)?;
            let tree = git
                .run(Some(repo), FileProtocol::Never, &["write-tree"], &env)?
                .text();
            Ok(journal.checkpoint().bind_git_tree(GitOid::new(tree)?))
        })();
        let _ = fs::remove_file(&index_path);
        result
    }

    fn commit_candidate(
        &self,
        repo: &Path,
        change: &Change,
    ) -> Result<(GitOid, GitOid), CapabilityError> {
        let git = self.workspace.git();
        let env = self.identity.env();
        git.run(Some(repo), FileProtocol::Never, &["add", "-A"], &[])?;
        let message = format!("bullet: candidate for {}", change.id);
        git.run(
            Some(repo),
            FileProtocol::Never,
            &["commit", "--allow-empty", "--no-verify", "-m", &message],
            &env,
        )?;
        let head = git
            .run(Some(repo), FileProtocol::Never, &["rev-parse", "HEAD"], &[])?
            .text();
        let tree = git
            .run(
                Some(repo),
                FileProtocol::Never,
                &["rev-parse", "HEAD^{tree}"],
                &[],
            )?
            .text();
        Ok((GitOid::new(head)?, GitOid::new(tree)?))
    }

    fn require_private_branch(&self) -> Result<(), CapabilityError> {
        match self.workspace.git().head_state(self.workspace.repo_dir())? {
            HeadState::Branch(name) if name == self.workspace.branch() => Ok(()),
            HeadState::Branch(name) => Err(CapabilityError::WrongBranch {
                expected: self.workspace.branch().to_string(),
                found: name,
            }),
            HeadState::Detached => Err(CapabilityError::WrongBranch {
                expected: self.workspace.branch().to_string(),
                found: "(detached)".into(),
            }),
        }
    }

    fn validate_active_checkpoint(&self) -> Result<Checkpoint, CapabilityError> {
        let checkpoint = self.write_tree_checkpoint(self.workspace.repo_dir(), &self.journal)?;
        if &checkpoint != self.workspace.generation_checkpoint() {
            return Err(GenerationError::Corrupt(
                "active repository or journal does not match its generation manifest".into(),
            )
            .into());
        }
        Ok(checkpoint)
    }

    fn publish_stage(
        &mut self,
        stage: StagedGeneration,
        checkpoint: Checkpoint,
    ) -> Result<(), CapabilityError> {
        if let Err(error) = self.workspace.publish_generation(stage, checkpoint) {
            if matches!(&error, CapabilityError::Generation(inner) if inner.may_have_published()) {
                self.healthy = false;
            }
            return Err(error);
        }
        match DurableJournal::open(self.workspace.journal_dir()) {
            Ok(journal) => {
                if let Err(error) = validate_journal_objects(&journal, &self.cas) {
                    self.healthy = false;
                    return Err(GenerationError::OutcomeUnknown(format!(
                        "published generation CAS validation failed: {error}"
                    ))
                    .into());
                }
                self.journal = journal;
                Ok(())
            }
            Err(error) => {
                self.healthy = false;
                Err(GenerationError::OutcomeUnknown(format!(
                    "published generation journal did not reopen: {error}"
                ))
                .into())
            }
        }
    }
}

fn open_workspace_cas(runtime_dir: &std::path::Path) -> Result<ImmutableCas, CapabilityError> {
    let root = runtime_dir.join("cas");
    match fs::symlink_metadata(&root) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(&root).map_err(|error| crate::io_err("create workspace CAS", &error))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                    .map_err(|error| crate::io_err("secure workspace CAS", &error))?;
            }
            File::open(runtime_dir)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| crate::io_err("sync workspace runtime", &error))?;
        }
        Err(error) => return Err(crate::io_err("inspect workspace CAS", &error)),
    }
    ImmutableCas::open(&root).map_err(Into::into)
}

fn validate_journal_objects(
    journal: &DurableJournal,
    cas: &ImmutableCas,
) -> Result<(), CapabilityError> {
    for op in journal.ops() {
        for digest in [op.before.as_ref(), op.after.as_ref()]
            .into_iter()
            .flatten()
        {
            if cas.get(digest)?.is_none() {
                return Err(CasError::Corrupt(format!(
                    "journal sequence {} references missing object {}",
                    op.seq,
                    digest.to_hex()
                ))
                .into());
            }
        }
    }
    Ok(())
}
