//! The capability API and its real-Git implementation.

use crate::cas::{CasError, ImmutableCas};
use crate::clone::{guard_repository, PrivateClone};
use crate::generation::{GenerationError, StagedGeneration};
use crate::lineage::WorkspaceLineage;
use crate::patch::{validate_batch, PatchHunk, PatchOp};
use crate::safe_git::{FileProtocol, HeadState};
use crate::scope::ScopeGrant;
use crate::status::{parse_status_line, StatusEntry};
use crate::CapabilityError;
use bullet_git_journal::{Checkpoint, DurableJournal, JournalMutation};
use bullet_git_types::{
    AuthorityEnvelope, Candidate, CandidateProvenance, Change, ChangeEvolution, ChangeId, Digest,
    EvolutionEdge, GitOid, PatchMutation, PatchProposal, Preimage, RepoPath, WireAuthorityToken,
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

    /// Apply one canonical proposal against its exact checkpoint and path
    /// preimages. The returned checkpoint is the newly active generation.
    ///
    /// # Errors
    ///
    /// Returns authority, proposal, checkpoint, preimage, scope, symlink, or
    /// generation errors. Any validation refusal leaves the prior generation
    /// and journal authoritative.
    fn apply_proposal(
        &mut self,
        auth: &AuthorityEnvelope,
        proposal: &PatchProposal,
    ) -> Result<Checkpoint, CapabilityError>;

    /// Checkpoint the journal and the working tree without touching the live
    /// index (temporary `GIT_INDEX_FILE`).
    ///
    /// # Errors
    ///
    /// Returns authority, sequencer, or git errors.
    fn checkpoint(&mut self, auth: &AuthorityEnvelope) -> Result<Checkpoint, CapabilityError>;

    /// Read-only refusal check for Candidate preparation. Daemon dispatch
    /// calls this before consuming a one-use mutation permit; the writer calls
    /// it again at its final boundary.
    ///
    /// # Errors
    ///
    /// Returns authority, provenance, workspace, scope, checkpoint, or Git
    /// refusals without publishing a generation or controlled commit.
    fn validate_candidate_preparation(
        &self,
        auth: &AuthorityEnvelope,
        provenance: &CandidateProvenance,
    ) -> Result<(), CapabilityError>;

    /// Prepare an exact Candidate from a fresh workspace scan.
    ///
    /// # Errors
    ///
    /// Returns authority, scope, sequencer, or git errors.
    fn prepare_candidate(
        &mut self,
        auth: &AuthorityEnvelope,
        change: &Change,
        provenance: &CandidateProvenance,
    ) -> Result<Candidate, CapabilityError>;

    /// Query the durable Change graph. A ChangeId never authorizes integration.
    ///
    /// # Errors
    ///
    /// Missing Change or authority failure.
    fn query_lineage(
        &self,
        auth: &AuthorityEnvelope,
        change_id: &ChangeId,
    ) -> Result<ChangeEvolution, CapabilityError>;

    /// Record one evolution edge after a new Candidate exists.
    ///
    /// # Errors
    ///
    /// Missing Change or authority failure.
    fn record_evolution(
        &mut self,
        auth: &AuthorityEnvelope,
        change: &Change,
        edge: EvolutionEdge,
    ) -> Result<(), CapabilityError>;
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
    lineage: WorkspaceLineage,
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
            lineage: WorkspaceLineage::new(),
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

    /// Borrow the already-validated active generation checkpoint.
    ///
    /// Construction and every generation publication validate this exact
    /// persisted checkpoint. Reading it performs no Git, journal, CAS, tree,
    /// generation, or authority-settlement operation.
    #[must_use]
    pub fn active_checkpoint(&self) -> &Checkpoint {
        self.workspace.generation_checkpoint()
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

    fn proposal_patches(proposal: &PatchProposal) -> Vec<PatchHunk> {
        proposal
            .operations
            .iter()
            .map(|operation| match &operation.mutation {
                PatchMutation::Write { content_utf8 } => {
                    PatchHunk::write(operation.path.as_str(), content_utf8.as_bytes().to_vec())
                }
                PatchMutation::Delete => PatchHunk::delete(operation.path.as_str()),
            })
            .collect()
    }

    fn require_proposal_attempt(&self, proposal: &PatchProposal) -> Result<(), CapabilityError> {
        if proposal.producing_attempt_id.as_str() == self.expected.attempt_id {
            Ok(())
        } else {
            Err(CapabilityError::ProposalAttemptMismatch {
                expected: self.expected.attempt_id.clone(),
                found: proposal.producing_attempt_id.to_string(),
            })
        }
    }

    fn require_candidate_provenance(
        &self,
        token: &WireAuthorityToken,
        provenance: &CandidateProvenance,
        active_checkpoint: &Checkpoint,
        base_commit: &GitOid,
    ) -> Result<(), CapabilityError> {
        provenance.validate()?;
        require_candidate_field(
            "producing_attempt_id",
            &self.expected.attempt_id,
            provenance.producing_attempt_id.as_str(),
        )?;
        require_candidate_field(
            "attempt_fence",
            &self.expected.attempt_fence.to_string(),
            &provenance.attempt_fence.to_string(),
        )?;
        require_candidate_field(
            "variant_id",
            &self.workspace.manifest().variant_id,
            provenance.variant_id.as_str(),
        )?;
        require_candidate_field(
            "authority_variant_id",
            &token.variant_id,
            provenance.variant_id.as_str(),
        )?;
        require_candidate_field(
            "base_checkpoint_id",
            active_checkpoint.id.as_str(),
            provenance.base_checkpoint_id.as_str(),
        )?;
        require_candidate_field(
            "base_commit",
            base_commit.as_str(),
            provenance.base_commit.as_str(),
        )?;
        let local_grant = self
            .grant
            .allowed_prefixes
            .iter()
            .map(|path| path.parse::<RepoPath>())
            .collect::<Result<Vec<_>, _>>()?;
        if provenance.granted_scope != local_grant {
            return Err(CapabilityError::CandidateSubjectMismatch {
                field: "granted_scope",
                expected: serde_json::to_string(&local_grant)
                    .unwrap_or_else(|_| "<unencodable>".into()),
                found: serde_json::to_string(&provenance.granted_scope)
                    .unwrap_or_else(|_| "<unencodable>".into()),
            });
        }
        Ok(())
    }

    fn require_proposal_checkpoint(
        &self,
        proposal: &PatchProposal,
        active: &Checkpoint,
    ) -> Result<(), CapabilityError> {
        if proposal.base_checkpoint_id == active.id
            && proposal.base_checkpoint_digest == active.digest
        {
            Ok(())
        } else {
            Err(CapabilityError::StaleCheckpoint(format!(
                "expected {}:{}, found {}:{}",
                active.id,
                active.digest.to_hex(),
                proposal.base_checkpoint_id,
                proposal.base_checkpoint_digest.to_hex()
            )))
        }
    }

    fn require_proposal_preimages(
        &self,
        proposal: &PatchProposal,
        normalized: &[String],
    ) -> Result<Vec<Option<Vec<u8>>>, CapabilityError> {
        let mut verified = Vec::with_capacity(proposal.operations.len());
        for (operation, path) in proposal.operations.iter().zip(normalized) {
            let current = read_proposal_file_nofollow(self.workspace.repo_dir(), path)?;
            match (&operation.preimage, current) {
                (Preimage::Absent, None) => verified.push(None),
                (Preimage::Digest { digest }, Some(bytes)) if Digest::of(&bytes) == *digest => {
                    verified.push(Some(bytes));
                }
                _ => return Err(CapabilityError::StalePreimage(path.clone())),
            }
        }
        Ok(verified)
    }

    fn publish_patches(
        &mut self,
        patches: &[PatchHunk],
        normalized: &[String],
    ) -> Result<Checkpoint, CapabilityError> {
        let mutations = self.prepare_journal_mutations(patches, normalized)?;
        self.publish_prepared_patches(patches, normalized, &mutations)
    }

    fn publish_proposal_patches(
        &mut self,
        proposal: &PatchProposal,
        patches: &[PatchHunk],
        normalized: &[String],
        preimages: &[Option<Vec<u8>>],
    ) -> Result<Checkpoint, CapabilityError> {
        let mutations = proposal
            .operations
            .iter()
            .zip(normalized)
            .zip(preimages)
            .map(|((operation, path), prior)| {
                let before = prior
                    .as_deref()
                    .map(|bytes| self.cas.put(bytes).map(|stored| stored.digest))
                    .transpose()?;
                match &operation.mutation {
                    PatchMutation::Write { content_utf8 } => Ok(JournalMutation::write(
                        path,
                        before,
                        self.cas.put(content_utf8.as_bytes())?.digest,
                    )),
                    PatchMutation::Delete => Ok(JournalMutation::delete(
                        path,
                        before.expect("validated delete always has stable preimage bytes"),
                    )),
                }
            })
            .collect::<Result<Vec<_>, CapabilityError>>()?;
        self.publish_prepared_patches(patches, normalized, &mutations)
    }

    fn publish_prepared_patches(
        &mut self,
        patches: &[PatchHunk],
        normalized: &[String],
        mutations: &[JournalMutation],
    ) -> Result<Checkpoint, CapabilityError> {
        let stage = self.workspace.stage_generation()?;
        let stage_repo = stage.repo_dir();
        let mut stage_journal = DurableJournal::open(stage.journal_dir())?;
        let mut unrestored = Vec::new();
        if let Err(error) =
            crate::apply::apply_all(&stage_repo, patches, normalized, &mut unrestored)
        {
            return Err(match crate::apply::restore_all(&unrestored) {
                Some(rollback) => error.with_failed_rollback(&rollback),
                None => error,
            });
        }
        stage_journal.record_batch(mutations)?;
        validate_journal_objects(&stage_journal, &self.cas)?;
        let checkpoint = self.write_tree_checkpoint(&stage_repo, &stage_journal)?;
        self.publish_stage(stage, checkpoint.clone())?;
        Ok(checkpoint)
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
            Ok(journal
                .checkpoint()
                .bind_git_tree(self.workspace.git_oid(tree)?))
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
        Ok((self.workspace.git_oid(head)?, self.workspace.git_oid(tree)?))
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

#[cfg(target_os = "linux")]
fn read_proposal_file_nofollow(
    repo_dir: &Path,
    path: &str,
) -> Result<Option<Vec<u8>>, CapabilityError> {
    use rustix::fs::{open, openat2, Mode, OFlags, ResolveFlags};
    use std::io::Read as _;

    let root = open(
        repo_dir,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| CapabilityError::Io(format!("open proposal repository root: {error}")))?;
    let descriptor = match openat2(
        &root,
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    ) {
        Ok(descriptor) => descriptor,
        Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
        Err(_) => return Err(CapabilityError::StalePreimage(path.to_owned())),
    };
    let mut file = File::from(descriptor);
    if !file
        .metadata()
        .map_err(|error| crate::io_err("inspect proposal preimage descriptor", &error))?
        .is_file()
    {
        return Err(CapabilityError::StalePreimage(path.to_owned()));
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take((crate::MAX_CAS_OBJECT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| crate::io_err("read proposal preimage descriptor", &error))?;
    if bytes.len() > crate::MAX_CAS_OBJECT_BYTES {
        return Err(CasError::ObjectTooLarge {
            max: crate::MAX_CAS_OBJECT_BYTES,
            actual: bytes.len(),
        }
        .into());
    }
    Ok(Some(bytes))
}

#[cfg(not(target_os = "linux"))]
fn read_proposal_file_nofollow(
    _repo_dir: &Path,
    _path: &str,
) -> Result<Option<Vec<u8>>, CapabilityError> {
    Err(CapabilityError::Io(
        "safe proposal preimage reads require the admitted Linux openat2 backend".into(),
    ))
}

#[cfg(all(test, target_os = "linux"))]
mod proposal_preimage_tests {
    use super::*;

    #[test]
    fn descriptor_relative_read_never_follows_parent_symlink() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = temp.path().join("repo");
        let outside = temp.path().join("outside");
        fs::create_dir(&repo).expect("repo");
        fs::create_dir(&outside).expect("outside");
        fs::write(outside.join("secret"), b"outside bytes").expect("outside fixture");
        std::os::unix::fs::symlink(&outside, repo.join("src")).expect("parent symlink");

        let error =
            read_proposal_file_nofollow(&repo, "src/secret").expect_err("parent symlink refused");
        assert_eq!(error.reason_code(), "STALE_PREIMAGE");
    }
}

fn require_candidate_field(
    field: &'static str,
    expected: &str,
    found: &str,
) -> Result<(), CapabilityError> {
    if expected == found {
        Ok(())
    } else {
        Err(CapabilityError::CandidateSubjectMismatch {
            field,
            expected: expected.to_owned(),
            found: found.to_owned(),
        })
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
