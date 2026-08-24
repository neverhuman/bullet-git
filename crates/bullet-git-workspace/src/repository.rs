//! The capability API and its real-Git implementation.

use crate::apply::{apply_all, restore_all};
use crate::clone::{guard_repository, sequencer_check, PrivateClone};
use crate::patch::{validate_batch, PatchHunk, PatchOp};
use crate::safe_git::{FileProtocol, HeadState};
use crate::scope::ScopeGrant;
use crate::status::{parse_status_line, StatusEntry};
use crate::CapabilityError;
use bullet_git_journal::{Checkpoint, Journal};
use bullet_git_types::{
    AuthorityEnvelope, Candidate, CandidateId, Change, Digest, GitOid, WireAuthorityToken,
};
use std::ffi::OsString;
use std::fs;

/// Agent-facing repository capability.
pub trait AgentRepository {
    /// Read the tracked tree listing.
    ///
    /// # Errors
    ///
    /// Returns `UNAUTHORIZED`/`STALE_AUTHORITY` on a bad token.
    fn read_tree(&self, auth: &AuthorityEnvelope) -> Result<Vec<String>, CapabilityError>;

    /// Apply a scoped patch set. Validation is all-or-nothing; writes are
    /// snapshot-rollback atomic so a later IO error restores the prior tree.
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
    journal: Journal,
    checkpoint_count: u64,
}

impl RealRepository {
    /// Bind a private clone to a scope grant and expected authority.
    #[must_use]
    pub fn new(
        workspace: PrivateClone,
        grant: ScopeGrant,
        expected: ExpectedAuthority,
        identity: CommitIdentity,
    ) -> Self {
        Self {
            workspace,
            grant,
            expected,
            identity,
            journal: Journal::new(),
            checkpoint_count: 0,
        }
    }

    /// Borrow the underlying workspace.
    #[must_use]
    pub fn workspace(&self) -> &PrivateClone {
        &self.workspace
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

    fn write_tree_checkpoint(&mut self) -> Result<Checkpoint, CapabilityError> {
        self.checkpoint_count += 1;
        let index_path = self
            .workspace
            .runtime_dir()
            .join(format!("tmp-index-{}", self.checkpoint_count));
        let env = [("GIT_INDEX_FILE", OsString::from(&index_path))];
        let repo = self.workspace.repo_dir().to_path_buf();
        let git = self.workspace.git();
        git.run(
            Some(&repo),
            FileProtocol::Never,
            &["read-tree", "HEAD"],
            &env,
        )?;
        git.run(Some(&repo), FileProtocol::Never, &["add", "-A"], &env)?;
        let tree = git
            .run(Some(&repo), FileProtocol::Never, &["write-tree"], &env)?
            .text();
        let _ = fs::remove_file(&index_path);
        let mut checkpoint = self.journal.checkpoint();
        checkpoint.git_tree = Some(GitOid::new(tree)?);
        Ok(checkpoint)
    }

    fn commit_candidate(&self, change: &Change) -> Result<(GitOid, GitOid), CapabilityError> {
        let repo = self.workspace.repo_dir();
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
}

impl AgentRepository for RealRepository {
    fn read_tree(&self, auth: &AuthorityEnvelope) -> Result<Vec<String>, CapabilityError> {
        self.expected.require(auth)?;
        let out = self.workspace.git().run(
            Some(self.workspace.repo_dir()),
            FileProtocol::Never,
            &["ls-files"],
            &[],
        )?;
        Ok(String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::to_string)
            .collect())
    }

    fn apply_change(
        &mut self,
        auth: &AuthorityEnvelope,
        patches: &[PatchHunk],
    ) -> Result<(), CapabilityError> {
        self.expected.require(auth)?;
        self.guard()?;
        let normalized = self.validate_patches(patches)?;
        let mut undo = Vec::new();
        let applied = apply_all(self.workspace.repo_dir(), patches, &normalized, &mut undo);
        if let Err(err) = applied {
            restore_all(&undo);
            return Err(err);
        }
        for (patch, path) in patches.iter().zip(&normalized) {
            match &patch.op {
                PatchOp::Write(contents) => self.journal.record(path, contents),
                PatchOp::Delete => {
                    if let Some((_, Some(before))) = undo.iter().find(|(p, _)| p.ends_with(path)) {
                        self.journal.record_delete(path, before);
                    }
                }
            }
        }
        Ok(())
    }

    fn checkpoint(&mut self, auth: &AuthorityEnvelope) -> Result<Checkpoint, CapabilityError> {
        self.expected.require(auth)?;
        self.guard()?;
        sequencer_check(self.workspace.repo_dir())?;
        self.write_tree_checkpoint()
    }

    fn prepare_candidate(
        &mut self,
        auth: &AuthorityEnvelope,
        change: &Change,
    ) -> Result<Candidate, CapabilityError> {
        self.expected.require(auth)?;
        self.guard()?;
        sequencer_check(self.workspace.repo_dir())?;
        self.require_private_branch()?;
        let entries = self.status_scan()?;
        let actual_scope = self.classify_scan(&entries)?;
        let _ = self.write_tree_checkpoint()?;
        let (head, tree) = self.commit_candidate(change)?;
        let base = GitOid::new(self.workspace.base_sha())?;
        let range = format!("{base}..{head}");
        let patch = self.workspace.git().run(
            Some(self.workspace.repo_dir()),
            FileProtocol::Never,
            &["diff", &range],
            &[],
        )?;
        let patch_hash = Digest::of(&patch.stdout);
        let manifest = self.workspace.manifest();
        Ok(Candidate {
            id: CandidateId::from_content(&change.id, &tree, &head),
            change: change.id.clone(),
            base_commit: base,
            head_commit: head,
            tree_hash: tree,
            patch_hash,
            variant_id: manifest.variant_id.clone(),
            attempt_id: manifest.attempt_id.clone(),
            granted_scope: self.grant.allowed_prefixes.clone(),
            actual_scope,
            parent_candidate_id: None,
            prepared_at: self.identity.date.clone(),
            lineage_subject: None,
            environment_digest: None,
        })
    }
}
