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

#[path = "repository_guards.rs"]
mod guards;
#[path = "repository_helpers.rs"]
mod helpers;
#[path = "repository_ops.rs"]
mod ops;
#[path = "repository_preservation.rs"]
mod preservation;
#[path = "repository_publish.rs"]
mod publish;
use helpers::*;

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
}
