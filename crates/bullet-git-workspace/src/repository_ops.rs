//! AgentRepository operations over immutable workspace generations.

use super::*;
use crate::clone::sequencer_check;

impl AgentRepository for RealRepository {
    fn read_tree(&self, auth: &AuthorityEnvelope) -> Result<Vec<String>, CapabilityError> {
        self.require_healthy()?;
        self.expected.require(auth)?;
        self.guard()?;
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
        self.require_healthy()?;
        self.expected.require(auth)?;
        self.guard()?;
        let normalized = self.validate_patches(patches)?;
        self.publish_patches(patches, &normalized).map(|_| ())
    }

    fn apply_proposal(
        &mut self,
        auth: &AuthorityEnvelope,
        proposal: &PatchProposal,
    ) -> Result<Checkpoint, CapabilityError> {
        self.require_healthy()?;
        self.expected.require(auth)?;
        self.guard()?;
        proposal.validate()?;
        self.require_proposal_attempt(proposal)?;
        let active = self.validate_active_checkpoint()?;
        self.require_proposal_checkpoint(proposal, &active)?;
        let patches = Self::proposal_patches(proposal);
        let normalized = self.validate_patches(&patches)?;
        let preimages = self.require_proposal_preimages(proposal, &normalized)?;
        self.publish_proposal_patches(proposal, &patches, &normalized, &preimages)
    }

    fn checkpoint(&mut self, auth: &AuthorityEnvelope) -> Result<Checkpoint, CapabilityError> {
        self.require_healthy()?;
        self.expected.require(auth)?;
        self.guard()?;
        sequencer_check(self.workspace.repo_dir())?;
        self.validate_active_checkpoint()
    }

    fn prepare_candidate(
        &mut self,
        auth: &AuthorityEnvelope,
        change: &Change,
    ) -> Result<Candidate, CapabilityError> {
        self.require_healthy()?;
        self.expected.require(auth)?;
        self.guard()?;
        sequencer_check(self.workspace.repo_dir())?;
        self.require_private_branch()?;
        let entries = self.status_scan()?;
        let actual_scope = self.classify_scan(&entries)?;
        let stage = self.workspace.stage_generation()?;
        let stage_repo = stage.repo_dir();
        let stage_journal = DurableJournal::open(stage.journal_dir())?;
        let (head, tree) = self.commit_candidate(&stage_repo, change)?;
        let checkpoint = self.write_tree_checkpoint(&stage_repo, &stage_journal)?;
        self.publish_stage(stage, checkpoint)?;

        let base = GitOid::new(self.workspace.base_sha())?;
        let range = format!("{}..{}", base.hex(), head.hex());
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
