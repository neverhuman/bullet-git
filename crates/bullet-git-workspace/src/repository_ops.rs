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

    fn validate_candidate_preparation(
        &self,
        auth: &AuthorityEnvelope,
        provenance: &CandidateProvenance,
    ) -> Result<(), CapabilityError> {
        self.require_healthy()?;
        let token = self.expected.require(auth)?;
        self.guard()?;
        sequencer_check(self.workspace.repo_dir())?;
        self.require_private_branch()?;
        let entries = self.status_scan()?;
        self.classify_scan(&entries)?;
        let base_checkpoint = self.validate_active_checkpoint()?;
        let base = GitOid::new(self.workspace.base_sha())?;
        self.require_candidate_provenance(&token, provenance, &base_checkpoint, &base)
    }

    fn prepare_candidate(
        &mut self,
        auth: &AuthorityEnvelope,
        change: &Change,
        provenance: &CandidateProvenance,
    ) -> Result<Candidate, CapabilityError> {
        self.validate_candidate_preparation(auth, provenance)?;
        let token = self.expected.require(auth)?;
        let entries = self.status_scan()?;
        let actual_scope = self
            .classify_scan(&entries)?
            .into_iter()
            .map(|path| path.parse::<RepoPath>())
            .collect::<Result<Vec<_>, _>>()?;
        let base_checkpoint = self.validate_active_checkpoint()?;
        let base = GitOid::new(self.workspace.base_sha())?;
        self.require_candidate_provenance(&token, provenance, &base_checkpoint, &base)?;
        let stage = self.workspace.stage_generation()?;
        let stage_repo = stage.repo_dir();
        let stage_journal = DurableJournal::open(stage.journal_dir())?;
        let (head, tree) = self.commit_candidate(&stage_repo, change)?;
        let range = format!("{}..{}", base.hex(), head.hex());
        let patch = self.workspace.git().run(
            Some(&stage_repo),
            FileProtocol::Never,
            &["diff", &range],
            &[],
        )?;
        let manifest = bullet_git_types::CandidateManifest {
            schema_version: provenance.schema_version,
            repository_id: provenance.repository_id.clone(),
            change_id: change.id.clone(),
            producing_attempt_id: provenance.producing_attempt_id.clone(),
            attempt_fence: provenance.attempt_fence,
            work_package_id: provenance.work_package_id.clone(),
            variant_id: provenance.variant_id.clone(),
            plan_revision_id: provenance.plan_revision_id.clone(),
            graph_revision_id: provenance.graph_revision_id.clone(),
            base_checkpoint_id: provenance.base_checkpoint_id.clone(),
            base_commit: base,
            head_commit: head,
            tree_oid: tree,
            patch_digest: Digest::of(&patch.stdout),
            parent_candidate_ids: provenance.parent_candidate_ids.clone(),
            granted_scope: provenance.granted_scope.clone(),
            actual_scope,
            context_capsule_id: provenance.context_capsule_id.clone(),
            configuration_snapshot_id: provenance.configuration_snapshot_id.clone(),
            policy_snapshot_id: provenance.policy_snapshot_id.clone(),
            routing_snapshot_id: provenance.routing_snapshot_id.clone(),
            environment_digest: provenance.environment_digest,
            toolchain_digest: provenance.toolchain_digest,
        };
        let candidate = Candidate::from_manifest(manifest, self.identity.date.clone())?;
        let checkpoint = self.write_tree_checkpoint(&stage_repo, &stage_journal)?;
        self.publish_stage(stage, checkpoint)?;
        Ok(candidate)
    }

    fn query_lineage(
        &self,
        auth: &AuthorityEnvelope,
        change_id: &ChangeId,
    ) -> Result<ChangeEvolution, CapabilityError> {
        self.require_healthy()?;
        self.expected.require(auth)?;
        Ok(self.lineage.query(change_id)?)
    }

    fn record_evolution(
        &mut self,
        auth: &AuthorityEnvelope,
        change: &Change,
        edge: EvolutionEdge,
    ) -> Result<(), CapabilityError> {
        self.require_healthy()?;
        self.expected.require(auth)?;
        self.lineage.record_change(change.clone())?;
        self.lineage.record_edge(&change.id, edge)?;
        Ok(())
    }
}
