//! Queryable Change graph. A ChangeId never authorizes integration.

use crate::{CandidateId, Change, ChangeId, EvolutionEdge};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// One Change and the edges that rewrote its Candidates.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeEvolution {
    /// Stable intention.
    pub change: Change,
    /// Ordered edges. The ChangeId may survive; CandidateIds never do.
    pub edges: Vec<EvolutionEdge>,
}

impl ChangeEvolution {
    /// Evidence IDs conceptually bound to any predecessor named by an invalidating edge.
    #[must_use]
    pub fn invalidated_predecessors(&self) -> Vec<CandidateId> {
        self.edges
            .iter()
            .filter(|edge| edge.invalidates_evidence())
            .map(|edge| edge.from.clone())
            .collect()
    }
}

/// In-memory Change lineage. Persistence is a caller concern.
#[derive(Clone, Debug, Default)]
pub struct LineageGraph {
    changes: Vec<ChangeEvolution>,
}

/// Lineage refusal.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum LineageError {
    /// Change is not recorded.
    #[error("change not found: {0}")]
    NotFound(String),
    /// Edge names a Change that does not own the predecessor.
    #[error("lineage subject mismatch: {0}")]
    SubjectMismatch(String),
}

impl LineageError {
    /// Stable reason code.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::NotFound(_) => "CHANGE_NOT_FOUND",
            Self::SubjectMismatch(_) => "LINEAGE_SUBJECT_MISMATCH",
        }
    }
}

impl LineageGraph {
    /// Empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a Change. Replacing the same id is refused unless bytes match.
    ///
    /// # Errors
    ///
    /// Subject mismatch when the id already exists with different fields.
    pub fn record_change(&mut self, change: Change) -> Result<(), LineageError> {
        if let Some(existing) = self.changes.iter().find(|row| row.change.id == change.id) {
            if existing.change != change {
                return Err(LineageError::SubjectMismatch(change.id.to_string()));
            }
            return Ok(());
        }
        self.changes.push(ChangeEvolution {
            change,
            edges: Vec::new(),
        });
        Ok(())
    }

    /// Append an evolution edge to a recorded Change.
    ///
    /// # Errors
    ///
    /// Missing Change.
    pub fn record_edge(
        &mut self,
        change_id: &ChangeId,
        edge: EvolutionEdge,
    ) -> Result<(), LineageError> {
        let row = self
            .changes
            .iter_mut()
            .find(|row| row.change.id == *change_id)
            .ok_or_else(|| LineageError::NotFound(change_id.to_string()))?;
        row.edges.push(edge);
        Ok(())
    }

    /// Query one Change.
    ///
    /// # Errors
    ///
    /// Missing Change.
    pub fn query(&self, change_id: &ChangeId) -> Result<ChangeEvolution, LineageError> {
        self.changes
            .iter()
            .find(|row| row.change.id == *change_id)
            .cloned()
            .ok_or_else(|| LineageError::NotFound(change_id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CandidateId, ChangeId, Digest, EvolutionKind};

    fn change() -> Change {
        Change {
            id: ChangeId::from_seed("lineage"),
            mission: "demo".into(),
            acceptance_root: Digest::of(b"acc"),
        }
    }

    #[test]
    fn rebase_invalidates_predecessor_evidence() {
        let mut graph = LineageGraph::new();
        graph.record_change(change()).expect("change");
        let from = CandidateId::from_seed("c1");
        let to = CandidateId::from_seed("c2");
        graph
            .record_edge(
                &change().id,
                EvolutionEdge {
                    from: from.clone(),
                    to,
                    kind: EvolutionKind::Rebase,
                },
            )
            .expect("edge");
        let evo = graph.query(&change().id).expect("query");
        assert_eq!(evo.invalidated_predecessors(), vec![from]);
        assert!(!EvolutionKind::Repair.invalidates_evidence());
        assert!(EvolutionKind::Rebase.invalidates_evidence());
    }
}
