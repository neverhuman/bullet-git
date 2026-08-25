//! Workspace-local Change lineage. Advisers must not write this store.

use bullet_git_types::{
    Change, ChangeEvolution, ChangeId, EvolutionEdge, LineageError, LineageGraph,
};
use std::cell::RefCell;

/// Process-local lineage attached to a workspace.
#[derive(Clone, Debug, Default)]
pub struct WorkspaceLineage {
    graph: RefCell<LineageGraph>,
}

impl WorkspaceLineage {
    /// Empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a Change.
    ///
    /// # Errors
    ///
    /// Subject mismatch.
    pub fn record_change(&self, change: Change) -> Result<(), LineageError> {
        self.graph.borrow_mut().record_change(change)
    }

    /// Record an evolution edge.
    ///
    /// # Errors
    ///
    /// Missing Change.
    pub fn record_edge(
        &self,
        change_id: &ChangeId,
        edge: EvolutionEdge,
    ) -> Result<(), LineageError> {
        self.graph.borrow_mut().record_edge(change_id, edge)
    }

    /// Query one Change.
    ///
    /// # Errors
    ///
    /// Missing Change.
    pub fn query(&self, change_id: &ChangeId) -> Result<ChangeEvolution, LineageError> {
        self.graph.borrow().query(change_id)
    }
}
