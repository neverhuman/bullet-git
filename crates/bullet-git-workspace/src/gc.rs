//! Trust-aware GC: retention classes and object tombstone pins.
//!
//! `git gc --prune=now` may delete unreachable objects. Live workspaces and
//! tombstoned objects stay reachable through `refs/bullet/retain/...` so a
//! hostile prune cannot erase them.

use crate::{CapabilityError, FileProtocol, SafeGit};
use bullet_git_types::GitOid;
use std::path::Path;

/// Why an object must survive or may be pruned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetentionClass {
    /// Object belongs to a live private workspace.
    LiveWorkspace,
    /// Object is tombstoned and must remain readable.
    Tombstoned,
    /// Object has no retain pin and may be pruned.
    Eligible,
}

impl RetentionClass {
    /// Whether `git gc --prune` may drop objects of this class.
    #[must_use]
    pub const fn may_prune(self) -> bool {
        matches!(self, Self::Eligible)
    }

    /// Ref namespace used to keep the object reachable, if any.
    #[must_use]
    pub const fn retain_namespace(self) -> Option<&'static str> {
        match self {
            Self::LiveWorkspace => Some("refs/bullet/retain/live"),
            Self::Tombstoned => Some("refs/bullet/retain/tombstone"),
            Self::Eligible => None,
        }
    }
}

/// One object plus the class that governs prune.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionPin {
    /// Object identity.
    pub oid: GitOid,
    /// Retention class.
    pub class: RetentionClass,
}

/// Pin a live or tombstoned object so `gc --prune=now` cannot drop it.
///
/// # Errors
///
/// `IO_FAILED` when the class is eligible, or `GIT_FAILED` when the ref update
/// fails.
pub fn pin_retained_object(
    git: &SafeGit,
    repo: &Path,
    pin: &RetentionPin,
) -> Result<String, CapabilityError> {
    let Some(namespace) = pin.class.retain_namespace() else {
        return Err(CapabilityError::Io(
            "eligible objects cannot receive a retain pin".into(),
        ));
    };
    let name = format!("{namespace}/{}", pin.oid.hex());
    git.run(
        Some(repo),
        FileProtocol::Never,
        &["update-ref", &name, pin.oid.hex()],
        &[],
    )?;
    Ok(name)
}

/// Whether a retain ref currently names the object.
///
/// # Errors
///
/// `GIT_FAILED` when `show-ref` fails for a reason other than absence.
pub fn retention_ref_exists(
    git: &SafeGit,
    repo: &Path,
    pin: &RetentionPin,
) -> Result<bool, CapabilityError> {
    let Some(namespace) = pin.class.retain_namespace() else {
        return Ok(false);
    };
    let name = format!("{namespace}/{}", pin.oid.hex());
    git.probe(Some(repo), &["show-ref", "--verify", "--quiet", &name])
}
