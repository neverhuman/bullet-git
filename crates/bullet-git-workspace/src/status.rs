//! `git status --porcelain=v2` parsing for the fresh candidate scan.

pub(crate) enum StatusEntry {
    Tracked(String),
    Untracked(String),
}

/// Parse one `git status --porcelain=v2` line into a classified path.
///
/// Changed entries: `1 <XY> <sub> <mH> <mI> <mW> <hH> <hI> <path>`.
/// Renames: `2 ... <Xscore> <path>\t<origPath>`. Unmerged: `u` with ten
/// fields before the path. Untracked: `? <path>`.
pub(crate) fn parse_status_line(line: &str) -> Option<StatusEntry> {
    let (kind, rest) = line.split_once(' ')?;
    match kind {
        "?" => Some(StatusEntry::Untracked(rest.to_string())),
        "1" => {
            let path = rest.splitn(8, ' ').nth(7)?;
            Some(StatusEntry::Tracked(path.to_string()))
        }
        "u" => {
            let path = rest.splitn(10, ' ').nth(9)?;
            Some(StatusEntry::Tracked(path.to_string()))
        }
        "2" => {
            let tail = rest.splitn(9, ' ').nth(8)?;
            let path = tail.split('\t').next().unwrap_or(tail);
            Some(StatusEntry::Tracked(path.to_string()))
        }
        _ => None,
    }
}
