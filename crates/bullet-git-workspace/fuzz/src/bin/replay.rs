//! Replay checked-in corpus seeds against exact, filename-bound outcomes.

use bullet_git_fuzz::{fuzz_git_config, fuzz_patch};
use bullet_git_workspace::CapabilityError;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

const MAX_SEED_BYTES: u64 = 1_048_576;

#[derive(Clone, Copy)]
enum Expected {
    Admit,
    Refuse(&'static str),
}

#[derive(Clone, Copy)]
struct Case {
    name: &'static str,
    expected: Expected,
}

const CONFIG_CASES: &[Case] = &[
    Case {
        name: "hooks_path",
        expected: Expected::Refuse("HOSTILE_GIT_CONFIG"),
    },
    Case {
        name: "include_path",
        expected: Expected::Refuse("HOSTILE_GIT_CONFIG"),
    },
    Case {
        name: "ordinary_core",
        expected: Expected::Admit,
    },
];

const PATCH_CASES: &[Case] = &[
    Case {
        name: "duplicate",
        expected: Expected::Refuse("DUPLICATE_PATH"),
    },
    Case {
        name: "empty",
        expected: Expected::Refuse("INVALID_OPERATION_COUNT"),
    },
    Case {
        name: "oversized",
        expected: Expected::Refuse("INVALID_OPERATION_COUNT"),
    },
];

fn main() -> ExitCode {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let result = replay_corpus(
        &root.join("corpus/git_config"),
        CONFIG_CASES,
        fuzz_git_config,
    )
    .and_then(|config_count| {
        replay_corpus(&root.join("corpus/patch"), PATCH_CASES, |bytes| {
            fuzz_patch(bytes).map(|_| ())
        })
        .map(|patch_count| config_count + patch_count)
    });
    match result {
        Ok(seeds) => {
            println!("fuzz-replay: {seeds} exact outcomes closed");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("fuzz-replay: {error}");
            ExitCode::FAILURE
        }
    }
}

fn replay_corpus(
    dir: &Path,
    cases: &[Case],
    runner: impl Fn(&[u8]) -> Result<(), CapabilityError>,
) -> Result<usize, String> {
    let directory_metadata = fs::symlink_metadata(dir)
        .map_err(|error| format!("cannot inspect {}: {error}", dir.display()))?;
    if !directory_metadata.is_dir() || directory_metadata.file_type().is_symlink() {
        return Err(format!(
            "{} is not a non-symlink corpus directory",
            dir.display()
        ));
    }
    let mut actual = fs::read_dir(dir)
        .map_err(|error| format!("cannot read {}: {error}", dir.display()))?
        .map(|entry| {
            entry
                .map_err(|error| format!("cannot enumerate {}: {error}", dir.display()))
                .and_then(|entry| {
                    entry
                        .file_name()
                        .into_string()
                        .map_err(|_| format!("non-UTF-8 corpus name in {}", dir.display()))
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    actual.sort();
    let mut expected = cases
        .iter()
        .map(|case| case.name.to_owned())
        .collect::<Vec<_>>();
    expected.sort();
    if actual != expected {
        return Err(format!(
            "{} inventory mismatch: expected {expected:?}, found {actual:?}",
            dir.display()
        ));
    }

    for case in cases {
        let path = dir.join(case.name);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(format!("{} is not a regular corpus file", path.display()));
        }
        if metadata.len() > MAX_SEED_BYTES {
            return Err(format!(
                "{} exceeds the {MAX_SEED_BYTES}-byte replay bound",
                path.display()
            ));
        }
        let bytes =
            fs::read(&path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_SEED_BYTES {
            return Err(format!(
                "{} exceeded the {MAX_SEED_BYTES}-byte replay bound while being read",
                path.display()
            ));
        }
        verify(case, runner(&bytes))?;
    }
    Ok(cases.len())
}

fn verify(case: &Case, outcome: Result<(), CapabilityError>) -> Result<(), String> {
    match (case.expected, outcome) {
        (Expected::Admit, Ok(())) => {
            println!("fuzz-replay: admit {}", case.name);
            Ok(())
        }
        (Expected::Admit, Err(error)) => Err(format!(
            "{} expected admission, got {}: {error}",
            case.name,
            error.reason_code()
        )),
        (Expected::Refuse(expected), Err(error)) if error.reason_code() == expected => {
            println!("fuzz-replay: refuse {} {expected}", case.name);
            Ok(())
        }
        (Expected::Refuse(expected), Err(error)) => Err(format!(
            "{} expected {expected}, got {}: {error}",
            case.name,
            error.reason_code()
        )),
        (Expected::Refuse(expected), Ok(())) => Err(format!(
            "{} expected {expected}, but the oracle admitted it",
            case.name
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    #[cfg(unix)]
    #[test]
    fn corpus_directory_symlink_is_refused_before_enumeration() {
        let root = tempfile::tempdir().expect("temporary root");
        let real = root.path().join("real");
        fs::create_dir(&real).expect("real corpus directory");
        let linked = root.path().join("linked");
        symlink(&real, &linked).expect("corpus directory symlink");

        let error = replay_corpus(&linked, &[], |_| Ok(())).expect_err("symlink refused");
        assert!(error.contains("not a non-symlink corpus directory"));
    }

    #[test]
    fn unexpected_inventory_is_refused_before_an_oracle_runs() {
        let root = tempfile::tempdir().expect("temporary corpus");
        fs::write(root.path().join("unexpected"), b"seed").expect("unexpected seed");

        let error = replay_corpus(root.path(), &[], |_| {
            panic!("inventory mismatch reached oracle")
        })
        .expect_err("unexpected inventory refused");
        assert!(error.contains("inventory mismatch"));
    }

    #[test]
    fn over_bound_seed_is_refused_before_an_oracle_runs() {
        let root = tempfile::tempdir().expect("temporary corpus");
        let path = root.path().join("large");
        let file = fs::File::create(&path).expect("large seed");
        file.set_len(MAX_SEED_BYTES + 1).expect("sparse large seed");
        let cases = [Case {
            name: "large",
            expected: Expected::Admit,
        }];

        let error = replay_corpus(root.path(), &cases, |_| {
            panic!("over-bound seed reached oracle")
        })
        .expect_err("over-bound seed refused");
        assert!(error.contains("replay bound"));
    }

    #[test]
    fn admission_and_reason_mismatches_fail_closed() {
        let admission = Case {
            name: "admit",
            expected: Expected::Admit,
        };
        let refusal = Case {
            name: "refuse",
            expected: Expected::Refuse("HOSTILE_GIT_CONFIG"),
        };

        assert!(verify(&refusal, Ok(())).is_err());
        assert!(verify(
            &admission,
            Err(CapabilityError::HostileGitConfig("fixture".into()))
        )
        .is_err());
        assert!(verify(
            &refusal,
            Err(CapabilityError::InvalidOperationCount { max: 1, actual: 0 })
        )
        .is_err());
    }
}
