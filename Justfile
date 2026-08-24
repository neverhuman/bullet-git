default:
    @just --list

setup:
    rustup component add rustfmt clippy
    cargo fetch

fast:
    bash scripts/ci-local.sh fast

check:
    bash scripts/ci-local.sh required
