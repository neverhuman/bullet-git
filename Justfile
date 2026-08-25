default:
    @just --list

setup:
    bash scripts/ci-local.sh source-scan
    rustup component add rustfmt clippy
    cargo fetch --locked

fast:
    bash scripts/ci-local.sh fast # cargo nextest

lint:
    bash scripts/ci-local.sh lint

docs:
    bash scripts/ci-local.sh docs

required:
    bash scripts/ci-local.sh required

check:
    bash scripts/ci-local.sh required

contract:
    bash scripts/ci-local.sh contract

security:
    bash scripts/ci-local.sh security

audit:
    bash scripts/ci-local.sh audit

[positional-arguments]
ci-doctor lane="all":
    bash scripts/ci-doctor.sh "$1"

hooks-install:
    git config --local core.hooksPath ops/git-hooks

nightly:
    bash scripts/ci-local.sh nightly

toolchain-msrv:
    bash scripts/ci-local.sh toolchain-msrv
