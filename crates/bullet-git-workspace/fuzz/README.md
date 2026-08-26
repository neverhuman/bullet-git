# Corpus replay prerequisite

Status: deterministic component check; not release evidence.

The BulletGit contract lane replays the six checked-in patch and local-config
seeds against filename-bound admission or typed-refusal outcomes. It rejects an
unexpected corpus entry, a symlinked corpus or seed, an over-bound seed, and an
outcome that differs from the committed expectation.

This harness does **not** implement the planned cargo-fuzz targets, the pinned
100,000-run nightly job, or closure item L-06. Those remain blocked, as do all
Bullet release profiles. Run the covered component check with:

```bash
bash scripts/ci-local.sh contract
```
