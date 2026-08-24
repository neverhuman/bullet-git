# bullet-git

Agent-first repository kernel for Bullet Farm.

```text
ChangeId     stable engineering intention
CandidateId  exact immutable implementation (content-derived)
GitOid       exported ordinary Git commit
```

This crate family owns the change graph. `bullet-gitd` (this repo) is the
capability daemon and the sole workspace writer; pack protocol, refs, and
protected updates belong to the forge (Jeryu/GitHub). GitHub remains
ordinary Git.

See `docs/architecture.md` for the daemon protocol and trust model.

## Readiness

This repository currently proves component primitives: private dissociated clones, scoped writes
and deletes, exact Candidates, journals, preservation checks, and daemon protocol behavior. Its
legacy authority token is not a signed production grant, and its shortened Candidate/ProofRoot
types are not yet the canonical `v1alpha1` transaction records.

There is no five-plane transaction receipt or production-readiness claim here. Protected refs,
checks, integration, and observation remain forge/control-plane responsibilities and are not
simulated inside BulletGit.

```bash
just fast
```
