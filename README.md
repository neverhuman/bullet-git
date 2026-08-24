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

```bash
just fast
```
