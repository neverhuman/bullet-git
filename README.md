# bullet-git

Agent-first repository kernel for Bullet Farm.

```text
ChangeId     stable engineering intention
CandidateId  exact immutable implementation
GitOid       exported ordinary Git commit
```

This crate family owns the change graph. `jeryu-gitd` owns pack protocol,
refs, and protected updates. GitHub remains ordinary Git.

```bash
just fast
```
