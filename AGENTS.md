# bullet-git Agent Instructions

Read `SPLIT.md` first. This repository is BulletGit.
Discover the outermost family root from the parent `repos.manifest.toml`. Read
and append `<family-root>/AGENT_CHAT.md` before every claim and edit.

Read `agent/JANKURAI_STANDARD.md` next.
Do not reimplement pack protocol. `bullet-gitd` (this repo) is the capability
daemon; pack protocol, refs, and protected updates belong to the forge
(Jeryu/GitHub). GitHub never sees custom object types.
