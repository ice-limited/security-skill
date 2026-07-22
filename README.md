# security-skill

AI Agent skill for security review of software development artifacts —
application source code, Dockerfiles, Terraform, Helm, CI/CD pipelines,
Kubernetes manifests, dependencies, API specs, and configuration.

Designed to work across Claude Code, Codex, OpenCode, Antigravity, Grok
Build, Cursor, and similar AI coding agents: one tool-agnostic core, thin
per-tool adapters.

## Status

Scaffolding only. Architecture, planning, and feature specs live in the
[security-skill-workspace](https://git.cpmplatform.com/cpmatch/devops/security-skill/workspace)
repo — see `CONTEXT.md` there before contributing here.

## Layout (planned)

```
adapters/         Per-tool entry points (SKILL.md for Claude Code, AGENTS.md
                   for Codex/OpenCode/Cursor/etc.)
knowledge/         OWASP/CWE/NIST SSDF/ASVS reference material and mappings
detectors/         Detection rules per sub-skill (code review, dependency,
                   iac, kubernetes, docker, api, secret, supply-chain)
schema/            Finding schema (JSON canonical) + Markdown/HTML renderers
policy/            Severity -> action policy engine and org config
```
This layout is provisional — it will be filled in and corrected as each
sub-skill's plan lands.
