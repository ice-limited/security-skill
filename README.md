# security-skill

AI Agent skill for security review of software development artifacts —
application source code, Dockerfiles, Terraform, Helm, CI/CD pipelines,
Kubernetes manifests, dependencies, API specs, and configuration.

Designed to work across Claude Code, Codex, OpenCode, Antigravity, Grok
Build, Cursor, and similar AI coding agents: one tool-agnostic core, thin
per-tool adapters.

## Status

Early implementation. Architecture, planning, and feature specs live in the
[security-skill-workspace](https://git.cpmplatform.com/cpmatch/devops/security-skill/workspace)
repo — see `CONTEXT.md` there before contributing here. Plan status for
everything in `plans/` there is the source of truth for what's actually
done vs. still `todo`.

**Renderer/tooling language: Python** (decided 2026-07-22, plan 001
kickoff). `schema/` is implemented; `jsonschema` is the only third-party
dependency (see `schema/requirements.txt`).

## Layout

```
schema/            Finding schema (JSON canonical) + Markdown/HTML renderers.
                    Implemented — see finding.schema.json,
                    scan-report.schema.json, render_markdown.py,
                    render_html.py, validate.py, test_renderers.py.
knowledge/         OWASP/CWE/CAPEC/ATT&CK/NIST-SSDF/CERT reference lookups
                   + authoritative-only cross-standard mappings.
                   Implemented — see README.md in this directory.
adapters/          Per-tool entry points (SKILL.md for Claude Code, AGENTS.md
                   for Codex/OpenCode/Cursor/etc.) — planned, not yet built.
detectors/         Detection rules per sub-skill (code review, dependency,
                   iac, kubernetes, docker, api, secret, supply-chain) —
                   planned, not yet built.
policy/            Severity -> action policy engine and org config —
                   planned, not yet built.
```

## Running the tests

```
cd schema && pip install -r requirements.txt && python3 -m unittest test_renderers -v
cd ../knowledge && python3 -m unittest test_knowledge -v
cd ../knowledge && python3 -m unittest test_check_freshness -v      # mocked, no network
cd ../knowledge && RUN_LIVE_TESTS=1 python3 -m unittest test_check_freshness -v   # hits real GitHub API
```
