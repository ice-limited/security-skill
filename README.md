# security-skill

AI Agent skill for security review of software development artifacts —
application source code, Dockerfiles, Terraform, Helm, CI/CD pipelines,
Kubernetes manifests, dependencies, API specs, and configuration.

Designed to work across Claude Code, Codex, OpenCode, Antigravity, Grok
Build, Cursor, and similar AI coding agents: one tool-agnostic core, thin
per-tool adapters.

## Status

Early implementation. Architecture, planning, and feature specs live in the
[security-skill-workspace](https://git.cpmplatform.com/cpmatch/ai-security-skill/workspace)
repo — see `CONTEXT.md` there before contributing here. Plan status for
everything in `plans/` there is the source of truth for what's actually
done vs. still `todo`.

**Renderer/tooling language: Python** (decided 2026-07-22, plan 001
kickoff). `schema/` is implemented; `jsonschema` is the only third-party
dependency (see `schema/requirements.txt`).

**Cross-platform:** targets macOS, Windows, and Linux equally (plan 022)
— every file read/write specifies `encoding="utf-8"` explicitly, CLI
entry points reconfigure stdin/stdout/stderr to UTF-8, and
`.gitattributes` normalizes line endings to LF. Command examples below
use the macOS/Linux (`bash`/`zsh`) form; see each command's Windows note.

## Layout

```
schema/            Finding schema (JSON canonical) + Markdown/HTML renderers.
                    Implemented — see finding.schema.json,
                    scan-report.schema.json, render_markdown.py,
                    render_html.py, validate.py, test_renderers.py.
knowledge/         OWASP/CWE/CAPEC/ATT&CK/NIST-SSDF/CERT reference lookups
                   + authoritative-only cross-standard mappings.
                   Implemented — see README.md in this directory.
policy/            Severity -> action policy engine, default + per-repo
                   override config. Implemented — see README.md in this
                   directory.
decision/          Exact-duplicate dedup + exception-based suppression,
                   sits between detectors and policy/. Implemented — see
                   README.md in this directory.
adapters/          Per-tool entry points (SKILL.md for Claude Code, AGENTS.md
                   for Codex/OpenCode/Cursor/etc.) — planned, not yet built.
detectors/         Detection rules per sub-skill (code review, dependency,
                   iac, kubernetes, docker, api, secret, supply-chain) —
                   planned, not yet built.
```

## Running the tests

macOS/Linux (`bash`/`zsh`):

```
cd schema && pip install -r requirements.txt && python3 -m unittest test_renderers -v
cd ../knowledge && python3 -m unittest test_knowledge -v
cd ../knowledge && python3 -m unittest test_check_freshness -v      # mocked, no network
cd ../knowledge && RUN_LIVE_TESTS=1 python3 -m unittest test_check_freshness -v   # hits real GitHub API
cd ../policy && python3 -m unittest test_engine -v
cd ../decision && python3 -m unittest test_decision -v
```

Windows: use `python` (not `python3` — not a standard command name on
Windows installs) and the shell-appropriate env var syntax for the one
command that sets one (`RUN_LIVE_TESTS`):

```
:: cmd.exe
set RUN_LIVE_TESTS=1 && python -m unittest test_check_freshness -v
```
```
# PowerShell
$env:RUN_LIVE_TESTS=1; python -m unittest test_check_freshness -v
```

### Cross-platform encoding verification

Every file read/write in this repo specifies `encoding="utf-8"`
explicitly (plan 022) specifically because the default otherwise depends
on OS locale — commonly UTF-8 on macOS/Linux, commonly something else
(e.g. `cp1252`) on Windows. To verify a change hasn't reintroduced a
locale-dependent read/write, run any test suite with the locale forced
away from UTF-8 — this reproduced 52 real failures across this
codebase before the plan 022 fix, so it's a meaningful check, not
theater:

```
LC_ALL=en_US.US-ASCII LANG=en_US.US-ASCII python3 -m unittest test_renderers -v
```

(macOS/Linux only — Windows doesn't honor `LC_ALL`; a Windows machine
running a non-English locale hits the equivalent risk "for free," which
is exactly why every read/write here is explicit about its encoding
rather than relying on any platform's default.)
