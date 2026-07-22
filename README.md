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
common/            Shared utilities: stdio UTF-8 reconfiguration, JSON
                   Schema validation. Implemented — see README.md in
                   this directory.
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
                   for Codex/OpenCode/Cursor/etc.) — reserved for Phase 3
                   (plans 017-019), not yet built or scaffolded.
detectors/         Detection rules per sub-skill (code review, dependency,
                   iac, kubernetes, docker, api, secret, supply-chain) —
                   reserved for Phase 1 (plans 006-014), not yet built or
                   scaffolded. Planned layout: one subdirectory per
                   sub-skill (detectors/secret/, detectors/code-review/,
                   ...), each following the convention below.
```

### Directory-per-concern convention (plan 005)

`schema/`, `knowledge/`, `policy/`, `decision/` all converged on the same
shape independently — this is now the standard for every new concern
directory, including each `detectors/{sub-skill}/` in Phase 1:

- One or more `*.schema.json` (or other data) file(s) — the concern's
  canonical data/config shape.
- A core `.py` module with the concern's actual logic, callable as both
  a library (`import x; x.some_function(...)`) and a CLI
  (`python3 x.py args`), the latter via a testable `main(argv=None)`
  kept separate from the `if __name__ == "__main__":` guard.
- `validate.py`, if the concern has its own config/data schema.
- `test_*.py` — including `CrossPlatformEncodingTests` and
  `SourceEncodingAuditTests` from day one (plan 022's binding
  requirement, see CONTEXT.md §2 in the security-skill-workspace repo).
- `README.md`.

Cross-directory imports (e.g. a detector using `common/`) use a
`sys.path.insert` at the top of the importing file — this repo has no
package/install infrastructure (no `pyproject.toml`, no `__init__.py`)
by design, matching every module already here. **Walk upward looking for
`common/`, don't hardcode a fixed number of `.parent`s** — a fixed depth
(e.g. `.parent.parent`) happens to work for today's 1-level-deep
directories (`schema/`, `knowledge/`, `policy/`, `decision/`) but breaks
silently for Phase 1's 2-level-deep `detectors/{sub-skill}/` layout. This
was a real bug caught while testing plan 005, not a hypothetical:

```python
_common_dir = next(p for p in Path(__file__).resolve().parents if (p / "common").is_dir()) / "common"
sys.path.insert(0, str(_common_dir))
from streams import reconfigure_streams
```

### `ruleId` naming convention

Dot-namespaced, lowercase-kebab: `{subSkill}.{rule-name}`, optionally
deeper-namespaced (e.g. `code-review.sqli.string-concat`). Already
enforced by `finding.schema.json`'s own regex
(`^[a-z0-9-]+(\.[a-z0-9-]+)+$`); every Phase 1 detector's rules follow
this. Examples already in use: `secret.aws-access-key`,
`dependency.cve`, `kubernetes.hostpath-mount`.

## Running the tests

macOS/Linux (`bash`/`zsh`):

```
cd common && python3 -m unittest test_common -v
cd ../schema && pip install -r requirements.txt && python3 -m unittest test_renderers -v
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
