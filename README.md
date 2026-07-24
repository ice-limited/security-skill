# security-skill

AI Agent skill for security review of software development artifacts —
application source code, Dockerfiles, Terraform, Helm, CI/CD pipelines,
Kubernetes manifests, dependencies, API specs, and configuration.

Designed to work across Claude Code, Codex, OpenCode, Antigravity, Grok
Build, Cursor, and similar AI coding agents: one tool-agnostic core, thin
per-tool adapters.

## Status

Early implementation. Architecture, planning, and feature specs live in the
[security-skill-workspace](https://github.com/ice-limited/security-skill-workspace)
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
                   Schema validation, Semgrep CLI wrapper (subprocess
                   + result-to-finding.schema.json mapping, shared by
                   detectors/code-review/ and detectors/auth/), Trivy
                   CLI wrapper (subprocess + result-to-finding.schema.json
                   mapping, shared by detectors/docker/ and
                   detectors/kubernetes/).
                   Implemented — see README.md in this directory.
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
adapters/          Per-tool entry points. claude-code/ (017),
                   agents-md/ (018, Codex/OpenCode/Cursor), antigravity/
                   and grok-build/ (019, both reuse 017/018's content —
                   see README.md in each directory) all done.
detectors/         Detection rules per sub-skill (code review, dependency,
                   iac, kubernetes, docker, api, secret, supply-chain) —
                   one subdirectory per sub-skill, each following the
                   convention below.
  secret/            Pattern + entropy hardcoded-secret detection
                     (AWS/GCP/Azure keys, GitHub/GitLab PATs, JWTs,
                     private keys, generic credentials). Implemented —
                     see README.md in this directory.
  code-review/       Injection & Request-Forgery classes (SQLi, XSS,
                     SSRF, Command Injection), plan 007 — a thin
                     wrapper around the Semgrep CLI (subprocess), not a
                     from-scratch engine. Implemented — see README.md
                     in this directory.
  dependency/        CVEs, known-malicious packages, license
                     compliance, deprecated packages (plan 008) — a
                     thin wrapper around the osv-scanner CLI
                     (subprocess) covering npm/PyPI/Go/Maven/Packagist/
                     Pub/SwiftURL in one tool. Implemented — see
                     README.md in this directory.
  docker/            Dockerfile hardening: unpinned base image, root
                     user, missing HEALTHCHECK (plan 009) — a thin
                     wrapper around Trivy's `config` scan mode
                     (subprocess), plus hand-written custom rules for
                     apt-get upgrade, curl|bash, and ADD-vs-COPY (no
                     tool covers these as security-specific checks).
                     Implemented — see README.md in this directory.
  auth/              AuthN/AuthZ code review (plan 023) — hybrid:
                     playbook.py (a checklist the invoking AI agent
                     reasons over directly — the primary mechanism,
                     Semgrep's registry coverage for this class is too
                     patchy across cpmatch's stack) plus
                     semgrep_detector.py (a narrow deterministic subset
                     for JWT signature/algorithm bypass, the one
                     pattern Semgrep covers well here). Both halves
                     implemented. See README.md in this directory.
  kubernetes/        Workload hardening: hostNetwork/hostPID/hostPath,
                     privileged/root containers, unpinned `:latest`
                     tags, missing CPU/memory limits, writable root
                     filesystems (plan 010) — a thin wrapper around
                     Trivy's `config` scan mode (subprocess, shared
                     with detectors/docker/ via common/trivy_wrapper.py),
                     no custom rules needed; natively renders and scans
                     Helm charts too, no `helm` CLI dependency at scan
                     time. Implemented — see README.md in this directory.
  iac/               IaC misconfiguration: curated IAM + public-exposure
                     checks across Terraform (AWS/Azure/GCP),
                     CloudFormation (AWS), and Ansible playbook
                     hardening (plan 011) — a thin wrapper around the
                     Checkov CLI (subprocess), not Trivy — verified at
                     kickoff that Trivy's AWS IAM-wildcard check is
                     deprecated, GCP has no project-level IAM check at
                     all, and Ansible has zero shipped Trivy checks.
                     Helm dropped from scope entirely (redundant with
                     010). Implemented — see README.md in this directory.
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
`dependency.cve`, `kubernetes.hostpath-volume`, `iac.aws-iam-wildcard-actions`.

## Running the tests

macOS/Linux (`bash`/`zsh`):

```
cd common && python3 -m unittest test_common -v
cd common && python3 -m unittest test_semgrep_wrapper -v   # requires real `semgrep` on PATH for its subprocess tests (skipped, not failed, if absent)
cd common && python3 -m unittest test_trivy_wrapper -v   # requires real `trivy` on PATH for its subprocess tests (skipped, not failed, if absent)
cd ../schema && pip install -r requirements.txt && python3 -m unittest test_renderers -v
cd ../knowledge && python3 -m unittest test_knowledge -v
cd ../knowledge && python3 -m unittest test_check_freshness -v      # mocked, no network
cd ../knowledge && RUN_LIVE_TESTS=1 python3 -m unittest test_check_freshness -v   # hits real GitHub API
cd ../policy && python3 -m unittest test_engine -v
cd ../decision && python3 -m unittest test_decision -v
cd ../detectors/secret && python3 -m unittest test_scanner -v
cd ../code-review && pip install -r requirements.txt && python3 -m unittest test_scanner -v   # requires real `semgrep` on PATH + network for its registry config
cd ../dependency && python3 -m unittest test_scanner -v   # requires real `osv-scanner` on PATH + network to query OSV
cd ../docker && python3 -m unittest test_scanner -v   # requires real `trivy` on PATH + network for its checks bundle
cd ../auth && python3 -m unittest test_playbook -v
cd ../auth && python3 -m unittest test_semgrep_detector -v
cd ../kubernetes && python3 -m unittest test_scanner -v   # requires real `trivy` on PATH + network for its checks bundle; Helm-specific tests also require real `helm` on PATH
cd ../iac && pip install -r requirements.txt && python3 -m unittest test_scanner -v   # requires real `checkov` on PATH
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
