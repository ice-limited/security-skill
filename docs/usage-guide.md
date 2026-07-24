# security-skill — Usage Guide

A practical, end-to-end guide to actually running this project: setup,
invoking each detector, reading findings, running the Policy/Decision/
Action layers, installing the AI-agent adapters, and running the test
suite. For architecture and design rationale, see
`CONTEXT.md`/`plans/` in the security-skill-workspace repo — this guide
is deliberately just "how do I run this," not "why is it built this
way."

All commands below are written relative to this repo's root
(`security-skill/`). ภาษาไทย: [`usage-guide.th.md`](usage-guide.th.md).

## 1. What this is

`security-skill` performs security review of software artifacts —
source code, IaC, containers, Kubernetes manifests, CI/CD pipelines,
dependencies, API specs, and supply-chain metadata — the way a human
security engineer would: citing OWASP/CWE/NIST-SSDF, distinguishing
severity/confidence, and (where safe) proposing a concrete fix. It's
meant to be invoked by an AI coding agent during development, not run
as a standalone scanning service (though every detector is also a
plain CLI you can run yourself, which is what this guide covers).

## 2. Setup

### 2.1 Python environment

Every module is pure Python 3, callable as a script with no
packaging/install step (no `pyproject.toml`, no `pip install .`) — just
clone and run. Some detectors need extra packages:

```
pip install -r schema/requirements.txt        # jsonschema, referencing — needed by every schema-validating module
pip install -r detectors/code-review/requirements.txt   # semgrep
pip install -r detectors/iac/requirements.txt           # checkov
pip install -r detectors/api/requirements.txt           # PyYAML, ruamel.yaml
```

Recommended: one venv at the repo root (`python3 -m venv .venv`) with
all of the above installed — that's what this repo's own
`run_all_tests.py` looks for and prefers automatically.

### 2.2 External tools

Several detectors wrap a real, external CLI rather than reimplementing
its analysis — install only the ones for the artifact types you
actually need to scan:

| Tool | Needed by | Install |
|---|---|---|
| `semgrep` | code-review, auth (JWT half), api (open_redirect) | `pip install semgrep` |
| `trivy` | docker, kubernetes | `brew install trivy` (or a prebuilt binary — see trivy's own docs for Windows/Linux) |
| `checkov` | iac, cicd | `pip install checkov` |
| `osv-scanner` | dependency | `brew install osv-scanner` (or a prebuilt binary/Scoop/WinGet) |
| `scorecard` | supply-chain (one of its three checks) | `brew install scorecard` |
| `helm` | kubernetes (Helm-chart-specific checks only) | see Helm's own install docs |
| Node.js/npm | api (Spectral spec-lint) | any current Node.js install |

Each detector's own error message names the exact install command if
its tool is missing — you don't need to memorize this table, the
detector will tell you.

`detectors/api/` additionally needs one local `npm install`:

```
cd detectors/api && npm install
```

### 2.3 Verify your setup

```
python3 run_all_tests.py
```

Runs every test suite in the repo. A clean run shows `0` in the Fail
and Err columns for every directory (a nonzero Skip count is fine and
expected — it just means one of the external tools above isn't
installed, or you haven't opted into a live-network test).

## 3. Quick start — run one detector

Every detector takes a real file/directory and prints a JSON array of
`Finding` objects (see `schema/finding.schema.json`) to stdout:

```
python3 detectors/secret/scanner.py path/to/some/file.py
```

```json
[
  {
    "findingId": "secret-...",
    "ruleId": "secret.aws-access-key",
    "title": "Hardcoded AWS access key",
    "severity": "Critical",
    "confidence": 95,
    "problem": "...",
    "impact": "...",
    "recommendation": "...",
    "references": [{"standard": "CWE", "id": "CWE-798"}],
    "location": {"file": "...", "startLine": 12, "endLine": 12},
    "detectorSource": {"name": "secret-detector", "version": "0.1.0"},
    "suppressed": false
  }
]
```

Every finding has the same shape regardless of which detector produced
it — that's the point of the canonical schema.

## 4. Every sub-skill — what to run and on what

| Sub-skill | Command | What it takes |
|---|---|---|
| Secret | `python3 detectors/secret/scanner.py <file> [--artifact-type ...]` | one file at a time |
| Code Review (injection/SSRF) | `python3 detectors/code-review/scanner.py <file_or_dir> [--config p/owasp-top-ten] [--artifact-type source-code]` | source code |
| Auth (deterministic half) | `python3 detectors/auth/semgrep_detector.py <file_or_dir> [--config p/jwt] [--artifact-type source-code]` | source code |
| Auth (playbook half) | `python3 detectors/auth/playbook.py [--language <lang>]` | prints a checklist for *you* to apply — see §4.1 |
| Dependency | `python3 detectors/dependency/scanner.py <file_or_dir> [--artifact-type package-lock] [--data-source native]` | a project with a lockfile |
| Docker | `python3 detectors/docker/scanner.py <file_or_dir> [--artifact-type dockerfile]` | a project containing Dockerfiles |
| Kubernetes | `python3 detectors/kubernetes/scanner.py <file_or_dir>` | manifests or a Helm chart |
| IaC | `python3 detectors/iac/scanner.py <file_or_dir>` | Terraform/CloudFormation/Ansible |
| API (spec lint) | `python3 detectors/api/scanner.py <spec_path>` | an OpenAPI spec |
| API (open redirect) | `python3 detectors/api/open_redirect.py <file_or_dir> [--artifact-type source-code]` | source code |
| API (auth cross-reference) | `python3 detectors/api/crossref.py <spec_path>` | an OpenAPI spec |
| CI/CD Pipeline (deterministic half) | `python3 detectors/cicd/scanner.py <file_or_dir>` | a repo containing pipeline configs |
| CI/CD Pipeline (playbook half) | `python3 detectors/cicd/playbook.py --format <github-actions\|gitlab-ci\|jenkinsfile>` | prints a checklist — see §4.1 |
| Supply Chain (config presence) | `python3 detectors/supply-chain/scanner.py <file_or_dir>` | a repo, typically `.github/workflows/` |
| Supply Chain (SBOM) | `python3 detectors/supply-chain/sbom_scanner.py <file_or_dir>` | a repo (validates any SBOM files found) |
| Supply Chain (Scorecard) | `python3 detectors/supply-chain/scorecard_wrapper.py <file_or_dir>` | a repo root |
| Race Condition (TOCTOU) | `python3 detectors/race-condition/playbook.py [--language <lang>]` | prints a checklist — see §4.1 |

### 4.1 Playbook-based sub-skills (Auth's playbook half, CI/CD's playbook
half, Race Condition) are different

These don't scan a file and print findings — they print a *checklist*
that a human or AI agent applies while reading the code/config
directly. After finding something, construct a `Finding`-shaped dict
yourself and validate it against the schema:

```python
import playbook   # from that sub-skill's own directory
checklist = playbook.load_checklist()
text = playbook.render_playbook(checklist, language="python")
errors = playbook.validate_agent_finding(my_finding_dict)  # [] if valid
```

This exists because, for these specific weakness classes, no
deterministic tool has real coverage worth wrapping (checked against
Semgrep's real registry at each sub-skill's own kickoff) — the
checklist is the actual detector, not a fallback.

## 5. The full pipeline: Detection → Decision → Policy → Action

A single detector's raw findings aren't a full `ScanReport`
(`schema/scan-report.schema.json`) — assembling one (adding
`schemaVersion`/`scanId`/`repository`/`timestamp`/`summary` around the
`findings[]` array) is the caller's job; no single CLI does it for you
today. Once you have one:

```
# Decision Layer — dedup + org exception suppression
python3 decision/decision.py path/to/scan-report.json [--repo-root path/to/target/repo]

# Policy Engine — severity -> action (block-merge/require-review/create-ticket/notify/none)
python3 policy/engine.py path/to/scan-report.json [--repo-root path/to/target/repo]

# Action Layer: build a Remediation for one finding (only useful for secret.* findings' real patches)
python3 action/remediation.py path/to/finding.json [--source-file path/to/scanned_file]

# Action Layer: gate verdict + ticket/notification payloads from a policy verdict
python3 action/integrations.py path/to/scan-report.json [--repo-root path/to/target/repo]
```

`action/integrations.py` exits non-zero iff the policy verdict's
`aggregateAction` is `block-merge` — a CI step can gate on that exit
code directly.

`--repo-root` (accepted by `decision.py`, `policy/engine.py`, and
`action/integrations.py`) points at the repo actually being scanned, so
each can look for that repo's own `.security-skill/exceptions.json` /
`.security-skill/policy.json` override — omit it to use this project's
built-in defaults.

## 6. Rendering a report as Markdown/HTML

```
python3 schema/render_markdown.py < path/to/scan-report.json > report.md
python3 schema/render_html.py < path/to/scan-report.json > report.html
```

Both read a full `ScanReport` from stdin (not a bare findings array).

To validate a `ScanReport` or `Remediation` or `Integration` record
against its schema directly:

```
python3 schema/validate.py path/to/scan-report.json
```

## 7. Installing the AI-agent adapters

If you want an AI coding agent to invoke this project's detectors
automatically during a review session, install the adapter that
matches your tool. **Symlink, don't copy**, wherever a symlink is an
option — every adapter's commands are relative to this repo's own
root; a symlink still resolves through to the real checkout, a copy
won't, and (per plan 017's own manual test, a real gap found this way)
a copied install also risks drifting out of sync with a future fix
that only lands in this checkout. `$SECURITY_SKILL` below means this
repo's own absolute path on your machine.

### 7.1 Claude Code

Project-level (this repo's users only) or personal-level (every repo
you open in Claude Code) — pick one:

```
# Project-level: from inside the target repo you want reviewed
mkdir -p .claude/skills
ln -s "$SECURITY_SKILL/adapters/claude-code/security-review" .claude/skills/security-review

# Personal-level: available in every repo you open
mkdir -p ~/.claude/skills
ln -s "$SECURITY_SKILL/adapters/claude-code/security-review" ~/.claude/skills/security-review
```

**Verify**: start a Claude Code session in the target repo and ask for
a security review — the skill should trigger automatically. If it
doesn't seem to activate, confirm the symlink resolves
(`ls -la .claude/skills/security-review/SKILL.md` should show real
content, not a broken link).

### 7.2 Codex / OpenCode / Cursor (AGENTS.md convention)

Unlike Claude Code's isolated skill directory, `AGENTS.md` is a single
repo-root file most repos already use for their own project
instructions — **append**, don't overwrite:

```
# From inside the target repo
cat "$SECURITY_SKILL/adapters/agents-md/AGENTS.md" >> AGENTS.md
```

If the target repo has no `AGENTS.md` yet, this simply creates one. If
it already has content, this appends the security-review section below
it — review the result once (`AGENTS.md`) to make sure nothing got
mangled, since a plain `>>` doesn't understand Markdown structure.

**Verify**: ask the agent to review a file for security issues and
confirm (per its own output, or a tool like Grok Build's `grok
inspect`, see below) that it actually invoked a real detector via Bash,
not just commented on the code from general knowledge.

### 7.3 Antigravity

Same symlink pattern as Claude Code, different directory — Antigravity
reads its own Skill format from `.agents/skills/<name>/` (or the
legacy `.agent/skills/`):

```
# From inside the target repo
mkdir -p .agents/skills
ln -s "$SECURITY_SKILL/adapters/antigravity/skills/security-review" .agents/skills/security-review
```

(`AGENTS.md` coverage for Antigravity comes from §7.2 above — it reads
that file too, at session start; nothing extra needed here for that
half.)

**Verify**: not first-hand tested against a real Antigravity install
in this project's own development environment (no CLI available) —
confirm the symlink resolves, then check within Antigravity itself
that the skill appears in its own skill listing.

### 7.4 Grok Build

**Nothing to install.** Grok Build already reads both `AGENTS.md`
(§7.2 — no action needed if you did that step for another tool) and a
`.claude/skills/` directory directly, confirmed via a real `grok
inspect` run during this project's own development (see
`adapters/grok-build/README.md`). If you've already installed the
Claude Code adapter (§7.1) or the AGENTS.md content (§7.2) in a repo,
Grok Build picks it up with no extra step.

**Verify**:

```
grok inspect
```

Look for `security-review` under `Skills` (tagged `project [claude]`
if it found `.claude/skills/security-review/`) and your `AGENTS.md`
under `Project Instructions`.

### 7.5 The hard rule every adapter carries

Every adapter's content states the same requirement: the agent must
invoke the real detector and report real structured output, never
substitute general judgment when a detector or its prerequisite tool
is unavailable — and if a checkout can't be located from a relative
path (e.g. you copied instead of symlinking), the agent should ask you
where it is rather than searching the filesystem for one.

## 8. Running the test suite

```
python3 run_all_tests.py [--verbose]
```

Discovers and runs every `test_*.py` in the repo, one command,
per-directory pass/fail/skip summary. See `docs/testing-standards.md`
for the fixture/mocking/mutation-testing conventions every sub-skill's
own tests follow, and each directory's own `README.md` for that
directory's specific cross-platform verification command
(`LC_ALL=en_US.US-ASCII LANG=en_US.US-ASCII python3 -m unittest ...`).

## 9. Extending this project

New feature work in this repo is planned before it's implemented — see
`AGENTS.md`/`CONTEXT.md`/`plans/` in the security-skill-workspace repo
(the separate repo this one is a submodule of) for the process and the
full history of design decisions behind everything in this guide.
