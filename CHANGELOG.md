# Changelog

All notable changes to this repo (the skill implementation itself) are
recorded here. Changes to the workspace (planning docs, process,
license, repo config) are recorded in
[security-skill-workspace/CHANGELOG.md](https://github.com/ice-limited/security-skill-workspace/blob/main/CHANGELOG.md)
(separate repo).

Format loosely follows [Keep a Changelog](https://keepachangelog.com/).
Backfilled 2026-07-24 (see `security-skill-workspace` AGENTS.md rule 10:
every change now gets an entry here going forward, in the same turn
it's made — this backfill covers everything implemented before that
rule existed).

## [Unreleased]

### Added

- **Windows install instructions for the adapter symlink step**
  (`docs/usage-guide.md`/`.th.md` §7.1 Claude Code, §7.3 Antigravity),
  found by another good user question: a real Windows symlink
  (`mklink`/`New-Item -ItemType SymbolicLink`) needs either an elevated
  prompt or Developer Mode, which the guide never mentioned for
  Windows users at all. Documented a **junction**
  (`mklink /J`/`New-Item -ItemType Junction`) as the practical default
  instead — same effect for a local directory, no elevation or
  Developer Mode required — with the real symlink commands kept as a
  fallback for the one case a junction can't cover (a checkout reachable
  only via a mapped network path).

## [1.0.1] - 2026-07-25

Patch release: install automation, doc fixes, and a real adapter bug
found by a user question.

### Added

- **`install.sh` / `install.ps1` / `install.bat`** — one-command setup
  for macOS/Linux, Windows PowerShell, and Windows cmd.exe. Discovers
  and installs every real `requirements.txt` in the repo dynamically
  (not a hardcoded list — a static list has already gone stale twice in
  this project's own history), runs `npm install` for `detectors/api/`
  if Node.js is present, and reports which optional external tools
  (semgrep/trivy/checkov/osv-scanner/scorecard/helm) are and aren't on
  `PATH` with the install hint for each. Verified for real:
  `install.sh` was run end-to-end in this environment (fresh `.venv`,
  all 5 real `requirements.txt` installed, `run_all_tests.py` passing
  against the result) — `install.ps1`/`install.bat` were reviewed
  carefully but not executed (no Windows/PowerShell Core available in
  this environment); both add explicit UTF-8 console handling so the
  Thai text in their output doesn't depend on the host's default
  codepage, the same discipline this project's own Python CLIs follow.
- Fixed a real, small documentation gap found while writing the install
  scripts: `detectors/supply-chain/requirements.txt` (needs
  `ruamel.yaml`) was missing from `docs/usage-guide.md`/`.th.md`'s
  setup section — added.

### Fixed

- **Real gap in both interactive-agent adapters** (`adapters/claude-code/security-review/SKILL.md`,
  `adapters/agents-md/AGENTS.md`), found by the user asking exactly the
  right question: an AI agent invoking a bare `python3
  detectors/secret/scanner.py ...` from a *different* repo's session
  doesn't resolve to `security-skill/`'s own `.venv` — it uses whatever
  `python3` is first on that shell's `PATH`, so `jsonschema` and
  similar imports fail. Worse, `semgrep`/`checkov` specifically are
  installed only inside that `.venv` (unlike `trivy`/`osv-scanner`/
  `scorecard`/`helm`, real system binaries already on `PATH`), so even
  a working `python3` still can't find them as subprocesses. Fixed by
  adding one explicit step to both adapters: activate
  `security-skill/.venv` once per session before running any command —
  this makes `python3`/`python` resolve to the venv's interpreter *and*
  puts `.venv/bin` on `PATH`, fixing both problems at once. Added a
  regression guard to each adapter's own static test
  (`test_venv_activation_instruction_present`), mutation-tested.

## [1.0.0] - 2026-07-25

All 24 plans in the security-skill-workspace roadmap are `done` as of
this release — Detection Layer (10 sub-skills, plans 006-014/023/024),
Decision Layer (004), Policy Engine (003), Action Layer (015-016),
three AI-agent adapters (017-019), the cross-sub-skill test harness
(020), and cross-platform compatibility (022). 674 tests, 0 failures.

### Added

- **License** — Business Source License 1.1-style source-available
  license (Licensor: Ice Limited), modified to have no Change Date/
  Change License (a permanent restriction, not the standard License's
  guaranteed eventual open-sourcing). See `LICENSE.md`.
- **001 — Finding Schema & Multi-format Output**: `finding.schema.json`/
  `scan-report.schema.json`, JSON/Markdown/HTML renderers.
- **002 — Knowledge Base & Standards Mapping**: OWASP/CWE/NIST-SSDF/ASVS
  reference data under `knowledge/`.
- **003 — Policy Engine & Severity-to-Action Config**: `policy/engine.py`,
  default + per-repo policy override.
- **004 — Decision Layer**: exact-duplicate dedup + exception-based
  suppression (`decision/`).
- **005 — Repo Scaffolding & Core+Adapter Architecture**: formalized the
  directory-per-concern convention; `common/` (shared stream-reconfigure
  and schema-validation utilities).
- **006 — Secret Detection Skill**: pattern + entropy-based hardcoded
  secret detection, 8 rules (`detectors/secret/`).
- **007 — Code Review Skill (Injection/SSRF classes)**: Semgrep-wrapped
  SQLi/XSS/SSRF/Command Injection detection (`detectors/code-review/`).
- **008 — Dependency Skill**: OSV-based CVE/license/deprecation scanning
  (`detectors/dependency/`).
- **009 — Docker Skill**: Trivy-wrapped Dockerfile checks
  (`detectors/docker/`).
- **010 — Kubernetes Skill**: Trivy/Helm-based manifest checks
  (`detectors/kubernetes/`).
- **011 — IaC Skill**: Checkov-wrapped Terraform/CloudFormation/Ansible
  checks (`detectors/iac/`); `common/checkov_wrapper.py` extracted.
- **012 — API Skill**: Spectral (OpenAPI spec-lint) + Semgrep (open
  redirect) + deterministic-extraction/playbook hybrid for auth
  cross-reference (`detectors/api/`) — first Node.js/npm dependency.
- **013 — CI/CD Pipeline Skill**: Checkov + playbook hybrid for GitHub
  Actions/GitLab CI/Jenkinsfile (`detectors/cicd/`).
- **014 — Supply Chain Skill**: SBOM validation, OpenSSF Scorecard,
  GitHub Actions config-presence checks (`detectors/supply-chain/`).
  Phase 1 (Detection sub-skills, 006–014/023) complete.
- **015 — Action Layer: Recommendations & Auto-fix**: `Remediation`
  record (`schema/remediation.schema.json`), safety-tier assignment,
  real computed patch generation for `secret.*` findings
  (`action/remediation.py`).
- **016 — Action Layer: Ticketing, Notifications & Gate Enforcement**:
  `Integration` record (`schema/integration.schema.json`), gate-verdict/
  ticket/notification payload generation from a policy verdict
  (`action/integrations.py`).
- **017 — Claude Code Adapter**: `adapters/claude-code/security-review/`
  — a router Skill + one reference doc per sub-skill, using Claude
  Code's progressive-disclosure mechanism.
- **018 — AGENTS.md Adapter**: `adapters/agents-md/AGENTS.md` — one
  flat entry point for Codex/OpenCode/Cursor. Real research confirmed
  Cursor reads `AGENTS.md` natively in Agent mode, so `.cursor/rules/*.mdc`
  was deferred rather than built (a genuine future enhancement, not a
  gap this plan needed to close).
- **019 — Antigravity / Grok Build Adapter**: no new content authored.
  Research (confirmed for Grok Build by a real, first-hand `grok inspect`
  run in this environment) found both tools already read 017/018's
  existing content directly. `adapters/antigravity/skills/security-review`
  is a symlink to 017's content (Antigravity's own Skill format is
  structurally identical, discovered from a different directory);
  `adapters/grok-build/` documents Grok's native reuse with no wiring
  needed at all. Antigravity itself couldn't be verified first-hand (no
  CLI in this environment) — documented as an honest, open gap.
- **021 — Knowledge Base Freshness Checker**: verifies `knowledge/`
  reference data against upstream sources (`knowledge/check_freshness.py`).
- **022 — Cross-Platform Compatibility**: audited and fixed macOS/
  Windows/Linux compatibility across every module (explicit UTF-8
  encoding everywhere, `.gitattributes` LF normalization, stdin/stdout/
  stderr reconfiguration).
- **023 — AuthN/AuthZ Code Review Skill**: Semgrep-subset (JWT bypass) +
  playbook hybrid (`detectors/auth/`).
- **020 — Test Fixtures & Evaluation Corpus**: retrofit, not a
  from-scratch build — Phase 1 already shipped its own inline synthetic
  fixtures per sub-skill without this plan. Added
  `run_all_tests.py` (discovers and runs every `test_*.py` in the repo,
  one command, per-directory pass/fail/skip summary, skips never fail
  the run) and `docs/testing-standards.md` (formalizes the fixture/
  mocking/mutation-testing conventions that already existed in
  practice).
- **024 — Race Condition Code Review Skill**: reopened and implemented
  (originally deferred past Phase 1 at its 2026-07-22 kickoff over
  near-zero Semgrep registry coverage for race conditions/TOCTOU; the
  user explicitly overrode the unmet revisit condition and asked to
  proceed on 2026-07-25). `detectors/race-condition/` — playbook-only,
  no deterministic scanner, scoped to TOCTOU-shaped file/resource
  access only (narrower than general race conditions). Added `CWE-367`
  to `knowledge/cwe.json`. `finding.schema.json`'s `subSkill` enum
  gained `race-condition` (schemaVersion 1.2.0 → 1.3.0). Also updated
  the Claude Code (017) and AGENTS.md (018) adapters' own coverage for
  this new sub-skill — their own coverage-guard tests correctly caught
  the gap the moment the new subSkill enum value existed.

### Fixed

- **006 (Secret Detection)**, found during 015's implementation:
  `generic-api-key`/`azure-ad-client-secret` rules computed
  `location.startByte`/`endByte` from the whole regex match instead of
  the narrower capture group, producing an over-wide (and, downstream,
  incorrect) byte span. Fixed at the source in
  `detectors/secret/scanner.py`, with regression tests.
- **Environment gap, found while building 020's evaluation harness**:
  `common/test_checkov_wrapper.py` and `detectors/iac/test_scanner.py`
  mock `subprocess.run` for their own output-normalization tests, but
  still call the real `_check_checkov_available()` gate first, which
  checks the real `PATH` — so they failed (not skipped) in any shell
  that hadn't manually activated this repo's `.venv`. Not a code bug;
  fixed in `run_all_tests.py` by prepending `.venv/bin` to the
  subprocess environment's `PATH`, the same thing `source
  .venv/bin/activate` would do. Documented as a known rough edge in
  `docs/testing-standards.md` for anyone running those two files
  directly outside the harness.

### Not yet implemented

- **018 (AGENTS.md Adapter), 019 (Antigravity/Grok Build Adapter), 020
  (Test Fixtures), 024 (Race Condition)** are all now `done` — all
  plans in `plans/` (workspace repo) are `done` except **019's own
  `.cursor/rules/*.mdc`** (deferred, not built — see 018/019's own
  entries above), **020's OWASP Benchmark/WebGoat corpus adoption**
  (deferred, not pursued), and **024's beyond-TOCTOU scope** (deferred,
  not pursued). See `plans/` in the workspace repo for current status
  of anything not covered by an entry above.
