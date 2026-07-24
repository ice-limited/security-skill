<!--
security-skill's AGENTS.md-convention entry point (plan 018). Copy the
section below into your own repo's AGENTS.md (append it — don't
overwrite an existing AGENTS.md, since this convention assumes one file
per repo covering everything, not just this skill). See
plans/018-agents-md-adapter.md and
meetings/2026-07-24-1000-plan-018-kickoff.md in the
security-skill-workspace repo for design rationale, and
adapters/claude-code/security-review/ (plan 017) for the sibling Claude
Code Skill this content mirrors.
-->

## Security Review (security-skill)

When asked to review code, a PR, or specific files for security issues
— or asked to "run a security scan," "security audit," "check this
Dockerfile/Terraform/pipeline/API spec for security issues," or
similar — use `security-skill`'s real detectors, not general judgment
alone.

**Hard rule: always invoke the real detector and report its real
structured output. If a detector's prerequisite tool isn't installed,
say so and relay its own install instructions verbatim — never
silently fall back to reviewing the code yourself as if that were
equivalent.** Findings from this skill carry Problem/Impact/
Recommendation/Reference/severity/confidence structure
(`schema/finding.schema.json`) the same way a human security reviewer
would cite OWASP/CWE/NIST SSDF — an unstructured, detector-free review
defeats the entire point of using it.

### Locating `security-skill/`

Every command below is relative to the `security-skill/` repo root. If
that checkout isn't a sibling of the repo you're reviewing, **ask the
user where it is rather than searching the filesystem for one** — a
filesystem search could land on the wrong checkout (different clone,
branch, or an unrelated project), silently running code the user never
pointed you at.

### Step 1 — identify what's in scope, run the matching detector(s)

A review often spans several rows — run every detector that applies,
not just the first match. **Always run the Secret row regardless of
what else applies** — secrets can leak into any file type.

| You see... | Sub-skill | Command | Prerequisite |
|---|---|---|---|
| Any file, any type | Secret | `python3 detectors/secret/scanner.py <file> [--artifact-type ...]` | none |
| Application source code | Code Review | `python3 detectors/code-review/scanner.py <file_or_dir> [--config p/owasp-top-ten]` | `semgrep` (`pip install semgrep`) |
| Application source code (authn/authz) | Auth | `python3 detectors/auth/semgrep_detector.py <file_or_dir>` (deterministic JWT-bypass half) **and** `python3 detectors/auth/playbook.py --language <lang>` (playbook half — see note below) | `semgrep` for the first; none for the playbook |
| Package manifests/lockfiles | Dependency | `python3 detectors/dependency/scanner.py <project> [--artifact-type package-lock]` | `osv-scanner` (`brew install osv-scanner`) + network |
| `Dockerfile*` | Docker | `python3 detectors/docker/scanner.py <project> [--artifact-type dockerfile]` | `trivy` (`brew install trivy`) |
| Kubernetes YAML / Helm charts | Kubernetes | `python3 detectors/kubernetes/scanner.py <manifests_or_chart>` | `trivy`; `helm` too for chart-specific checks |
| Terraform / CloudFormation / Ansible | IaC | `python3 detectors/iac/scanner.py <project>` | `checkov` (`pip install checkov`) |
| OpenAPI/other API specs | API | `python3 detectors/api/scanner.py <spec>` (Spectral lint), `python3 detectors/api/open_redirect.py <src>` (Semgrep), `python3 detectors/api/crossref.py <spec>` (auth cross-reference) | Node.js/npm (`cd detectors/api && npm install`) + `pip install -r requirements.txt`; `semgrep` for open_redirect.py |
| `.github/workflows/*`, `.gitlab-ci.yml`, `Jenkinsfile` | CI/CD Pipeline | `python3 detectors/cicd/scanner.py <repo>` (deterministic half) **and** `python3 detectors/cicd/playbook.py --format <github-actions\|gitlab-ci\|jenkinsfile>` (playbook half — Jenkinsfile has zero deterministic coverage) | `checkov` for the first; none for the playbook |
| Any repo (SBOM/provenance/signing) | Supply Chain | `python3 detectors/supply-chain/scanner.py <path>`, `python3 detectors/supply-chain/sbom_scanner.py .`, `python3 detectors/supply-chain/scorecard_wrapper.py .` | `scorecard` (`brew install scorecard`) for the last one only |

**Playbook note (Auth, CI/CD Pipeline)**: `playbook.py` isn't a script
you parse — it prints a checklist that *you* apply directly while
reading the code/config, for weaknesses these sub-skills' own
deterministic tooling (Semgrep, Checkov) doesn't reach well. When you
find something, construct a `Finding`-shaped dict yourself (same
fields any other detector produces) and validate it with
`playbook.validate_agent_finding(finding)`. This still counts as
running the real detector, not a substitute for one — the checklist
itself is the versioned, reviewed artifact, same as any other
detector's ruleset.

### Step 2 — report

Parse each command's JSON array of `Finding` objects and report every
finding's `title`, `severity`, `confidence`, `problem`, `impact`,
`recommendation`, and `references` — framing in your own words is fine,
but every fact must come from the finding's own fields, not invented.
If multiple detectors ran, group by severity (Critical/High/Medium/
Low/Info) across all of them, and mention any detector you skipped due
to a missing prerequisite plus what installing it requires.

### Not this entry point's job

- CI-pipeline enforcement (merge blocking, tickets, notifications) —
  `policy/engine.py` (003) and `action/integrations.py` (016), meant
  for actual CI wiring, not an interactive review session.
- `.cursor/rules/*.mdc` glob-scoped activation — Cursor reads this
  `AGENTS.md` directly in Agent mode; `.mdc` is a separate, deferred
  enhancement (see plan 018), not required for this content to work.
