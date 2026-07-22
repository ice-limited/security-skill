# detectors/cicd/

CI/CD pipeline security review across GitHub Actions, GitLab CI, and
Jenkinsfile — **hybrid**, mirroring detectors/auth's (023) shape: a
deterministic Checkov-based half for what it reliably catches, plus a
playbook the invoking agent reasons over directly for everything else.
See `plans/013-cicd-pipeline-skill.md` and
`meetings/2026-07-22-2300-plan-013-kickoff.md` in the
security-skill-workspace repo for design rationale.

## Why Checkov, not `zizmor`

`zizmor` (github.com/woodruffw/zizmor, MIT) is a purpose-built GitHub
Actions security tool with 39 audits — verified at this plan's kickoff
to cover every attack class in scope far more deeply than Checkov's 7
`github_actions` checks. **Checkov was chosen anyway**, for consistency
with 011 (IaC Skill), which already wraps it — an explicit trade-off
the kickoff discussion weighed and the user confirmed, not an
oversight. `zizmor` also only covers GitHub Actions; GitLab CI and
Jenkinsfile would still need a different mechanism regardless.

## `rules.py`/`scanner.py` — the deterministic half

Wraps `common/checkov_wrapper.py` — shared with `detectors/iac/`
(011), extracted at this plan's implementation once 013 became
Checkov's second consumer (plan 005's "share once a second consumer
exists" precedent). Curates 6 rule_ids across 7 Checkov check codes:

| ruleId | Checkov check(s) | CWE |
|---|---|---|
| `cicd-pipeline.unsecure-commands-enabled` | `CKV_GHA_1` | CWE-94 |
| `cicd-pipeline.shell-injection-pattern` | `CKV_GHA_2` | CWE-94 |
| `cicd-pipeline.curl-with-secret-in-script` | `CKV_GHA_3` (GH Actions), `CKV_GITLABCI_1` (GitLab CI) | CWE-532 |
| `cicd-pipeline.reverse-shell-pattern` | `CKV_GHA_4` | CWE-506 |
| `cicd-pipeline.workflow-dispatch-inputs-affect-build` | `CKV_GHA_7` | CWE-20 |
| `cicd-pipeline.excessive-top-level-permissions` | `CKV2_GHA_1` | CWE-269 |

**Real correction found at implementation, not assumed from the
kickoff's own research**: the kickoff found only 7 `CKV_GHA_*` checks
by reading `checks/job/*.py`. Checkov *also* ships one graph-based
check, `CKV2_GHA_1` ("top-level permissions not write-all"), stored as
a JSON graph-check definition
(`checkov/github_actions/checks/graph_checks/ReadOnlyTopLevelPermissions.json`),
invisible to a `*.py`-only source search. This directly closes part of
the "excessive permissions" gap the kickoff assumed was entirely
playbook-only — the *maximal* `write-all` case is now deterministic;
only job-level permissions and non-maximal grants remain playbook-only.

**Excluded, deliberately**: `CKV_GHA_5`/`6` (Cosign artifact-signing/
SBOM-attestation presence) — belong to **014** (Supply Chain Skill),
not this plan's script-injection/secrets/permissions scope, even though
Checkov ships them under the same `github_actions` framework.
`CKV_GITLABCI_2` (pipeline-efficiency, not security) and
`CKV_GITLABCI_3` — verified **dead code**: its `scan_conf()`
unconditionally `return CheckResult.PASSED, conf`, incapable of ever
firing, confirmed by reading the source directly, not assumed from its
name.

**Real quirk found and fixed generically in `common/checkov_wrapper.py`**:
`CKV2_GHA_1` (a graph check) reports a 0-indexed `file_line_range`,
unlike every regular (`CKV_*`) check, which is properly 1-indexed.
Fixed by clamping to a minimum of 1 in `map_checkov_check()` — a
general fix, not a special case for this one check_id, since
finding.schema.json requires `startLine >= 1` regardless of which
check produced it.

**`artifactType` translation**: Checkov's own `check_type` uses
underscores (`github_actions`, `gitlab_ci`); finding.schema.json's
`artifactType` enum uses hyphens for these two values. `scanner.py`
passes `common/checkov_wrapper.py`'s new `artifact_type_map` parameter
to translate — 011's own frameworks (terraform/cloudformation/ansible)
never needed this, since Checkov's strings already matched the schema
exactly there.

## `checklist.json`/`checklist.schema.json`/`playbook.py` — the playbook half

Covers what `rules.py` doesn't reach, across **all three** formats
(including Jenkinsfile, which has **zero deterministic tool coverage
anywhere** — verified at kickoff: no Checkov framework, no Semgrep
pack): unpinned external references, excessive permissions beyond the
one deterministic write-all case (job-level permissions and
non-maximal-but-broader-than-needed grants — ก้อง's kickoff note on
GitHub Actions' job-level-overrides-workflow-level precedence is baked
into the checklist item's guidance), broader script-injection patterns,
and broader secrets-in-logs patterns.

**Not a shared module with detectors/auth's (023) own checklist
infrastructure** — a deliberate call, not an oversight: the
`weaknessClass` enum genuinely differs per domain (023:
broken-authentication/broken-authorization; this plan: code-injection/
excessive-privilege/supply-chain-integrity/information-exposure), and
023 is already `done`/stable — refactoring it again for a shared schema
carries real regression risk for a benefit (avoiding ~100 lines of
schema duplication) that doesn't clearly outweigh it. Revisit if a
*third* playbook-shaped sub-skill appears (plan 005's "share once a
second consumer exists" precedent, applied here to mean the *second*
schema instance alone doesn't yet justify it).

`formatNotes` (not `languageNotes` — the axis here is pipeline format,
not programming language) covers github-actions/gitlab-ci/jenkinsfile
per item.

## Usage

```python
import scanner
import playbook

findings = scanner.scan_paths([".github/workflows/", ".gitlab-ci.yml"])  # deterministic half

checklist = playbook.load_checklist()
text = playbook.render_playbook(checklist, pipeline_format="jenkinsfile")
item = playbook.checklist_item(checklist, "cicd-pipeline.unpinned-external-reference")
errors = playbook.validate_agent_finding(finding)  # validate an agent-produced finding
```

```
python3 scanner.py path/to/repo
python3 playbook.py --format github-actions
```

## Not this module's job

- `CKV_GHA_5`/`6` (Cosign signing/SBOM) — 014's job.
- Secrets detection itself — 006's job, called into, not duplicated.
- A bespoke deterministic scanner for Jenkinsfile — verified no tool
  exists anywhere for it; the playbook is the mechanism, by design.
- Measuring whether an agent following the playbook actually catches
  real pipeline bugs — plan 020's job.

## Cross-platform

Every file read/write here specifies `encoding="utf-8"` explicitly.
Verify with (from inside this directory):
```
LC_ALL=en_US.US-ASCII LANG=en_US.US-ASCII python3 -m unittest test_scanner -v
LC_ALL=en_US.US-ASCII LANG=en_US.US-ASCII python3 -m unittest test_playbook -v
```
(macOS/Linux; see the top-level `security-skill/README.md`.)
