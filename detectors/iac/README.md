# detectors/iac/

IaC misconfiguration detection: curated IAM + public-exposure checks
across Terraform (AWS/Azure/GCP), CloudFormation (AWS), and Ansible
playbook hardening. See `plans/011-iac-skill.md` and
`meetings/2026-07-22-2100-plan-011-kickoff.md` in the
security-skill-workspace repo for design rationale.

## Why Checkov, not Trivy

009/010 already wrap Trivy successfully, so this plan's kickoff
checked whether `trivy config` (already proven, already shared via
`common/trivy_wrapper.py`) covered Terraform/CloudFormation/Ansible
well enough to reuse, rather than assuming a new tool would be needed.
Three real, verified gaps ruled that out:

- **AWS**: Trivy's IAM-wildcard-policy check (`AWS-0057`) is marked
  `deprecated: true` in its own rego source and doesn't fire, even
  with `--include-deprecated-checks` explicitly passed.
- **GCP**: no project-level IAM check exists in Trivy's entire checks
  bundle at all — only bucket-level public access is covered. A
  `google_project_iam_binding` granting `roles/owner` to `allUsers`
  goes completely undetected.
- **Ansible**: despite `--misconfig-scanners` listing `ansible` as a
  supported mode, the checks bundle has zero Ansible-specific rego
  rules — every real playbook fixture tried reported "0 config files
  detected."

**Checkov** (github.com/bridgecrewio/checkov, Apache-2.0 — same license
family as Trivy) covers all three gaps with active, non-deprecated
checks, verified directly against the same fixtures. 009/010 keep
using Trivy (already proven sufficient there); this plan uses Checkov
instead of forcing a shared wrapper across two tools whose invocation
contracts differ enough to fight each other (see below).

## Not extracted to common/ (yet)

Unlike `common/trivy_wrapper.py` (shared between 009/010) and
`common/semgrep_wrapper.py` (shared between 007/023), this module's
Checkov-invocation logic stays self-contained in `scanner.py` — plan
005's own precedent is to extract to `common/` only once a *second*
consumer needs the same logic, and no other planned sub-skill
currently needs Checkov.

## Curated checklist, not Checkov's full catalog

Checkov ships ~1500+ checks across Terraform/CloudFormation/Ansible
with no embedded CWE/OWASP metadata (checked a check's Python source
directly at kickoff — just an `id`/`name`, nothing else) and no
severity in its open-source CLI output (`severity: null` on every
finding, verified empirically). Hand-curating the full catalog is
impractical, and ROLES.md's own framing for each cloud expert is
already narrow (IAM policy findings, S3/SG misconfig rules for AWS;
Azure AD/RBAC for Azure; GCP IAM for GCP) — this plan curates ~5-7
checks per cloud plus all of Checkov's built-in Ansible checks (minus
one judgment-call exclusion, see below), rather than exposing
everything. See `rules.py`'s `CHECKOV_RULES` for the full list with
hand-authored `problem`/`impact`/`recommendation`/`references`.

**Ansible** exposes all of Checkov's built-in task checks except
`CKV_AWS_135` ("EC2 is EBS optimized") — a cost/performance concern
with no confidentiality/integrity/availability implication for an
attacker, excluded as a judgment call distinct from the "curate a
focused checklist" scope decision (which was about coverage *breadth*,
not about including a check with no real security relevance).

## A real cross-framework nuance: check IDs aren't shared

Unlike Trivy's unified "cloud" schema (identical check IDs regardless
of Terraform vs. CloudFormation source), **Checkov's check IDs are
often framework-specific for the same logical concern** — verified by
running an identical fixture (public S3 + wildcard IAM policy + open
security group) through both a `.tf` file and an equivalent
CloudFormation template and diffing the resulting check IDs. IAM
privilege escalation, for example, is `CKV_AWS_286` in Terraform but
`CKV_AWS_110` in CloudFormation. `rules.py`'s `CheckovRule.check_ids`
is therefore a `{framework: check_id}` dict, not a single ID — the
reverse of `common/trivy_wrapper.py`'s flat 1:1 shape — and
`scanner.py` builds a `(framework, check_id) -> CheckovRule` reverse
index at import time (`_CHECK_ID_INDEX`) to look up which curated rule,
if any, a given Checkov finding maps to.

## Three real Checkov quirks found during implementation, not by inspection

1. **Passing more than one path to a single invocation garbles the
   JSON output.** `checkov -d dirA -d dirB` doesn't error — it silently
   produces *two JSON documents concatenated back to back* in stdout,
   which isn't valid JSON as a whole and isn't a JSON array either
   (`json.loads()` raises "Extra data"). `scan_paths()` invokes
   `run_checkov()` once per path and aggregates, exactly like
   009/010's own one-Trivy-invocation-per-path constraint, but for a
   different underlying reason.
2. **The top-level `-o json` shape is polymorphic.** A bare summary
   dict with no `check_type`/`results` keys when nothing matched *any*
   requested framework at all; a single `check_type`/`results`/
   `summary` dict when exactly one framework matched; a list of such
   dicts when more than one framework matched within the same scanned
   path (e.g. a directory containing both Terraform and Ansible
   files). `run_checkov()` normalizes all three to a list.
3. **`file_abs_path` isn't actually absolute for CloudFormation.**
   Terraform and Ansible results come back genuinely absolute
   regardless of what was passed on the command line, but
   CloudFormation's `file_abs_path` just echoes back whatever path
   string was given — relative or not. The same class of bug 009 found
   with Trivy's `Target` field. Fixed in `_resolve_file_path()` via
   `.resolve()` against this process's own CWD (safe because nothing
   in this module changes CWD between invoking checkov and processing
   its output). Mutation-tested: reverting the fix, an end-to-end test
   using `tempfile.TemporaryDirectory()` alone did *not* catch the
   regression (that path is always already absolute) — a dedicated
   test that `os.chdir()`s into the fixture directory and passes a
   bare relative filename was needed to actually exercise the bug
   (`test_cloudformation_stays_absolute_even_when_caller_passes_a_relative_path`).

## Error handling — a third, distinct exit-code contract

Checkov's exit-code convention differs from both Trivy's (`0`=success
regardless of findings, nonzero=failure) and 008's osv-scanner's (`0`
or `1` both valid, content-dependent): here `0` means "ran cleanly, may
or may not have findings," `1` means "ran cleanly AND has findings"
(not a failure), and only `2` (or a crash) is a genuine invocation
error. Separately, checkov's own path-validation is unreliable: a
genuinely nonexistent directory reports the *identical* zero-count
JSON summary and exit `0` as a real, empty, existing directory — the
only difference is a stderr log line, too fragile to depend on.
`run_checkov()` validates the path itself (`Path(path).exists()`)
before ever invoking checkov, rather than trying to parse its
inconsistent error signaling.

## Known limitation: a malformed file's parse failure isn't surfaced

Found during the "test plan 011" round, verified for real: a directory
containing one syntactically-broken `.tf` file alongside valid ones
does not fail the whole scan — checkov records a `parsing_errors` count
for the broken file internally while still scanning and reporting on
every valid sibling file normally (confirmed empirically, not assumed).
This module currently does **not** surface that count anywhere;
`finding.schema.json` has no slot for "this file failed to parse," and
raising `ScannerError` for any nonzero `parsing_errors` would be worse
— it would fail an otherwise-successful scan of every *other* file just
because one had a typo. `test_malformed_file_does_not_crash_and_valid_sibling_still_scans`
locks in today's actual behavior (no crash, valid files still scan) so
a future change to this area is measured against real behavior, not
assumption. Surfacing parse failures as their own signal (e.g. a
warning channel distinct from findings) is a reasonable future
enhancement, not built here.

## Usage

```python
from scanner import scan_file, scan_paths

findings = scan_paths(["path/to/repo"])   # invokes checkov once per path given
findings = scan_file(Path("main.tf"))
```

```
python3 scanner.py path/to/project
```

Requires the real `checkov` CLI on `PATH` (`pip install -r
requirements.txt`, or `pip install checkov` directly).
`test_scanner.py`'s subprocess-driving tests skip themselves (not
fail) if it isn't installed, but are never mocked when it is (same
discipline as every prior external-tool wrapper here).

## Not this module's job

- File selection/exclusion — orchestration concern, same boundary as
  every other detector here.
- Helm entirely — verified at kickoff that neither Trivy nor Checkov
  has a concept of "chart authoring" distinct from rendering the chart
  and scanning the output as Kubernetes manifests, which is exactly
  010's job already (`detectors/kubernetes/`). The original plan
  stub's "Helm chart authoring, as distinct from rendered-manifest
  checks in 010" didn't correspond to anything either tool actually
  offers, so it was dropped from scope entirely rather than built.
- Rendered Kubernetes manifest checks generally — 010's job.
- Checkov's full catalog beyond the curated checklist (encryption-at-
  rest, logging, versioning, backup/replication, etc.) — real,
  legitimate concerns, good candidates for a future scope expansion.
- Additional Ansible patterns beyond Checkov's built-in checks (file
  permissions, command injection via Jinja2 templating) — a future
  scope-expansion candidate, not custom-built now.

## Cross-platform

Every file read/write here specifies `encoding="utf-8"` explicitly.
Verify with:
`LC_ALL=en_US.US-ASCII LANG=en_US.US-ASCII python3 -m unittest test_scanner -v`
(macOS/Linux; see the top-level `security-skill/README.md`). Checkov
is a pip-installed Python CLI, so it has the same cross-platform story
as `pip install`-based tooling generally (no separate Windows binary
concern the way Trivy/Helm needed to verify).
