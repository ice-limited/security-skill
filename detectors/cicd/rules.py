"""CI/CD pipeline misconfiguration rule catalog: script injection,
insecure workflow commands, secrets-in-logs, netcat/reverse-shell
patterns, and excessive top-level permissions across GitHub Actions and
GitLab CI, via Checkov (github.com/bridgecrewio/checkov, Apache-2.0) —
the same tool 011 already wraps.

Decided at kickoff (see plans/013-cicd-pipeline-skill.md and
meetings/2026-07-22-2300-plan-013-kickoff.md in the
security-skill-workspace repo): Checkov chosen as primary tool over
`zizmor` (a purpose-built, 39-audit GitHub-Actions-only tool verified
to have much deeper coverage) for consistency with 011's already-
wrapped tool — an explicit, understood trade-off, not an oversight.
The resulting coverage gap (unpinned action/image references,
non-maximal excessive permissions, broader script-injection/secrets-in-
-logs patterns) is closed by this sub-skill's playbook half
(playbook.py/checklist.json), not by this rule catalog.

**Real correction from the kickoff's own research**: the kickoff found
only 7 `CKV_GHA_*` checks by reading `checks/job/*.py`. Verified at
implementation that Checkov *also* ships one graph-based check,
`CKV2_GHA_1` ("Ensure top-level permissions are not set to write-all"),
stored as a JSON graph-check definition
(`checkov/github_actions/checks/graph_checks/ReadOnlyTopLevelPermissions.json`),
not a Python check class — invisible to a `*.py`-only source search.
This directly closes part of the "excessive permissions" gap the
kickoff assumed was entirely playbook-only: the *maximal* `write-all`
case is now a deterministic Checkov finding; only job-level permissions
and non-maximal-but-still-broader-than-needed grants remain
playbook-only (per ก้อง's kickoff note on that exact nuance).

Curated to exactly the checks relevant to this plan's declared scope
(script injection, unpinned/insecure-command patterns, secrets in
logs, excessive permissions) — `CKV_GHA_5`/`6` (Cosign artifact-signing/
SBOM-attestation presence) are explicitly excluded, deferred to 014
(Supply Chain Skill), even though Checkov ships them under the same
`github_actions` framework. `CKV_GITLABCI_2` (pipeline-efficiency, not
security) and `CKV_GITLABCI_3` (verified dead code — its `scan_conf()`
unconditionally returns `PASSED`, incapable of ever firing) are
excluded too.

CWE references verified directly against cwe.mitre.org and
owasp.org/Top10/2025 at implementation, not guessed:
- **CWE-94** ("Improper Control of Generation of Code ('Code
  Injection')") — newly added for `CKV_GHA_1`/`CKV_GHA_2`. Confirmed
  officially mapped to OWASP A05:2025 (Injection) — added to that
  category's `relatedCwe` crosswalk in `knowledge/owasp-top10.json`.
- **CWE-532** ("Insertion of Sensitive Information into Log File") —
  newly added for the curl+secret pattern (`CKV_GHA_3`/`CKV_GITLABCI_1`
  — shared `rule_id`, one per framework, mirroring 011's own
  cross-framework `check_ids` shape for the identical underlying
  concern). Confirmed officially mapped to OWASP A09:2025 (Security
  Logging and Alerting Failures) — added to that category's
  `relatedCwe` crosswalk too (previously unpopulated).
- **CWE-506** ("Embedded Malicious Code") — reused as-is for the
  netcat/reverse-shell pattern (`CKV_GHA_4`); a reverse shell embedded
  in a workflow script fits this definition directly.
- **CWE-20** ("Improper Input Validation") — reused as-is for
  `CKV_GHA_7` (non-empty `workflow_dispatch` inputs affecting build
  output); confirmed officially mapped to OWASP A05:2025 too (added to
  that same crosswalk above).
- **CWE-269** ("Improper Privilege Management") — reused as-is for
  `CKV2_GHA_1` (top-level `permissions: write-all`), matching 011's own
  IAM-wildcard precedent exactly; already paired with OWASP A06:2025
  (Insecure Design) in the knowledge base.
"""

from __future__ import annotations

import sys
from pathlib import Path

_common_dir = next(p for p in Path(__file__).resolve().parents if (p / "common").is_dir()) / "common"
sys.path.insert(0, str(_common_dir))
from checkov_wrapper import CheckovRule  # noqa: E402

_CODE_INJECTION_REFS = [{"standard": "CWE", "id": "CWE-94"}, {"standard": "OWASP-Top10", "id": "A05:2025"}]
_SECRETS_IN_LOGS_REFS = [{"standard": "CWE", "id": "CWE-532"}, {"standard": "OWASP-Top10", "id": "A09:2025"}]
_MALICIOUS_CODE_REFS = [{"standard": "CWE", "id": "CWE-506"}]
_INPUT_VALIDATION_REFS = [{"standard": "CWE", "id": "CWE-20"}, {"standard": "OWASP-Top10", "id": "A05:2025"}]
_EXCESSIVE_PERMISSIONS_REFS = [{"standard": "CWE", "id": "CWE-269"}, {"standard": "OWASP-Top10", "id": "A06:2025"}]

CHECKOV_RULES: list[CheckovRule] = [
    CheckovRule(
        rule_id="cicd-pipeline.unsecure-commands-enabled",
        title="Workflow re-enables deprecated, code-injection-prone workflow commands",
        problem=(
            "A job sets the `ACTIONS_ALLOW_UNSECURE_COMMANDS` environment variable to `true`, re-enabling "
            "GitHub's deprecated `::set-env`/`::add-path` workflow commands."
        ),
        impact=(
            "These commands were deprecated specifically because untrusted step output (e.g. from a "
            "third-party action or a build tool) could inject arbitrary environment variables or PATH entries "
            "into later steps, letting an attacker control subsequent command execution."
        ),
        recommendation="Remove `ACTIONS_ALLOW_UNSECURE_COMMANDS`; use `$GITHUB_ENV`/`$GITHUB_PATH` file-based commands instead.",
        references=_CODE_INJECTION_REFS,
        severity="High",
        confidence=85,
        check_ids={"github_actions": "CKV_GHA_1"},
    ),
    CheckovRule(
        rule_id="cicd-pipeline.shell-injection-pattern",
        title="Step's run command matches a known shell-injection-prone pattern",
        problem=(
            "A `run:` step's shell command matches a pattern known to be vulnerable to shell injection when "
            "combined with untrusted, expression-interpolated input (e.g. `${{ github.event.issue.title }}` "
            "piped directly into a shell)."
        ),
        impact=(
            "If the interpolated value is attacker-controlled (a PR title, issue body, branch name, commit "
            "message), the attacker can inject arbitrary shell commands that execute with the workflow's own "
            "permissions and secrets access."
        ),
        recommendation=(
            "Never interpolate untrusted `${{ ... }}` expressions directly into a `run:` shell command — pass "
            "them through an intermediate environment variable instead (`env: MY_VAR: ${{ ... }}`, then "
            "reference `$MY_VAR` in the script), which the shell does not re-parse as code."
        ),
        references=_CODE_INJECTION_REFS,
        severity="Critical",
        confidence=70,
        check_ids={"github_actions": "CKV_GHA_2"},
    ),
    CheckovRule(
        rule_id="cicd-pipeline.curl-with-secret-in-script",
        title="Script uses curl together with a secret/CI credential variable",
        problem=(
            "A pipeline script uses `curl` in the same line as a secret or CI-provided credential variable "
            "(e.g. `secrets.*` in GitHub Actions, `$CI_JOB_TOKEN`/`$CI_*` in GitLab CI)."
        ),
        impact=(
            "Command lines are frequently captured in build logs, shell history, or process listings — a "
            "secret passed this way (rather than via a header/auth mechanism curl itself redacts) risks "
            "leaking into any of those channels."
        ),
        recommendation=(
            "Avoid passing secrets as plain command-line arguments; use curl's `--netrc`/config-file "
            "credential mechanisms, or a header passed via a masked CI variable the platform itself redacts "
            "from logs."
        ),
        references=_SECRETS_IN_LOGS_REFS,
        severity="High",
        confidence=60,
        check_ids={"github_actions": "CKV_GHA_3", "gitlab_ci": "CKV_GITLABCI_1"},
    ),
    CheckovRule(
        rule_id="cicd-pipeline.reverse-shell-pattern",
        title="Step's run command matches a netcat reverse-shell pattern",
        problem="A `run:` step's shell command matches a pattern consistent with opening a reverse shell via netcat to a hardcoded IP address.",
        impact="If reachable from a real pipeline run (not just a test fixture), this gives whoever controls that IP an interactive shell with the workflow's own permissions and secrets access — a strong indicator of a compromised or maliciously modified pipeline.",
        recommendation="Remove the command; treat its presence as a strong incident-response signal, not just a lint finding, if found in a real repository rather than a test fixture.",
        references=_MALICIOUS_CODE_REFS,
        severity="Critical",
        confidence=75,
        check_ids={"github_actions": "CKV_GHA_4"},
    ),
    CheckovRule(
        rule_id="cicd-pipeline.workflow-dispatch-inputs-affect-build",
        title="workflow_dispatch declares inputs that can influence build output",
        problem="The workflow's `workflow_dispatch` trigger declares one or more `inputs`, letting a manual run pass arbitrary caller-supplied values into the workflow.",
        impact="If any declared input reaches a build step (a version string, a build flag, a script argument), a caller with workflow_dispatch permission can influence the build's behavior or output beyond just choosing the entry point and source location.",
        recommendation="Remove `workflow_dispatch` inputs, or ensure none of them reach build/execution steps unvalidated — treat every input the same as other untrusted, attacker-influenceable data.",
        references=_INPUT_VALIDATION_REFS,
        severity="Medium",
        confidence=45,
        check_ids={"github_actions": "CKV_GHA_7"},
    ),
    CheckovRule(
        rule_id="cicd-pipeline.excessive-top-level-permissions",
        title="Workflow's top-level permissions are set to write-all",
        problem="The workflow's top-level `permissions:` block is set to `write-all`, granting the `GITHUB_TOKEN` write access to every scope (contents, issues, pull-requests, packages, etc.) for every job in the workflow.",
        impact="A compromised or malicious step (a poisoned dependency, a subverted third-party action, an injected command from untrusted input) inherits this maximal token scope, able to modify repository contents, releases, issues, and more — far beyond what almost any single job actually needs.",
        recommendation="Set `permissions:` to the minimum scopes each job actually needs (ideally `contents: read` at the top level, with job-level overrides granting only what that specific job requires), rather than `write-all`.",
        references=_EXCESSIVE_PERMISSIONS_REFS,
        severity="High",
        confidence=80,
        check_ids={"github_actions": "CKV2_GHA_1"},
    ),
]
