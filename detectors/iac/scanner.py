"""IaC misconfiguration detection: curated IAM + public-exposure checks
across Terraform (AWS/Azure/GCP)/CloudFormation (AWS)/Ansible, via a
thin wrapper around the Checkov CLI (subprocess).

Decided at kickoff: wraps Checkov (github.com/bridgecrewio/checkov,
Apache-2.0), not Trivy (already wrapped for 009/010) — verified for
real that Trivy's AWS IAM-wildcard check is deprecated and doesn't
fire, GCP has no project-level IAM check at all, and Ansible has zero
shipped checks despite being a listed scanner mode. See
plans/011-iac-skill.md and
meetings/2026-07-22-2100-plan-011-kickoff.md in the
security-skill-workspace repo for the full empirical trail and every
tool-quirk finding referenced below.

The actual subprocess/mapping logic lives in common/checkov_wrapper.py
— extracted there at plan 013's implementation once 013 (CI/CD
Pipeline Skill) needed the same Checkov-wrapping logic for the
`github_actions`/`gitlab_ci` frameworks, per plan 005's "shared module
once a second consumer exists" precedent (the same trigger that moved
Semgrep/Trivy wrapping to common/ for 023/010). This module is now a
thin, subSkill-specific wrapper over it: which frameworks
(terraform/cloudformation/ansible) and which subSkill/ruleId namespace
("iac").
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from rules import CHECKOV_RULES

_common_dir = next(p for p in Path(__file__).resolve().parents if (p / "common").is_dir()) / "common"
sys.path.insert(0, str(_common_dir))
import checkov_wrapper as _cw  # noqa: E402
from streams import reconfigure_streams  # noqa: E402

DETECTOR_NAME = "iac-checkov-wrapper"

# This plan's curated scope, per the kickoff decision (Helm dropped
# entirely — verified redundant with 010's rendered-manifest checks).
FRAMEWORKS = ("terraform", "cloudformation", "ansible")

ScannerError = _cw.ScannerError
_CHECK_ID_INDEX = _cw.build_check_id_index(CHECKOV_RULES)


def run_checkov(path: str) -> list[dict]:
    return _cw.run_checkov(path, FRAMEWORKS)


def map_checkov_check(check: dict, framework: str, checkov_version: str) -> dict | None:
    """Maps one Checkov failed-check object to a finding.schema.json
    dict, using this plan's own hand-authored rule catalog (Checkov's
    own check metadata has no CWE mapping). Returns None for a Checkov
    check ID this plan doesn't have a curated mapping for (Checkov
    ships ~1500+ checks across these three frameworks; this plan
    curates a focused IAM + public-exposure subset per the kickoff
    decision) — silently skipped, not an error."""
    return _cw.map_checkov_check(
        check,
        framework,
        checkov_version,
        sub_skill="iac",
        rule_catalog_index=_CHECK_ID_INDEX,
        id_prefix="iac",
        detector_name=DETECTOR_NAME,
    )


def scan_paths(paths: list[str]) -> list[dict]:
    """Scans one or more files/directories (Terraform, CloudFormation,
    or Ansible content — any mix within a single path is auto-detected
    per-file by checkov itself) for this plan's curated IAM +
    public-exposure checklist.

    Invokes checkov once per path, not once for the whole list —
    verified for real that passing multiple paths to one invocation
    produces malformed concatenated JSON (see common/checkov_wrapper.py's
    run_checkov())."""
    return _cw.scan_paths(
        [str(p) for p in paths],
        FRAMEWORKS,
        sub_skill="iac",
        rule_catalog_index=_CHECK_ID_INDEX,
        id_prefix="iac",
        detector_name=DETECTOR_NAME,
    )


def scan_file(path: Path) -> list[dict]:
    return scan_paths([str(path)])


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Scan Terraform/CloudFormation/Ansible for IAM + public-exposure misconfigurations via Checkov.")
    parser.add_argument("paths", nargs="+", type=Path)
    args = parser.parse_args(argv)

    try:
        findings = scan_paths([str(p) for p in args.paths])
    except ScannerError as e:
        print(f"SCANNER ERROR: {e}", file=sys.stderr)
        return 1

    print(json.dumps(findings, indent=2))
    return 0


if __name__ == "__main__":
    reconfigure_streams()
    sys.exit(main())
