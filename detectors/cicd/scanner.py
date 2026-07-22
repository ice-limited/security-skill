"""CI/CD pipeline misconfiguration detection: script injection,
insecure workflow commands, secrets-in-logs patterns, and excessive
top-level permissions across GitHub Actions and GitLab CI, via a thin
wrapper around the Checkov CLI (subprocess).

Decided at kickoff: reuse Checkov (already wrapped by 011), not
`zizmor` (a purpose-built, more deeply-covering GitHub-Actions-only
tool) — an explicit consistency trade-off, not an oversight. See
plans/013-cicd-pipeline-skill.md and
meetings/2026-07-22-2300-plan-013-kickoff.md in the
security-skill-workspace repo for the full empirical trail.

The actual subprocess/mapping logic lives in common/checkov_wrapper.py
— shared with detectors/iac/scanner.py (011), extracted there at this
plan's implementation once 013 became Checkov's second consumer, per
plan 005's "shared module once a second consumer exists" precedent.
This module is a thin, subSkill-specific wrapper over it: which
frameworks (github_actions/gitlab_ci) and which subSkill/ruleId
namespace ("cicd"). This is the deterministic half only — see
playbook.py for the broader script-injection/secrets-in-logs/unpinned-
references/excessive-permissions coverage this rule catalog doesn't
reach (`CKV_GHA_5`/`6`, Cosign checks, are also out of scope here,
deferred to 014).
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

DETECTOR_NAME = "cicd-pipeline-checkov-wrapper"

# This plan's curated scope, per the kickoff decision.
FRAMEWORKS = ("github_actions", "gitlab_ci")

# Checkov's own check_type strings use underscores; finding.schema.json's
# artifactType enum uses hyphens for these two values — verified real
# at implementation (011's own frameworks needed no such mapping, since
# Checkov's terraform/cloudformation/ansible strings already match the
# schema exactly).
_ARTIFACT_TYPE_MAP = {"github_actions": "github-actions", "gitlab_ci": "gitlab-ci"}

ScannerError = _cw.ScannerError
_CHECK_ID_INDEX = _cw.build_check_id_index(CHECKOV_RULES)


def run_checkov(path: str) -> list[dict]:
    return _cw.run_checkov(path, FRAMEWORKS)


def map_checkov_check(check: dict, framework: str, checkov_version: str) -> dict | None:
    """Maps one Checkov failed-check object to a finding.schema.json
    dict, using this plan's own hand-authored rule catalog. Returns
    None for a Checkov check ID this plan doesn't have a curated
    mapping for (including `CKV_GHA_5`/`6`, deliberately deferred to
    014, and `CKV_GITLABCI_2`/`3`, excluded as non-security/dead code —
    see rules.py) — silently skipped, not an error."""
    return _cw.map_checkov_check(
        check,
        framework,
        checkov_version,
        sub_skill="cicd-pipeline",
        rule_catalog_index=_CHECK_ID_INDEX,
        id_prefix="cicd-pipeline",
        detector_name=DETECTOR_NAME,
        artifact_type_map=_ARTIFACT_TYPE_MAP,
    )


def scan_paths(paths: list[str]) -> list[dict]:
    """Scans one or more files/directories (GitHub Actions workflow
    YAML under `.github/workflows/`, or GitLab CI YAML — any mix within
    a single path is auto-detected per-file by checkov itself) for this
    plan's curated script-injection/secrets/permissions checklist.

    Invokes checkov once per path, not once for the whole list — same
    constraint 011 already found real (see
    common/checkov_wrapper.py's run_checkov())."""
    return _cw.scan_paths(
        [str(p) for p in paths],
        FRAMEWORKS,
        sub_skill="cicd-pipeline",
        rule_catalog_index=_CHECK_ID_INDEX,
        id_prefix="cicd-pipeline",
        detector_name=DETECTOR_NAME,
        artifact_type_map=_ARTIFACT_TYPE_MAP,
    )


def scan_file(path: Path) -> list[dict]:
    return scan_paths([str(path)])


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Scan GitHub Actions/GitLab CI pipeline config for script-injection/secrets/permissions issues via Checkov.")
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
