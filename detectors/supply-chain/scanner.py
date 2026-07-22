"""Supply chain config-presence detection: does a GitHub Actions
workflow that builds a container image also sign it and generate an
SBOM for it, and does the workflow generate SLSA provenance anywhere?

Deterministic, hand-written (not Checkov-based) — see ci_config.py's
own docstring for why: Checkov's `CKV_GHA_5`/`CKV_GHA_6` were verified
non-functional at this plan's implementation (a real upstream bug, not
a narrow gap), so this plan writes its own checks instead, mirroring
009's own precedent for gaps no existing tool covers. See
plans/014-supply-chain-skill.md in the security-skill-workspace repo.

Static/config-presence only — never a live `cosign verify`/
`slsa-verifier verify-image` against a real registry, per this plan's
own kickoff decision (every other detector in this project is
static/local-file analysis; a live network call would make this the
only non-deterministic-across-runs check in the whole skill).
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import ci_config
import rules

_common_dir = next(p for p in Path(__file__).resolve().parents if (p / "common").is_dir()) / "common"
sys.path.insert(0, str(_common_dir))
from streams import reconfigure_streams  # noqa: E402

DETECTOR_NAME = "supply-chain-ci-config-scanner"

ScannerError = ci_config.WorkflowParseError


def _finding_id(rule_id: str, file: str, start_line: int, end_line: int, discriminator: str) -> str:
    key = f"{rule_id}|{file}|{start_line}|{end_line}|{discriminator}"
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
    return f"supply-chain-{digest}"


def _build_finding(template: dict, file: str, line: int, discriminator: str, **format_kwargs) -> dict:
    end_line = line
    return {
        "findingId": _finding_id(template["rule_id"], file, line, end_line, discriminator),
        "ruleId": template["rule_id"],
        "subSkill": "supply-chain",
        "artifactType": "github-actions",
        "title": template["title"],
        "problem": template["problem"].format(**format_kwargs),
        "impact": template["impact"].format(**format_kwargs),
        "recommendation": template["recommendation"].format(**format_kwargs),
        "references": template["references"],
        "severity": template["severity"],
        "confidence": template["confidence"],
        "location": {"file": file, "startLine": line, "endLine": end_line},
        "detectorSource": {"name": DETECTOR_NAME, "version": "1.0.0"},
        "suppressed": False,
    }


def scan_workflow_file(path: Path) -> list[dict]:
    """Scans one GitHub Actions workflow file for missing image
    signing, missing SBOM generation (per build job), and missing SLSA
    provenance (workflow-wide)."""
    file = str(path)
    workflow = ci_config.load_workflow(path)
    findings: list[dict] = []

    job_statuses = ci_config.analyze_jobs(workflow)
    any_build_job = False
    for status in job_statuses:
        if not status.has_build_step:
            continue
        any_build_job = True
        if not status.has_sign_step_after_build:
            findings.append(_build_finding(rules.MISSING_IMAGE_SIGNING, file, status.line, status.job_name))
        if not status.has_sbom_step_after_build:
            findings.append(_build_finding(rules.MISSING_SBOM_GENERATION, file, status.line, status.job_name))

    if any_build_job and not ci_config.has_slsa_provenance_generator(workflow):
        findings.append(_build_finding(rules.MISSING_SLSA_PROVENANCE, file, 1, "workflow"))

    return findings


def _discover_workflow_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    return sorted(path.glob(".github/workflows/*.yml")) + sorted(path.glob(".github/workflows/*.yaml"))


def scan_paths(paths: list[str]) -> list[dict]:
    """Scans one or more GitHub Actions workflow files, or directories
    (searched for `.github/workflows/*.yml`/`*.yaml`)."""
    findings: list[dict] = []
    for raw_path in paths:
        p = Path(raw_path)
        if not p.exists():
            raise ScannerError(f"path does not exist: {raw_path}")
        for workflow_file in _discover_workflow_files(p):
            findings.extend(scan_workflow_file(workflow_file))
    return findings


def scan_file(path: Path) -> list[dict]:
    return scan_paths([str(path)])


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Scan GitHub Actions workflow(s) for missing image signing, SBOM generation, and SLSA provenance.")
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
