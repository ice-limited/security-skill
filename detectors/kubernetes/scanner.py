"""Kubernetes workload-hardening detection: hostNetwork/hostPID/
hostPath, privileged/root containers, unpinned `:latest` image tags,
missing CPU/memory limits, and writable root filesystems — via Trivy's
`config` scan mode, exactly the same scan mode 009 already wraps for
Dockerfiles.

Decided at kickoff: no new external tool, no custom rules. Trivy
already covers all 8 CONTEXT.md §7 checklist items natively, verified
for real against a synthetic Deployment manifest and a real
`helm create`-generated chart — see plans/010-kubernetes-skill.md and
meetings/2026-07-22-2000-plan-010-kickoff.md in the
security-skill-workspace repo for design rationale.

The actual subprocess/mapping logic lives in common/trivy_wrapper.py,
shared with detectors/docker/scanner.py (009) — this module is a thin,
subSkill-specific wrapper over it: its own rule catalog (rules.py) and
the raw-YAML-vs-Helm artifactType mapping (Trivy's own JSON output
tells us which one it was via each result's `Type` field — "kubernetes"
or "helm" — verified for real at implementation, not assumed).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from rules import TRIVY_RULES

_common_dir = next(p for p in Path(__file__).resolve().parents if (p / "common").is_dir()) / "common"
sys.path.insert(0, str(_common_dir))
import trivy_wrapper as _tw  # noqa: E402
from streams import reconfigure_streams  # noqa: E402

DETECTOR_NAME = "kubernetes-trivy-wrapper"

# Trivy's own `Type` field on each result ("kubernetes" or "helm" —
# verified for real at implementation) maps directly to two distinct
# finding.schema.json artifactType values; anything else falls back to
# "kubernetes-yaml" rather than raising, since Trivy's config scan mode
# is not expected to report any other Type for inputs this detector is
# pointed at.
_ARTIFACT_TYPE_BY_TRIVY_TYPE = {"kubernetes": "kubernetes-yaml", "helm": "helm"}

ScannerError = _tw.ScannerError


def run_trivy(path: str) -> dict:
    return _tw.run_trivy(path)


def map_trivy_misconfig(misconfig: dict, file: str, artifact_type: str, trivy_version: str) -> dict | None:
    """Maps one Trivy misconfiguration object to a finding.schema.json
    dict, using this plan's own hand-authored rule catalog (Trivy's own
    metadata has no CWE mapping). Returns None for a Trivy check ID
    this plan doesn't have a curated mapping for — Trivy reports ~23
    Kubernetes checks total, but this plan deliberately curates to the
    8 items in CONTEXT.md §7 (see kickoff decision)."""
    return _tw.map_trivy_misconfig(
        misconfig,
        file,
        artifact_type,
        trivy_version,
        sub_skill="kubernetes",
        rule_catalog=TRIVY_RULES,
        id_prefix="kubernetes",
        detector_name=DETECTOR_NAME,
    )


def _resolve_target_path(artifact_name: str, target: str) -> Path:
    return _tw.resolve_target_path(artifact_name, target)


def scan_paths(paths: list[str]) -> list[dict]:
    """Scans one or more files/directories (raw Kubernetes YAML or a
    Helm chart directory — Trivy renders and scans Helm charts
    natively, no `helm` CLI dependency needed at scan time) via Trivy's
    `config` mode. No custom-rules layer — unlike 009, this plan's
    entire curated scope is covered by Trivy's own checks.

    Invokes Trivy once per path, not once for the whole list — same
    constraint as 009 (see common/trivy_wrapper.py's run_trivy())."""
    findings = []
    for file, result, trivy_version in _tw.iter_scanned_files(paths):
        artifact_type = _ARTIFACT_TYPE_BY_TRIVY_TYPE.get(result.get("Type"), "kubernetes-yaml")
        for misconfig in result.get("Misconfigurations") or []:
            mapped = map_trivy_misconfig(misconfig, file, artifact_type, trivy_version)
            if mapped is not None:
                findings.append(mapped)

    return findings


def scan_file(path: Path) -> list[dict]:
    return scan_paths([str(path)])


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Scan Kubernetes YAML/Helm chart(s) for workload-hardening issues via Trivy.")
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
