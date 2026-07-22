"""SBOM validity scanning: finds JSON files that self-declare as a
CycloneDX or SPDX SBOM and validates them against the real, vendored
schema — see sbom_validate.py for the validation mechanism itself.

Presence (does the *pipeline* generate an SBOM at all) is scanner.py's
job (`supply-chain.missing-sbom-generation`, a CI-config-presence
check); this module only validates the *content* of an SBOM file that
already exists somewhere in the repo. A repo with no SBOM file at all
produces zero findings here — that's not a validity problem, and is
already covered by scanner.py's presence check.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import rules
import sbom_validate

_common_dir = next(p for p in Path(__file__).resolve().parents if (p / "common").is_dir()) / "common"
sys.path.insert(0, str(_common_dir))
from streams import reconfigure_streams  # noqa: E402

DETECTOR_NAME = "supply-chain-sbom-validator"

ScannerError = sbom_validate.SbomParseError


def _finding_id(rule_id: str, file: str, discriminator: str) -> str:
    key = f"{rule_id}|{file}|{discriminator}"
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
    return f"supply-chain-{digest}"


def _build_invalid_sbom_finding(file: str, sbom_format: str, errors: list[str]) -> dict:
    template = rules.INVALID_SBOM
    return {
        "findingId": _finding_id(template["rule_id"], file, sbom_format),
        "ruleId": template["rule_id"],
        "subSkill": "supply-chain",
        "artifactType": "config",
        "title": template["title"],
        "problem": template["problem"].format(sbom_format=sbom_format),
        "impact": template["impact"],
        "recommendation": template["recommendation"],
        "references": template["references"],
        "severity": template["severity"],
        "confidence": template["confidence"],
        "location": {"file": file, "startLine": 1, "endLine": 1},
        "detectorSource": {"name": DETECTOR_NAME, "version": "1.0.0"},
        "suppressed": False,
        "metadata": {"schemaValidationErrors": errors[:20]},
    }


def scan_file(path: Path) -> list[dict]:
    """Scans one JSON file: if it self-declares as a CycloneDX/SPDX
    SBOM, validates it against the real schema and returns a finding if
    invalid. Returns an empty list for a file that isn't an SBOM at
    all, or one that validates cleanly."""
    doc = sbom_validate.load_json_file(path)
    sbom_format = sbom_validate.detect_sbom_format(doc)
    if sbom_format is None:
        return []

    errors = sbom_validate.validate_sbom_content(doc, sbom_format)
    if not errors:
        return []

    return [_build_invalid_sbom_finding(str(path), sbom_format, errors)]


def _discover_json_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    return sorted(path.rglob("*.json"))


def scan_paths(paths: list[str]) -> list[dict]:
    """Scans one or more files/directories (any `.json` file found in
    a directory is checked for whether it self-declares as an SBOM —
    non-SBOM JSON files are silently skipped, not an error)."""
    findings: list[dict] = []
    for raw_path in paths:
        p = Path(raw_path)
        if not p.exists():
            raise ScannerError(f"path does not exist: {raw_path}")
        for json_file in _discover_json_files(p):
            findings.extend(scan_file(json_file))
    return findings


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Validate any CycloneDX/SPDX SBOM file(s) found under the given path(s).")
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
