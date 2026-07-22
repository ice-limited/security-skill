"""Validate a ScanReport JSON file against scan-report.schema.json, or a
Remediation JSON file against remediation.schema.json (plan 015 —
remediation.schema.json's own `patch.location` field `$ref`s
finding.schema.json's location def, the same cross-file `$ref` need
`validate_report` already resolves for ScanReport's `findings[]`).

Usage: python3 validate.py path/to/report.json
Requires the `jsonschema` package (see requirements.txt).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from referencing import Registry, Resource

_common_dir = next(p for p in Path(__file__).resolve().parents if (p / "common").is_dir()) / "common"
sys.path.insert(0, str(_common_dir))
from schema_validation import validate_against_schema  # noqa: E402
from streams import reconfigure_streams  # noqa: E402

SCHEMA_DIR = Path(__file__).parent


def _load(name: str) -> dict:
    return json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))


def _finding_registry(finding_schema: dict) -> Registry:
    return Registry().with_resources(
        [
            (finding_schema["$id"], Resource.from_contents(finding_schema)),
            ("finding.schema.json", Resource.from_contents(finding_schema)),
        ]
    )


def validate_report(report: dict) -> list[str]:
    finding_schema = _load("finding.schema.json")
    scan_report_schema = _load("scan-report.schema.json")
    return validate_against_schema(scan_report_schema, report, registry=_finding_registry(finding_schema))


def validate_remediation(remediation: dict) -> list[str]:
    finding_schema = _load("finding.schema.json")
    remediation_schema = _load("remediation.schema.json")
    return validate_against_schema(remediation_schema, remediation, registry=_finding_registry(finding_schema))


if __name__ == "__main__":
    # See plans/022-cross-platform-compatibility.md.
    reconfigure_streams()
    report_path = Path(sys.argv[1])
    report = json.loads(report_path.read_text(encoding="utf-8"))
    errors = validate_report(report)
    if errors:
        for err in errors:
            print(f"INVALID: {err}", file=sys.stderr)
        sys.exit(1)
    print(f"OK: {report_path} is a valid ScanReport")
