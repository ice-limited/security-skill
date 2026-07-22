"""Validate a ScanReport JSON file against scan-report.schema.json.

Usage: python3 validate.py path/to/report.json
Requires the `jsonschema` package (see requirements.txt).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

SCHEMA_DIR = Path(__file__).parent


def _load(name: str) -> dict:
    return json.loads((SCHEMA_DIR / name).read_text())


def validate_report(report: dict) -> list[str]:
    finding_schema = _load("finding.schema.json")
    scan_report_schema = _load("scan-report.schema.json")

    registry = Registry().with_resources(
        [
            (finding_schema["$id"], Resource.from_contents(finding_schema)),
            ("finding.schema.json", Resource.from_contents(finding_schema)),
        ]
    )
    validator = Draft202012Validator(scan_report_schema, registry=registry)

    return [f"{'/'.join(str(p) for p in e.path)}: {e.message}" for e in validator.iter_errors(report)]


if __name__ == "__main__":
    report_path = Path(sys.argv[1])
    report = json.loads(report_path.read_text())
    errors = validate_report(report)
    if errors:
        for err in errors:
            print(f"INVALID: {err}", file=sys.stderr)
        sys.exit(1)
    print(f"OK: {report_path} is a valid ScanReport")
