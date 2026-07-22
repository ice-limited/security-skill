"""Check that every `references[]` entry in a ScanReport cites a standard
ID that actually exists in the knowledge base.

This is a *semantic* check, separate from schema/validate.py's structural
JSON Schema validation — a reference can be structurally valid (right
shape, `standard` is one of the 8 allowed enum values) while still citing
a typo'd or non-existent ID within that standard. Catching that here at
detector-development time is exactly what plan 002 exists for.

Usage: python3 validate_references.py path/to/report.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import standards


def find_unknown_references(report: dict) -> list[str]:
    problems = []
    for finding in report.get("findings", []):
        for ref in finding.get("references", []):
            std, ref_id = ref["standard"], ref["id"]
            if not standards.exists(std, ref_id):
                problems.append(
                    f"finding {finding.get('findingId', '?')}: "
                    f"{std} {ref_id} not found in knowledge/{std}"
                )
    return problems


if __name__ == "__main__":
    report_path = Path(sys.argv[1])
    report = json.loads(report_path.read_text())
    problems = find_unknown_references(report)
    if problems:
        for p in problems:
            print(f"UNKNOWN REFERENCE: {p}", file=sys.stderr)
        sys.exit(1)
    print(f"OK: all references in {report_path} resolve against the knowledge base")
