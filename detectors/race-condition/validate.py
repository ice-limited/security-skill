"""Validate a checklist JSON file against checklist.schema.json.

Usage: python3 validate.py path/to/checklist.json
Requires the `jsonschema` package (see ../../schema/requirements.txt —
same dependency, not duplicated here).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_common_dir = next(p for p in Path(__file__).resolve().parents if (p / "common").is_dir()) / "common"
sys.path.insert(0, str(_common_dir))
from schema_validation import validate_against_schema  # noqa: E402
from streams import reconfigure_streams  # noqa: E402

RACE_CONDITION_DIR = Path(__file__).parent


def validate_checklist(checklist: dict) -> list[str]:
    schema = json.loads((RACE_CONDITION_DIR / "checklist.schema.json").read_text(encoding="utf-8"))
    return validate_against_schema(schema, checklist)


if __name__ == "__main__":
    # See plans/022-cross-platform-compatibility.md.
    reconfigure_streams()
    checklist_path = Path(sys.argv[1])
    checklist = json.loads(checklist_path.read_text(encoding="utf-8"))
    errors = validate_checklist(checklist)
    if errors:
        for err in errors:
            print(f"INVALID: {err}", file=sys.stderr)
        sys.exit(1)
    print(f"OK: {checklist_path} is a valid checklist")
