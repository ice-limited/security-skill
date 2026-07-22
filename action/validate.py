"""Validate a safety-tier JSON file against safety_tiers.schema.json.

Usage: python3 validate.py path/to/safety_tiers.json
Requires the `jsonschema` package (see ../schema/requirements.txt — same
dependency, not duplicated here).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_common_dir = next(p for p in Path(__file__).resolve().parents if (p / "common").is_dir()) / "common"
sys.path.insert(0, str(_common_dir))
from schema_validation import validate_against_schema  # noqa: E402
from streams import reconfigure_streams  # noqa: E402

ACTION_DIR = Path(__file__).parent


def validate_safety_tiers(tiers: dict) -> list[str]:
    schema = json.loads((ACTION_DIR / "safety_tiers.schema.json").read_text(encoding="utf-8"))
    return validate_against_schema(schema, tiers)


if __name__ == "__main__":
    # See plans/022-cross-platform-compatibility.md.
    reconfigure_streams()
    tiers_path = Path(sys.argv[1])
    tiers = json.loads(tiers_path.read_text(encoding="utf-8"))
    errors = validate_safety_tiers(tiers)
    if errors:
        for err in errors:
            print(f"INVALID: {err}", file=sys.stderr)
        sys.exit(1)
    print(f"OK: {tiers_path} is a valid safety-tier table")
