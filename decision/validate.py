"""Validate an exceptions JSON file against exceptions.schema.json.

Usage: python3 validate.py path/to/exceptions.json
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

DECISION_DIR = Path(__file__).parent


def validate_exceptions(exceptions: dict) -> list[str]:
    schema = json.loads((DECISION_DIR / "exceptions.schema.json").read_text(encoding="utf-8"))
    # common/schema_validation.py attaches format_checker, which is what
    # actually enforces "format": "date" here — without it jsonschema
    # treats format as an annotation only (not enforced), and a malformed
    # expiresAt like "not-a-date" would silently pass validation.
    return validate_against_schema(schema, exceptions)


if __name__ == "__main__":
    # See plans/022-cross-platform-compatibility.md — explicit, not
    # locale-dependent.
    reconfigure_streams()
    exceptions_path = Path(sys.argv[1])
    exceptions = json.loads(exceptions_path.read_text(encoding="utf-8"))
    errors = validate_exceptions(exceptions)
    if errors:
        for err in errors:
            print(f"INVALID: {err}", file=sys.stderr)
        sys.exit(1)
    print(f"OK: {exceptions_path} is a valid exceptions file")
