"""Validate an exceptions JSON file against exceptions.schema.json.

Usage: python3 validate.py path/to/exceptions.json
Requires the `jsonschema` package (see ../schema/requirements.txt — same
dependency, not duplicated here).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

DECISION_DIR = Path(__file__).parent


def validate_exceptions(exceptions: dict) -> list[str]:
    schema = json.loads((DECISION_DIR / "exceptions.schema.json").read_text(encoding="utf-8"))
    # format_checker is required or jsonschema treats "format": "date" as
    # an annotation only (not enforced) — without it, a malformed
    # expiresAt like "not-a-date" would silently pass validation.
    validator = Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)
    return [f"{'/'.join(str(p) for p in e.path)}: {e.message}" for e in validator.iter_errors(exceptions)]


if __name__ == "__main__":
    # See plans/022-cross-platform-compatibility.md — explicit, not
    # locale-dependent.
    sys.stdout.reconfigure(encoding="utf-8", newline="\n")
    sys.stderr.reconfigure(encoding="utf-8", newline="\n")
    exceptions_path = Path(sys.argv[1])
    exceptions = json.loads(exceptions_path.read_text(encoding="utf-8"))
    errors = validate_exceptions(exceptions)
    if errors:
        for err in errors:
            print(f"INVALID: {err}", file=sys.stderr)
        sys.exit(1)
    print(f"OK: {exceptions_path} is a valid exceptions file")
