"""Validate a policy JSON file against policy.schema.json.

Usage: python3 validate.py path/to/policy.json
Requires the `jsonschema` package (see ../schema/requirements.txt — same
dependency, not duplicated here).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

POLICY_DIR = Path(__file__).parent


def validate_policy(policy: dict) -> list[str]:
    schema = json.loads((POLICY_DIR / "policy.schema.json").read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    return [f"{'/'.join(str(p) for p in e.path)}: {e.message}" for e in validator.iter_errors(policy)]


if __name__ == "__main__":
    # See plans/022-cross-platform-compatibility.md.
    sys.stdout.reconfigure(encoding="utf-8", newline="\n")
    sys.stderr.reconfigure(encoding="utf-8", newline="\n")
    policy_path = Path(sys.argv[1])
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    errors = validate_policy(policy)
    if errors:
        for err in errors:
            print(f"INVALID: {err}", file=sys.stderr)
        sys.exit(1)
    print(f"OK: {policy_path} is a valid policy")
