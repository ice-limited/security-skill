"""Validate a policy JSON file against policy.schema.json.

Usage: python3 validate.py path/to/policy.json
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

POLICY_DIR = Path(__file__).parent


def validate_policy(policy: dict) -> list[str]:
    schema = json.loads((POLICY_DIR / "policy.schema.json").read_text(encoding="utf-8"))
    return validate_against_schema(schema, policy)


if __name__ == "__main__":
    # See plans/022-cross-platform-compatibility.md.
    reconfigure_streams()
    policy_path = Path(sys.argv[1])
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    errors = validate_policy(policy)
    if errors:
        for err in errors:
            print(f"INVALID: {err}", file=sys.stderr)
        sys.exit(1)
    print(f"OK: {policy_path} is a valid policy")
