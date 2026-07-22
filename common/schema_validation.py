"""Shared JSON Schema validation, used by every validate.py in this repo.

Centralized here (plan 005) after policy/validate.py and
decision/validate.py converged on the identical Draft202012Validator
pattern, and schema/validate.py needed the same pattern plus cross-file
$ref resolution. Consolidating means `format_checker` (needed to
actually enforce keywords like `"format": "date"` — jsonschema treats
`format` as annotation-only without it, a real bug found and fixed
during plan 004's testing) is now attached everywhere by construction,
not only where someone remembered to add it.
"""

from __future__ import annotations

from jsonschema import Draft202012Validator


def validate_against_schema(schema: dict, instance: dict, registry=None) -> list[str]:
    """Validates `instance` against `schema`, returning formatted error
    strings (empty list if valid).

    `registry` is an optional `referencing.Registry` for schemas that
    `$ref` other schema files (see schema/validate.py, which resolves
    finding.schema.json from within scan-report.schema.json) — omit it
    for a self-contained schema (policy.schema.json, exceptions.schema.json).
    """
    if registry is not None:
        validator = Draft202012Validator(
            schema, registry=registry, format_checker=Draft202012Validator.FORMAT_CHECKER
        )
    else:
        validator = Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)
    return [f"{'/'.join(str(p) for p in e.path)}: {e.message}" for e in validator.iter_errors(instance)]
