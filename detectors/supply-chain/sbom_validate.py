"""SBOM presence + structural validity: detects whether a file is a
CycloneDX or SPDX SBOM (by its own self-declared format fields) and, if
so, validates it against the actual published CycloneDX/SPDX JSON
Schema — per วิน's request at this plan's kickoff, not a hand-rolled
approximation of what a "valid" SBOM looks like.

Schemas vendored under `schemas/` (see `schemas/README.md` for exact
source URLs, versions, and licenses — CycloneDX 1.6, Apache-2.0; SPDX
2.3, Community Specification License 1.0 / CC-BY-3.0). Both are
JSON Schema **draft-07**, not this project's own draft 2020-12 —
`common/schema_validation.py`'s `validate_against_schema` hardcodes
`Draft202012Validator`, which is correct for this project's *own*
schemas but not appropriate to force onto a third-party draft-07
schema. Uses `jsonschema.validator_for(schema)` instead, which picks
the validator class matching the schema's own declared `$schema` —
the correct general approach for validating against an external schema
of unknown/varying draft version, not a reinvention of the shared
helper for its own sake.
"""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import FormatChecker

SUPPLY_CHAIN_DIR = Path(__file__).parent
SCHEMAS_DIR = SUPPLY_CHAIN_DIR / "schemas"

_CYCLONEDX_SCHEMA_PATH = SCHEMAS_DIR / "cyclonedx-bom-1.6.schema.json"
_SPDX_SCHEMA_PATH = SCHEMAS_DIR / "spdx-2.3.schema.json"


class SbomParseError(Exception):
    """Raised when a file that looks like it might be an SBOM (by
    extension) cannot even be parsed as JSON — fail loud rather than
    silently treating it as "not an SBOM, nothing to check"."""


def detect_sbom_format(doc: dict) -> str | None:
    """Returns "CycloneDX", "SPDX", or None (not recognized as either)
    based on the document's own self-declared format fields — never
    guessed from the filename alone."""
    if not isinstance(doc, dict):
        return None
    if doc.get("bomFormat") == "CycloneDX":
        return "CycloneDX"
    if "spdxVersion" in doc:
        return "SPDX"
    return None


def _load_schema(sbom_format: str) -> dict:
    path = _CYCLONEDX_SCHEMA_PATH if sbom_format == "CycloneDX" else _SPDX_SCHEMA_PATH
    return json.loads(path.read_text(encoding="utf-8"))


def validate_sbom_content(doc: dict, sbom_format: str) -> list[str]:
    """Validates `doc` against the real, vendored CycloneDX/SPDX JSON
    Schema matching `sbom_format`, returning formatted error strings
    (empty list if valid)."""
    schema = _load_schema(sbom_format)
    from jsonschema.validators import validator_for

    validator_cls = validator_for(schema)
    validator_cls.check_schema(schema)
    validator = validator_cls(schema, format_checker=FormatChecker())
    return [f"{'/'.join(str(p) for p in e.path)}: {e.message}" for e in validator.iter_errors(doc)]


def load_json_file(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as e:
        raise SbomParseError(f"{path}: not valid JSON: {e}") from e
    if not isinstance(doc, dict):
        raise SbomParseError(f"{path}: top-level document is not a mapping (got {type(doc).__name__})")
    return doc
