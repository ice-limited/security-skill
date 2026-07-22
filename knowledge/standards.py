"""Lookup layer over the vendored standards knowledge base.

Backs the `standard`/`id` values in a Finding's `references[]`
(schema/finding.schema.json). Source-of-truth model decided at the plan
002 kickoff (2026-07-22): lightweight `id -> {title, url}` per standard,
not full vendored guideline text. See
plans/002-knowledge-base-standards-mapping.md in the
security-skill-workspace repo for design rationale.
"""

from __future__ import annotations

import json
from pathlib import Path

KNOWLEDGE_DIR = Path(__file__).parent

# Maps the `standard` enum value (finding.schema.json) to its data file
# and, where the standard's own ID scheme makes it possible, a URL
# template that avoids repeating an identical URL pattern in every entry.
_STANDARD_FILES = {
    "OWASP-Top10": ("owasp-top10.json", None),
    "OWASP-ASVS": ("owasp-asvs.json", None),
    "OWASP-API-Top10": ("owasp-api-top10.json", None),
    "CWE": ("cwe.json", "https://cwe.mitre.org/data/definitions/{num}.html"),
    "CAPEC": ("capec.json", "https://capec.mitre.org/data/definitions/{num}.html"),
    "MITRE-ATTACK": ("mitre-attack.json", None),
    "NIST-SSDF": ("nist-ssdf.json", None),
    "CERT-Secure-Coding": ("cert-secure-coding.json", None),
}

_cache: dict[str, dict[str, dict]] = {}


class UnknownStandardError(KeyError):
    pass


def known_standards() -> list[str]:
    return list(_STANDARD_FILES)


def _numeric_suffix(standard_id: str) -> str:
    # "CWE-89" -> "89", "CAPEC-664" -> "664"
    return standard_id.rsplit("-", 1)[-1]


def load(standard: str) -> dict[str, dict]:
    """Load (and cache) the entries for one standard. Metadata keys
    (leading underscore, e.g. "_note") are excluded from the returned
    entries."""
    if standard not in _STANDARD_FILES:
        raise UnknownStandardError(standard)
    if standard not in _cache:
        filename, _ = _STANDARD_FILES[standard]
        raw = json.loads((KNOWLEDGE_DIR / filename).read_text())
        _cache[standard] = {k: v for k, v in raw.items() if not k.startswith("_")}
    return _cache[standard]


def exists(standard: str, standard_id: str) -> bool:
    return standard_id in load(standard)


def get(standard: str, standard_id: str) -> dict | None:
    return load(standard).get(standard_id)


def title(standard: str, standard_id: str) -> str | None:
    entry = get(standard, standard_id)
    return entry["title"] if entry else None


def url(standard: str, standard_id: str) -> str | None:
    entry = get(standard, standard_id)
    if entry is None:
        return None
    if "url" in entry:
        return entry["url"]
    _, template = _STANDARD_FILES[standard]
    if template:
        return template.format(num=_numeric_suffix(standard_id))
    return None
