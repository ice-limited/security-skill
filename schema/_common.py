"""Shared helpers for the finding/scan-report renderers.

Kept dependency-free (stdlib only) — the renderers themselves don't need
jsonschema; that's only used by validate.py for conformance testing.
"""

from __future__ import annotations

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


def group_by_severity(findings: list[dict]) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = {s: [] for s in SEVERITY_ORDER}
    for finding in findings:
        groups[finding["severity"]].append(finding)
    return groups


def format_references(finding: dict) -> str:
    parts = []
    for ref in finding["references"]:
        label = f"{ref['standard']} {ref['id']}"
        if ref.get("url"):
            parts.append(f"[{label}]({ref['url']})")
        else:
            parts.append(label)
    return ", ".join(parts)


def format_location(finding: dict) -> str:
    loc = finding["location"]
    if loc["startLine"] == loc["endLine"]:
        return f"{loc['file']}:{loc['startLine']}"
    return f"{loc['file']}:{loc['startLine']}-{loc['endLine']}"
