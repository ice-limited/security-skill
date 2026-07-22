"""Spec-aware code cross-reference: renders guidance for the invoking
AI agent to verify that every operation the OpenAPI spec declares as
secured (spec_analysis.py's deterministic extraction) actually has a
matching auth check in the implementation's route handler.

Deliberately a single playbook item, not a JSON+schema checklist
infrastructure like detectors/auth's (023) — that shape earns its
weight across 023's ~6 items with per-language notes; duplicating it
for exactly one item here would be process ceremony without a second
real consumer, so this stays a plain Python constant. If this
cross-reference mechanism grows a second item, revisit extracting a
shared checklist schema to common/ then (plan 005's "share once a
second consumer exists" precedent) — not preemptively now.

Scoped to spec-aware cross-reference ONLY, per the plan 012 kickoff's
decision to avoid duplicating 023's existing generic JWT-bypass/
mass-assignment detection (see meetings/2026-07-22-2200-plan-012-kickoff.md):
this item fires only on the specific mismatch "spec declares this
operation secured, but no matching auth check was found in the code" —
never on a generic JWT/authorization pattern 023 already owns.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from spec_analysis import Operation

_common_dir = next(p for p in Path(__file__).resolve().parents if (p / "common").is_dir()) / "common"
sys.path.insert(0, str(_common_dir))
from schema_validation import validate_against_schema  # noqa: E402
from streams import reconfigure_streams  # noqa: E402

API_DIR = Path(__file__).parent
FINDING_SCHEMA_PATH = _common_dir.parent / "schema" / "finding.schema.json"

RULE_ID = "api.spec-declared-auth-missing-in-code"
DETECTOR_NAME = "api-crossref-playbook"

REFERENCES = [{"standard": "CWE", "id": "CWE-862"}, {"standard": "OWASP-API-Top10", "id": "API2:2023"}]
SUGGESTED_SEVERITY = "High"
CONFIDENCE_DEFAULT_MAX = 65

GUIDANCE = (
    "Each operation below is declared by the OpenAPI spec as requiring at least one security scheme. "
    "For each one, locate the route handler in the implementation that serves that path/method and "
    "confirm it actually enforces authentication/authorization before performing the operation — a "
    "session check, token verification, or an equivalent framework-level default-deny middleware "
    "covering this route. Do not rely on the spec alone: the spec states intent, this check is about "
    "whether the code honors it."
)

EVIDENCE_REQUIREMENT = (
    "Cite the specific handler/function and confirm, by tracing its actual call path (decorators, "
    "middleware chain, framework routing config), that no authentication/authorization mechanism "
    "runs before it — not just that none is visible in the immediate handler body. A framework-level "
    "default-deny (e.g. global auth middleware applied to all routes) means this is NOT a finding "
    "even if the handler itself has no local check. If no matching route handler can be found at "
    "all for this path/method, do not report a finding — that is a spec/implementation drift issue "
    "outside this check's scope, not a missing-auth finding."
)


def render_guidance(operations: list[Operation], spec_file: str) -> str:
    """Renders the deterministically-extracted secured operations as
    playbook guidance text for the invoking agent. Returns an
    explanatory "nothing to check" message (not an empty string) when
    the spec declares no secured operations, so the agent doesn't
    mistake silence for an unrendered playbook."""
    if not operations:
        return f"No operations in {spec_file} are declared as requiring a security scheme — nothing to cross-reference.\n"

    lines = [
        f"## {RULE_ID} — spec-declared-secured operations to verify against the implementation",
        f"Guidance: {GUIDANCE}",
        f"Evidence required before reporting: {EVIDENCE_REQUIREMENT}",
        f"References: {', '.join(f'{r['standard']} {r['id']}' for r in REFERENCES)}",
        f"Suggested severity: {SUGGESTED_SEVERITY} | Max confidence unless corroborated further: {CONFIDENCE_DEFAULT_MAX}",
        "",
        f"Operations declared secured in {spec_file}:",
    ]
    for op in operations:
        schemes = ", ".join(op.security_schemes)
        lines.append(f"- {op.method.upper()} {op.path} ({spec_file}:{op.line}) — requires: {schemes}")
    return "\n".join(lines) + "\n"


def build_finding(
    operation: Operation,
    spec_file: str,
    code_file: str,
    code_start_line: int,
    code_end_line: int | None = None,
    confidence: int = CONFIDENCE_DEFAULT_MAX,
) -> dict:
    """Builds a finding.schema.json-conformant dict for a confirmed
    violation (spec declares `operation` secured, no matching auth
    check found at code_file:code_start_line). Used by tests to verify
    schema conformance, and available for the invoking agent to call
    directly instead of hand-assembling the dict itself."""
    end_line = code_end_line if code_end_line is not None else code_start_line
    schemes = ", ".join(operation.security_schemes)
    key = f"{RULE_ID}|{code_file}|{code_start_line}|{end_line}|{spec_file}|{operation.method}|{operation.path}"
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]

    return {
        "findingId": f"api-{digest}",
        "ruleId": RULE_ID,
        "subSkill": "api",
        "artifactType": "source-code",
        "title": "Endpoint declared secured in the OpenAPI spec has no matching auth check in code",
        "problem": (
            f"{spec_file}:{operation.line} declares {operation.method.upper()} {operation.path} as requiring "
            f"a security scheme ({schemes}), but no matching authentication/authorization check was found in "
            f"the route handler at {code_file}:{code_start_line}."
        ),
        "impact": (
            "Any caller can reach this operation without satisfying the security requirement the API's own "
            "contract declares, contradicting the spec's documented intent and likely exposing the operation "
            "to unauthorized use."
        ),
        "recommendation": (
            "Add the enforcement the spec already declares (session/token verification, or an equivalent "
            "framework-level auth middleware covering this route) to the handler."
        ),
        "references": REFERENCES,
        "severity": SUGGESTED_SEVERITY,
        "confidence": confidence,
        "location": {"file": code_file, "startLine": code_start_line, "endLine": end_line},
        "detectorSource": {"name": DETECTOR_NAME, "version": "1.0.0"},
        "suppressed": False,
        "metadata": {
            "specFile": spec_file,
            "specLine": operation.line,
            "specPath": operation.path,
            "specMethod": operation.method,
            "requiredSecuritySchemes": list(operation.security_schemes),
        },
    }


def validate_finding(finding: dict) -> list[str]:
    """Validates an agent-produced finding against the real
    finding.schema.json — same conformance bar every deterministic
    detector's own output must pass (mirrors detectors/auth/playbook.py's
    validate_agent_finding)."""
    schema = json.loads(FINDING_SCHEMA_PATH.read_text(encoding="utf-8"))
    return validate_against_schema(schema, finding)


def main(argv: list[str] | None = None) -> int:
    import argparse

    from spec_analysis import SpecParseError, load_and_extract, secured_operations

    parser = argparse.ArgumentParser(
        description="Render spec-aware auth cross-reference guidance for the invoking agent, from an OpenAPI spec."
    )
    parser.add_argument("spec_path", type=Path)
    args = parser.parse_args(argv)

    try:
        operations = secured_operations(load_and_extract(args.spec_path))
    except SpecParseError as e:
        print(f"SPEC PARSE ERROR: {e}", file=sys.stderr)
        return 1

    print(render_guidance(operations, str(args.spec_path)), end="")
    return 0


if __name__ == "__main__":
    reconfigure_streams()
    sys.exit(main())
