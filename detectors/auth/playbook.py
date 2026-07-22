"""AuthN/AuthZ code-review playbook.

Loads and validates checklist.json, renders it as guidance text for the
invoking AI agent, and helps validate any finding that agent produces
against the real finding.schema.json.

Unlike detectors/secret (006) and the planned detectors/code-review
(007), this sub-skill has no deterministic scanner for most of
cpmatch's stack — see plans/023-authn-authz-code-review-skill.md in the
security-skill-workspace repo. The invoking agent reads the rendered
playbook and reasons over the code directly; a Semgrep-subset detector
for the languages/frameworks with real registry coverage is deferred
until 007 is implemented and its Semgrep-invocation core exists to
reuse (see the plan's sequencing note) — this module is the playbook
half only.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from validate import validate_checklist

_common_dir = next(p for p in Path(__file__).resolve().parents if (p / "common").is_dir()) / "common"
sys.path.insert(0, str(_common_dir))
from schema_validation import validate_against_schema  # noqa: E402
from streams import reconfigure_streams  # noqa: E402

AUTH_DIR = Path(__file__).parent
FINDING_SCHEMA_PATH = _common_dir.parent / "schema" / "finding.schema.json"


class PlaybookError(Exception):
    """Raised for an invalid checklist config — fail loud rather than
    silently handing the agent a malformed playbook."""


def load_checklist(checklist_path: Path | None = None) -> dict:
    """Loads and validates a checklist file — defaults to this
    directory's own checklist.json, but accepts an explicit path so
    tests can exercise the invalid-checklist error path without
    touching the real file (same dependency-injection shape as
    policy/engine.py's load_repo_policy(repo_root))."""
    path = checklist_path if checklist_path is not None else AUTH_DIR / "checklist.json"
    checklist = json.loads(path.read_text(encoding="utf-8"))
    errors = validate_checklist(checklist)
    if errors:
        raise PlaybookError(f"{path} is not a valid checklist: {'; '.join(errors)}")
    return checklist


def render_playbook(checklist: dict, language: str | None = None) -> str:
    """Renders the checklist as guidance text for the invoking AI agent.

    If `language` is given, each item's language-specific note (if any)
    is appended after its generic guidance. The generic guidance is
    never filtered out by language — it applies regardless of stack,
    per the kickoff's "hybrid, not an even split" design (the playbook
    is the primary mechanism for languages with no Semgrep coverage,
    not just a supplement)."""
    lines = []
    for item in checklist["items"]:
        lines.append(f"## {item['ruleId']} — {item['title']}")
        lines.append(f"Weakness class: {item['weaknessClass']}")
        lines.append(f"Guidance: {item['guidance']}")
        lines.append(f"Evidence required before reporting: {item['evidenceRequirement']}")
        if language is not None:
            note = item.get("languageNotes", {}).get(language)
            if note:
                lines.append(f"{language}-specific: {note}")
        refs = ", ".join(f"{r['standard']} {r['id']}" for r in item["references"])
        lines.append(f"References: {refs}")
        lines.append(
            f"Suggested severity: {item['suggestedSeverity']} | "
            f"Max confidence unless corroborated further: {item['confidenceGuidance']['defaultMax']}"
        )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def checklist_item(checklist: dict, rule_id: str) -> dict:
    """Looks up one checklist item by ruleId. Raises PlaybookError
    instead of returning None on a miss — a caller asking for a ruleId
    that doesn't exist is a bug worth failing loudly on, not silently
    passing through."""
    for item in checklist["items"]:
        if item["ruleId"] == rule_id:
            return item
    raise PlaybookError(f"no checklist item with ruleId {rule_id!r}")


def validate_agent_finding(finding: dict) -> list[str]:
    """Validates a finding the invoking agent produced from this
    checklist against the real finding.schema.json — the same
    conformance check every deterministic detector's own output must
    pass (see detectors/secret/test_scanner.py's
    SchemaConformanceTests), applied here to agent-authored findings."""
    schema = json.loads(FINDING_SCHEMA_PATH.read_text(encoding="utf-8"))
    return validate_against_schema(schema, finding)


def main(argv: list[str] | None = None) -> int:
    """Holds the CLI's parse/render/print/error logic separately from
    the __main__ guard, so tests can call it with canned argv instead
    of shelling out to a real subprocess."""
    import argparse

    parser = argparse.ArgumentParser(description="Render the AuthN/AuthZ code-review playbook.")
    parser.add_argument("--language", default=None, help="Include this language's notes alongside generic guidance")
    args = parser.parse_args(argv)

    try:
        checklist = load_checklist()
    except PlaybookError as e:
        print(f"PLAYBOOK ERROR: {e}", file=sys.stderr)
        return 1

    print(render_playbook(checklist, args.language), end="")
    return 0


if __name__ == "__main__":
    # Reconfigured here, not inside main(), so tests that redirect
    # stdout/stderr to an io.StringIO (which has no .reconfigure()) can
    # still call main() directly. See plans/022-cross-platform-compatibility.md
    # and common/streams.py.
    reconfigure_streams()
    sys.exit(main())
