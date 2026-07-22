"""CI/CD pipeline playbook.

Loads and validates checklist.json, renders it as guidance text for the
invoking AI agent, and helps validate any finding that agent produces
against the real finding.schema.json.

Covers what rules.py's deterministic Checkov wrapper doesn't reach:
unpinned external references, excessive pipeline permissions beyond
the one deterministic write-all case, broader script-injection
patterns, and broader secrets-in-logs patterns — across all three
formats in scope (GitHub Actions, GitLab CI, Jenkinsfile). Jenkinsfile
has no deterministic tool coverage at all (verified at this plan's
kickoff — no Checkov framework, no Semgrep pack), so this playbook is
its only mechanism, the same situation 023 (detectors/auth) already
established for languages Semgrep's registry doesn't reach. See
plans/013-cicd-pipeline-skill.md in the security-skill-workspace repo.
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

CICD_DIR = Path(__file__).parent
FINDING_SCHEMA_PATH = _common_dir.parent / "schema" / "finding.schema.json"


class PlaybookError(Exception):
    """Raised for an invalid checklist config — fail loud rather than
    silently handing the agent a malformed playbook."""


def load_checklist(checklist_path: Path | None = None) -> dict:
    """Loads and validates a checklist file — defaults to this
    directory's own checklist.json, but accepts an explicit path so
    tests can exercise the invalid-checklist error path without
    touching the real file."""
    path = checklist_path if checklist_path is not None else CICD_DIR / "checklist.json"
    checklist = json.loads(path.read_text(encoding="utf-8"))
    errors = validate_checklist(checklist)
    if errors:
        raise PlaybookError(f"{path} is not a valid checklist: {'; '.join(errors)}")
    return checklist


def render_playbook(checklist: dict, pipeline_format: str | None = None) -> str:
    """Renders the checklist as guidance text for the invoking AI agent.

    If `pipeline_format` is given (one of "github-actions"/"gitlab-ci"/
    "jenkinsfile"), each item's format-specific note (if any) is
    appended after its generic guidance. The generic guidance is never
    filtered out by format — it applies regardless of which pipeline
    format is being reviewed, same "hybrid, not an even split" design
    023 established for its own languageNotes."""
    lines = []
    for item in checklist["items"]:
        lines.append(f"## {item['ruleId']} — {item['title']}")
        lines.append(f"Weakness class: {item['weaknessClass']}")
        lines.append(f"Guidance: {item['guidance']}")
        lines.append(f"Evidence required before reporting: {item['evidenceRequirement']}")
        if pipeline_format is not None:
            note = item.get("formatNotes", {}).get(pipeline_format)
            if note:
                lines.append(f"{pipeline_format}-specific: {note}")
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
    pass, applied here to agent-authored findings."""
    schema = json.loads(FINDING_SCHEMA_PATH.read_text(encoding="utf-8"))
    return validate_against_schema(schema, finding)


def main(argv: list[str] | None = None) -> int:
    """Holds the CLI's parse/render/print/error logic separately from
    the __main__ guard, so tests can call it with canned argv instead
    of shelling out to a real subprocess."""
    import argparse

    parser = argparse.ArgumentParser(description="Render the CI/CD pipeline playbook.")
    parser.add_argument(
        "--format",
        dest="pipeline_format",
        default=None,
        choices=["github-actions", "gitlab-ci", "jenkinsfile"],
        help="Include this pipeline format's notes alongside generic guidance",
    )
    args = parser.parse_args(argv)

    try:
        checklist = load_checklist()
    except PlaybookError as e:
        print(f"PLAYBOOK ERROR: {e}", file=sys.stderr)
        return 1

    print(render_playbook(checklist, args.pipeline_format), end="")
    return 0


if __name__ == "__main__":
    # Reconfigured here, not inside main(), so tests that redirect
    # stdout/stderr to an io.StringIO (which has no .reconfigure()) can
    # still call main() directly. See plans/022-cross-platform-compatibility.md
    # and common/streams.py.
    reconfigure_streams()
    sys.exit(main())
