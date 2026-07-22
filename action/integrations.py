"""Action Layer: turns a Policy Engine verdict (policy/engine.py's
evaluate()/evaluate_report(), over a ScanReport per finding.schema.json)
into an Integration record (schema/integration.schema.json) — a gate
verdict for CI, a ticket payload per `create-ticket` finding, and a
notification payload per `notify` finding.

**Pure data generator, by design — decided at this plan's own
kickoff**: this module never performs network I/O (no webhook POST,
no ticketing/chat API call) and never runs `git`/`gh`. Which
ticketing/chat system cpmatch actually uses is still unspecified, so
every payload here is deliberately vendor-agnostic (generic-webhook
shaped) rather than committing to a specific vendor's field names —
delivering a payload to a real webhook is a future plan's job once a
real target system is chosen. See
plans/016-action-layer-integrations-gate.md and
meetings/2026-07-23-1100-plan-016-kickoff.md in the
security-skill-workspace repo.

**No cascading actions.** policy/engine.py's `evaluate()` assigns
exactly one action per finding (`block-merge`/`require-review`/
`create-ticket`/`notify`/`none`). This module follows that literally:
`create-ticket` findings get a ticket record, `notify` findings get a
notification record, `block-merge`/`require-review`/`none` findings
are folded into the gate verdict only (no separate ticket/notification
record). Inventing a cascading interpretation (e.g. a `block-merge`
finding *also* producing a notification) would silently reinterpret
already-`done` policy-engine behavior rather than extend it — flagged
at kickoff as a real question for a future revision, not decided here.

**Layering contract**: `build_integrations()` takes an
already-computed policy verdict, not a policy config — it never
imports policy/engine.py itself. Only the CLI (`main()`) crosses that
directory boundary, to actually compute the verdict before handing it
to `build_integrations()`. This mirrors CONTEXT.md's layered
architecture: each layer consumes the previous layer's *output*, not
its code.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ACTION_DIR = Path(__file__).parent

_common_dir = next(p for p in ACTION_DIR.resolve().parents if (p / "common").is_dir()) / "common"
sys.path.insert(0, str(_common_dir))
from streams import reconfigure_streams  # noqa: E402

DETECTOR_NAME = "action-integrations-builder"

_TICKET_ACTION = "create-ticket"
_NOTIFY_ACTION = "notify"


class IntegrationError(Exception):
    """Raised when a verdict references a findingId not present in the
    given report — fail loud rather than silently producing a ticket or
    notification with missing finding content."""


def _gate_verdict(verdict: dict) -> dict:
    aggregate_action = verdict["aggregateAction"]
    count = len(verdict["perFinding"])
    if count == 0:
        summary = "none: no actionable findings."
    else:
        summary = f"{aggregate_action}: {count} finding(s) evaluated, strictest required action is '{aggregate_action}'."
    return {
        "kind": "gate-verdict",
        "aggregateAction": aggregate_action,
        "shouldBlockMerge": aggregate_action == "block-merge",
        "findingCount": count,
        "summary": summary,
    }


def _references_markdown(finding: dict) -> str:
    lines = []
    for ref in finding["references"]:
        line = f"- {ref['standard']} {ref['id']}"
        if ref.get("url"):
            line += f" — {ref['url']}"
        lines.append(line)
    return "\n".join(lines)


def _ticket(finding: dict) -> dict:
    description = (
        f"{finding['problem']}\n\n"
        f"**Impact:** {finding['impact']}\n\n"
        f"**Recommendation:** {finding['recommendation']}\n\n"
        f"**References:**\n{_references_markdown(finding)}\n\n"
        f"**Location:** `{finding['location']['file']}:{finding['location']['startLine']}`"
    )
    labels = sorted({"security", finding["subSkill"], f"severity:{finding['severity'].lower()}"})
    return {
        "kind": "ticket",
        "findingId": finding["findingId"],
        "title": finding["title"],
        "description": description,
        "severity": finding["severity"],
        "labels": labels,
    }


def _notification(finding: dict) -> dict:
    text = f"[{finding['severity']}] {finding['title']} ({finding['location']['file']}:{finding['location']['startLine']})"
    return {
        "kind": "notification",
        "findingId": finding["findingId"],
        "text": text,
        "severity": finding["severity"],
    }


def build_integrations(report: dict, verdict: dict) -> list[dict]:
    """Builds one gate-verdict record for the whole report, plus one
    ticket/notification record per finding whose policy `action` is
    `create-ticket`/`notify` respectively.

    `verdict` must be policy/engine.py's `evaluate()`/`evaluate_report()`
    output shape: `{"perFinding": [{"findingId", "severity", "action"}, ...],
    "aggregateAction": str}`. `report` must be the same ScanReport
    (scan-report.schema.json) the verdict was computed over."""
    findings_by_id = {f["findingId"]: f for f in report.get("findings", [])}

    records = [_gate_verdict(verdict)]

    for entry in verdict["perFinding"]:
        finding = findings_by_id.get(entry["findingId"])
        if finding is None:
            raise IntegrationError(
                f"verdict references findingId {entry['findingId']!r} not present in the given report"
            )
        if entry["action"] == _TICKET_ACTION:
            records.append(_ticket(finding))
        elif entry["action"] == _NOTIFY_ACTION:
            records.append(_notification(finding))
        # block-merge / require-review / none: folded into the gate
        # verdict only, per the no-cascading decision above.

    return records


def _load_policy_engine():
    """Cross-directory import of policy/engine.py — isolated to this one
    function, called only from main(). build_integrations() itself
    never imports policy/engine.py (see module docstring's layering
    contract). Inserting policy/ at the front of sys.path makes
    engine.py's own `from validate import validate_policy` resolve to
    policy/validate.py rather than this directory's own validate.py —
    safe here because nothing else in this module's import chain claims
    the name "validate" for anything else."""
    policy_dir = next(p for p in ACTION_DIR.resolve().parents if (p / "policy").is_dir()) / "policy"
    if str(policy_dir) not in sys.path:
        sys.path.insert(0, str(policy_dir))
    import engine as policy_engine

    return policy_engine


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Build gate-verdict/ticket/notification records from a ScanReport, evaluated against policy. "
        "Exits non-zero iff the policy verdict blocks the merge."
    )
    parser.add_argument("report", type=Path, help="Path to a scan-report.json")
    parser.add_argument("--repo-root", type=Path, default=None, help="Repo root to look for .security-skill/policy.json in")
    args = parser.parse_args(argv)

    policy_engine = _load_policy_engine()

    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
        policy = policy_engine.resolve_policy(args.repo_root)
        verdict = policy_engine.evaluate_report(report, policy)
        records = build_integrations(report, verdict)
    except (IntegrationError, policy_engine.PolicyError, OSError, json.JSONDecodeError) as e:
        print(f"INTEGRATION ERROR: {e}", file=sys.stderr)
        return 1

    print(json.dumps(records, indent=2))
    return 1 if records[0]["shouldBlockMerge"] else 0


if __name__ == "__main__":
    reconfigure_streams()
    sys.exit(main())
