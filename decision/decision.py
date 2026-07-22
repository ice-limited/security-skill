"""Decision layer: exact-duplicate dedup and exception-based suppression.

Sits between raw detector output (finding.schema.json) and the policy
engine (../policy/engine.py) — see plans/004-decision-layer-scoring.md
for design rationale. Confidence calibration is deliberately NOT
implemented yet (see calibrate_confidence()) — there's no detector
output yet to calibrate against.
"""

from __future__ import annotations

import json
import sys
from datetime import date
from pathlib import Path

from validate import validate_exceptions

DECISION_DIR = Path(__file__).parent


class DecisionError(Exception):
    """Raised for an invalid exceptions file — fail loud rather than
    silently ignoring a malformed override, same principle as plan 003's
    PolicyError."""


def load_exceptions(repo_root: Path | str | None) -> dict[str, dict]:
    """Returns {findingId: exception} read from
    repo_root/.security-skill/exceptions.json, or {} if repo_root is
    None or the file doesn't exist."""
    if repo_root is None:
        return {}
    path = Path(repo_root) / ".security-skill" / "exceptions.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise DecisionError(f"{path} is not valid JSON: {e}") from e
    errors = validate_exceptions(data)
    if errors:
        raise DecisionError(f"{path} is not a valid exceptions file: {'; '.join(errors)}")

    exceptions: dict[str, dict] = {}
    for exc in data["exceptions"]:
        finding_id = exc["findingId"]
        if finding_id in exceptions:
            # Fail loud rather than silently keeping whichever entry
            # happens to come last — two entries for the same finding
            # may carry conflicting reasons/expiry, which is a config
            # bug to fix, not to silently resolve.
            raise DecisionError(f"{path} has duplicate exceptions for findingId {finding_id!r}")
        exceptions[finding_id] = exc
    return exceptions


def _is_expired(exception: dict, today: date) -> bool:
    # "expiresAt: DATE" means valid through and including DATE (same
    # convention as a credit card's "valid thru" date) — expired
    # starting the day after, not on the date itself.
    expires_at = exception.get("expiresAt")
    if expires_at is None:
        return False
    return date.fromisoformat(expires_at) < today


def apply_exceptions(
    findings: list[dict], exceptions: dict[str, dict], today: date | None = None
) -> list[dict]:
    """Returns a new list of findings with `suppressed`/`suppressionReason`
    set for any finding whose findingId has a non-expired exception.
    Does not mutate the input findings. An expired exception leaves the
    finding active (not suppressed) — a lapsed "temporary" suppression
    must not silently keep suppressing forever."""
    today = today if today is not None else date.today()
    result = []
    for finding in findings:
        finding = dict(finding)
        exception = exceptions.get(finding["findingId"])
        if exception is not None and not _is_expired(exception, today):
            finding["suppressed"] = True
            finding["suppressionReason"] = exception["reason"]
        result.append(finding)
    return result


def dedup_findings(findings: list[dict]) -> list[dict]:
    """Collapses exact duplicates: same ruleId + same location. First
    occurrence wins; order otherwise preserved. Cross-detector fuzzy
    dedup is explicitly out of scope for v1 — see
    plans/004-decision-layer-scoring.md.

    "Same location" includes startByte/endByte when a detector provides
    them, not just file+startLine+endLine — two distinct findings from
    the same rule can legitimately share a line (e.g. two different
    hardcoded secrets on one line); collapsing on line range alone would
    silently drop one as a false "duplicate"."""
    seen: set[tuple] = set()
    result = []
    for finding in findings:
        loc = finding["location"]
        key = (
            finding["ruleId"],
            loc["file"],
            loc["startLine"],
            loc["endLine"],
            loc.get("startByte"),
            loc.get("endByte"),
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)
    return result


def calibrate_confidence(finding: dict) -> dict:
    """Plug-in point for future confidence calibration (plan 004's
    Design: "defines a single function boundary where a real calibration
    model could plug in later"). Currently an identity function — no
    calibration model exists yet because no detector has produced real
    true-positive/false-positive signal to calibrate one against."""
    return finding


def process(findings: list[dict], repo_root: Path | str | None = None) -> list[dict]:
    """The Decision Layer's main entry point: dedup, then apply
    exceptions, then (currently a no-op) confidence calibration."""
    findings = dedup_findings(findings)
    exceptions = load_exceptions(repo_root)
    findings = apply_exceptions(findings, exceptions)
    findings = [calibrate_confidence(f) for f in findings]
    return findings


def process_report(report: dict, repo_root: Path | str | None = None) -> dict:
    """Convenience wrapper: process() over a full ScanReport
    (scan-report.schema.json), returning a new report with `findings`
    replaced. Does not recompute `summary` — that's a rendering concern
    (see ../schema/render_*.py), not this layer's job."""
    report = dict(report)
    report["findings"] = process(report.get("findings", []), repo_root)
    return report


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Run the Decision Layer (dedup + exceptions) over a ScanReport."
    )
    parser.add_argument("report", type=Path, help="Path to a scan-report.json")
    parser.add_argument(
        "--repo-root", type=Path, default=None, help="Repo root to look for .security-skill/exceptions.json in"
    )
    args = parser.parse_args(argv)

    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
        result = process_report(report, args.repo_root)
    except DecisionError as e:
        print(f"DECISION ERROR: {e}", file=sys.stderr)
        return 1

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    # Reconfigured here, not inside main(), so tests that redirect
    # stdout/stderr to an io.StringIO (which has no .reconfigure()) can
    # still call main() directly. See plans/022-cross-platform-compatibility.md.
    sys.stdout.reconfigure(encoding="utf-8", newline="\n")
    sys.stderr.reconfigure(encoding="utf-8", newline="\n")
    sys.exit(main())
