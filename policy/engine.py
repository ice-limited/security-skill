"""Policy engine: severity -> action decision logic.

Deliberately separate from any real CI wiring (plan 016) — this module
is a pure function over findings + a policy config, testable with
synthetic data and no pipeline. See plans/003-policy-engine.md in the
security-skill-workspace repo for design rationale.

Does not implement suppression/exceptions itself (plan 004's job) — it
only respects the `suppressed` flag finding.schema.json already puts on
every finding.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from validate import validate_policy

POLICY_DIR = Path(__file__).parent

# Strictest first. A policy's `actions` values must all be members of
# this list — see ConsistencyTests in test_engine.py, which guards
# against this drifting from policy.schema.json's action enum.
ACTION_ORDER = ["block-merge", "require-review", "create-ticket", "notify", "none"]

# Must match finding.schema.json's severity enum (schema/finding.schema.json)
# and policy.schema.json's required `actions` keys — also guarded by a
# consistency test.
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


class PolicyError(Exception):
    """Raised for an invalid policy config — fail loud rather than
    silently falling back to a default when a repo's override is
    malformed."""


def load_default_policy() -> dict:
    return json.loads((POLICY_DIR / "default-policy.json").read_text(encoding="utf-8"))


def load_repo_policy(repo_root: Path) -> dict | None:
    """Returns the repo's `.security-skill/policy.json` if present, else
    None. Does NOT fall back to the default on an invalid file — raises
    instead, since a present-but-broken override is a configuration bug
    that should be fixed, not silently ignored."""
    override_path = Path(repo_root) / ".security-skill" / "policy.json"
    if not override_path.exists():
        return None
    try:
        policy = json.loads(override_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise PolicyError(f"{override_path} is not valid JSON: {e}") from e
    errors = validate_policy(policy)
    if errors:
        raise PolicyError(f"{override_path} is not a valid policy: {'; '.join(errors)}")
    return policy


def resolve_policy(repo_root: Path | str | None = None) -> dict:
    """Central default, wholesale-replaced by a repo's
    `.security-skill/policy.json` if present. Not a deep merge — a repo
    override must be a complete, valid policy on its own (enforced by
    policy.schema.json requiring all 5 severities), so there's no
    partial-override case to reconcile."""
    if repo_root is not None:
        repo_policy = load_repo_policy(Path(repo_root))
        if repo_policy is not None:
            return repo_policy
    return load_default_policy()


def _action_rank(action: str) -> int:
    return ACTION_ORDER.index(action)


def evaluate(findings: list[dict], policy: dict) -> dict:
    """Returns {"perFinding": [...], "aggregateAction": str}.

    Suppressed findings are skipped entirely — they never appear in
    perFinding and never influence aggregateAction, per 001's schema
    (a suppressed finding must not trigger any policy action)."""
    per_finding = []
    for finding in findings:
        if finding.get("suppressed"):
            continue
        action = policy["actions"][finding["severity"]]
        per_finding.append(
            {"findingId": finding["findingId"], "severity": finding["severity"], "action": action}
        )

    if per_finding:
        aggregate_action = min((d["action"] for d in per_finding), key=_action_rank)
    else:
        aggregate_action = "none"

    return {"perFinding": per_finding, "aggregateAction": aggregate_action}


def evaluate_report(report: dict, policy: dict) -> dict:
    """Convenience wrapper: evaluate() over a full ScanReport
    (scan-report.schema.json) instead of a bare findings list."""
    return evaluate(report.get("findings", []), policy)


def main(argv: list[str] | None = None) -> int:
    """Holds the CLI's parse/evaluate/print/error logic separately from
    the __main__ guard, so tests can call it with canned argv and a
    fake filesystem instead of shelling out to a real subprocess."""
    import argparse

    parser = argparse.ArgumentParser(description="Evaluate a ScanReport against policy.")
    parser.add_argument("report", type=Path, help="Path to a scan-report.json")
    parser.add_argument("--repo-root", type=Path, default=None, help="Repo root to look for .security-skill/policy.json in")
    args = parser.parse_args(argv)

    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
        policy = resolve_policy(args.repo_root)
        result = evaluate_report(report, policy)
    except PolicyError as e:
        print(f"POLICY ERROR: {e}", file=sys.stderr)
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
