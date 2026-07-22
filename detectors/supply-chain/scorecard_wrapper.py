"""OpenSSF Scorecard wrapper, curated to exactly 2 checks:
`Binary-Artifacts` and `SAST`. See plans/014-supply-chain-skill.md and
meetings/2026-07-22-2350-plan-014-kickoff.md in the
security-skill-workspace repo for why these two and not Scorecard's
other checks:

- `Pinned-Dependencies`, `Dangerous-Workflow`, `Token-Permissions`
  excluded — verified at kickoff they overlap 009's
  `docker.unpinned-base-image` and 013's own
  `cicd-pipeline.unpinned-external-reference`/generic script-injection/
  permissions scope directly.
- `Signed-Releases` excluded — verified incompatible with `--local`
  mode outright (`Unsupported RequestType` — needs the GitHub Releases
  API, which doesn't exist for a local checkout).

Static/local-mode only (`scorecard --local <path>`, no GitHub token) —
matches this plan's own kickoff decision against live/network-dependent
checks.

**Known real limitation, not silently papered over**: Scorecard's
`--local` mode walks the actual filesystem (not just git-tracked
content — verified it still reports `.gitignore`d `__pycache__/*.pyc`
files as "binaries", and even `--file-mode git` doesn't change this for
local scans) and can **crash outright** scanning a directory containing
certain symlinks (verified: a macOS Python virtualenv's `.venv/bin/`
symlink triggers `"path escapes from parent"`, an internal Scorecard
bug, not a target-repo problem). This wrapper surfaces that as a clear
`ScannerError` rather than silently returning no findings — callers
should point it at a real target repo checkout, not a directory
containing a Python virtualenv or similar symlink-heavy tooling
directory.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import rules

_common_dir = next(p for p in Path(__file__).resolve().parents if (p / "common").is_dir()) / "common"
sys.path.insert(0, str(_common_dir))
from streams import reconfigure_streams  # noqa: E402

DETECTOR_NAME = "supply-chain-scorecard-wrapper"

CHECKS = ("Binary-Artifacts", "SAST")

_RULE_BY_CHECK_NAME = {
    "Binary-Artifacts": rules.BINARY_ARTIFACT_COMMITTED,
    "SAST": rules.MISSING_SAST_TOOL,
}

_MAX_SCORE = 10


class ScannerError(Exception):
    """Raised for a real invocation failure (scorecard missing, a
    genuine per-check internal error such as the known symlink crash
    above) — fail loud rather than silently returning an empty findings
    list, which would look identical to "scanned cleanly, no issues
    found"."""


def _check_scorecard_available() -> None:
    if shutil.which("scorecard") is None:
        raise ScannerError(
            "scorecard CLI not found on PATH. Install with 'brew install scorecard' "
            "(or see https://github.com/ossf/scorecard#installation) — see plans/014-supply-chain-skill.md."
        )


def run_scorecard(path: str) -> list[dict]:
    """Invokes the real scorecard CLI in `--local` mode against exactly
    one path and returns its parsed `checks` list."""
    _check_scorecard_available()
    if not Path(path).exists():
        raise ScannerError(f"path does not exist: {path}")

    cmd = ["scorecard", "--local", str(path), "--checks", ",".join(CHECKS), "--format", "json"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    except FileNotFoundError as e:  # pragma: no cover - _check_scorecard_available covers the common case
        raise ScannerError(f"failed to execute scorecard: {e}") from e

    try:
        parsed = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise ScannerError(f"scorecard did not return valid JSON: {e}; stderr: {proc.stderr.strip()[-2000:]}") from e

    checks = parsed.get("checks") or []
    for check in checks:
        if check.get("score", -1) < 0:
            raise ScannerError(
                f"scorecard check {check.get('name')!r} failed internally: {check.get('reason')} — "
                "if this mentions a symlinked path (e.g. a Python virtualenv's bin/ directory), "
                "exclude that directory from the scanned path; see this module's own docstring."
            )
    return checks


def _finding_id(rule_id: str, file: str, discriminator: str) -> str:
    key = f"{rule_id}|{file}|{discriminator}"
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
    return f"supply-chain-{digest}"


def _build_finding(check: dict, file: str) -> dict | None:
    name = check.get("name")
    template = _RULE_BY_CHECK_NAME.get(name)
    if template is None:
        return None
    score = check.get("score", _MAX_SCORE)
    if score >= _MAX_SCORE:
        return None

    reason = check.get("reason", "")
    details = check.get("details") or []
    problem = template["problem"].format(detail=reason) if "{detail}" in template["problem"] else template["problem"]

    return {
        "findingId": _finding_id(template["rule_id"], file, name),
        "ruleId": template["rule_id"],
        "subSkill": "supply-chain",
        "artifactType": "config",
        "title": template["title"],
        "problem": problem,
        "impact": template["impact"],
        "recommendation": template["recommendation"],
        "references": template["references"],
        "severity": template["severity"],
        "confidence": template["confidence"],
        "location": {"file": file, "startLine": 1, "endLine": 1},
        "detectorSource": {"name": DETECTOR_NAME, "version": "1.0.0"},
        "suppressed": False,
        "metadata": {"scorecardScore": score, "scorecardReason": reason, "scorecardDetails": details[:20]},
    }


def scan_paths(paths: list[str]) -> list[dict]:
    """Scans one or more local repo directories via Scorecard's
    `Binary-Artifacts` and `SAST` checks."""
    findings: list[dict] = []
    for path in paths:
        for check in run_scorecard(path):
            finding = _build_finding(check, path)
            if finding is not None:
                findings.append(finding)
    return findings


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Scan a local repo checkout for committed binaries / missing SAST tooling via OpenSSF Scorecard.")
    parser.add_argument("paths", nargs="+")
    args = parser.parse_args(argv)

    try:
        findings = scan_paths(args.paths)
    except ScannerError as e:
        print(f"SCANNER ERROR: {e}", file=sys.stderr)
        return 1

    print(json.dumps(findings, indent=2))
    return 0


if __name__ == "__main__":
    reconfigure_streams()
    sys.exit(main())
