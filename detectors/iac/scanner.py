"""IaC misconfiguration detection: curated IAM + public-exposure checks
across Terraform (AWS/Azure/GCP)/CloudFormation (AWS)/Ansible, via a
thin wrapper around the Checkov CLI (subprocess).

Decided at kickoff: wraps Checkov (github.com/bridgecrewio/checkov,
Apache-2.0), not Trivy (already wrapped for 009/010) — verified for
real that Trivy's AWS IAM-wildcard check is deprecated and doesn't
fire, GCP has no project-level IAM check at all, and Ansible has zero
shipped checks despite being a listed scanner mode. See
plans/011-iac-skill.md and
meetings/2026-07-22-2100-plan-011-kickoff.md in the
security-skill-workspace repo for the full empirical trail and every
tool-quirk finding referenced below.

Kept self-contained here rather than extracted to common/ — plan 005's
own precedent is to share a tool wrapper only once a *second* consumer
needs the same logic (exactly how common/semgrep_wrapper.py and
common/trivy_wrapper.py both started inline in a single detector).
No other planned sub-skill currently needs Checkov.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

from rules import CHECKOV_RULES, CheckovRule

_common_dir = next(p for p in Path(__file__).resolve().parents if (p / "common").is_dir()) / "common"
sys.path.insert(0, str(_common_dir))
from streams import reconfigure_streams  # noqa: E402

DETECTOR_NAME = "iac-checkov-wrapper"
CHECKOV_VERSION_UNKNOWN = "unknown"

# This plan's curated scope, per the kickoff decision (Helm dropped
# entirely — verified redundant with 010's rendered-manifest checks).
FRAMEWORKS = ("terraform", "cloudformation", "ansible")


class ScannerError(Exception):
    """Raised for a real invocation failure (checkov missing, a bad
    invocation) — fail loud rather than silently returning an empty
    findings list, which would look identical to "scanned cleanly, no
    issues found"."""


def _check_checkov_available() -> None:
    if shutil.which("checkov") is None:
        raise ScannerError(
            "checkov CLI not found on PATH. Install with 'pip install checkov' — see plans/011-iac-skill.md."
        )


def _build_check_id_index() -> dict[tuple[str, str], CheckovRule]:
    index: dict[tuple[str, str], CheckovRule] = {}
    for rule in CHECKOV_RULES:
        for framework, check_id in rule.check_ids.items():
            index[(framework, check_id)] = rule
    return index


_CHECK_ID_INDEX = _build_check_id_index()


def run_checkov(path: str) -> list[dict]:
    """Invokes the real checkov CLI against exactly one path and
    returns a list of per-framework result dicts.

    Only one path per invocation: verified for real at implementation
    that passing more than one `-d`/`-f` value to a single checkov
    invocation produces multiple JSON documents concatenated back to
    back in stdout — not a single valid JSON value and not a JSON
    array. `json.loads()` on that raw output raises "Extra data".
    Invoking once per path and aggregating avoids this entirely
    (mirrors 009/010's own one-Trivy-invocation-per-path constraint,
    for a different but equally real reason).

    Normalizes Checkov's three real, verified `-o json` output shapes:
    (1) a bare summary dict with no `check_type`/`results` keys when
    nothing matched any requested framework at all, (2) a single dict
    with `check_type`/`results`/`summary` when exactly one framework
    matched, (3) a list of such dicts when more than one framework
    matched within the same path (e.g. a directory containing both
    Terraform and Ansible files)."""
    _check_checkov_available()
    if not Path(path).exists():
        # Verified for real at implementation: checkov's own exit code
        # and stdout cannot distinguish a nonexistent path from a
        # legitimately empty one — both report the identical
        # zero-count summary and exit 0; the only difference is a
        # stderr log line, too fragile to depend on. Validate the path
        # ourselves instead of trusting checkov's own error signaling.
        raise ScannerError(f"path does not exist: {path}")

    # Verified for real at implementation: Checkov's own `file_abs_path`
    # field for CloudFormation isn't actually resolved — it just echoes
    # back whatever path string was passed on the command line,
    # relative or not (Terraform/Ansible results come back genuinely
    # absolute regardless of what was passed in). `_resolve_file_path()`
    # fixes this on the way out, using this same process's own CWD —
    # correct as long as nothing changes CWD between this call and that
    # one, which nothing here does.
    resolved = Path(path)
    target_flag = "-d" if resolved.is_dir() else "-f"
    cmd = ["checkov", target_flag, str(resolved), "--framework", *FRAMEWORKS, "-o", "json", "--quiet", "--compact"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    except FileNotFoundError as e:  # pragma: no cover - _check_checkov_available covers the common case
        raise ScannerError(f"failed to execute checkov: {e}") from e

    # Verified for real at implementation: checkov's exit-code contract
    # is a third, distinct convention from both Trivy's (0=success
    # regardless of findings, nonzero=failure) and 008's osv-scanner's
    # (0 or 1 both valid, content-dependent) — here `0` means "ran
    # cleanly, may or may not have findings", `1` means "ran cleanly
    # AND has findings" (not a failure), and only `2` (or a crash) is a
    # genuine invocation error.
    if proc.returncode not in (0, 1):
        raise ScannerError(f"checkov exited {proc.returncode}: {proc.stderr.strip()[-2000:]}")

    try:
        parsed = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise ScannerError(f"checkov did not return valid JSON: {e}") from e

    if isinstance(parsed, dict) and "check_type" not in parsed:
        return []
    if isinstance(parsed, dict):
        return [parsed]
    return parsed


def _finding_id(rule_id: str, file: str, start_line: int, end_line: int, discriminator: str) -> str:
    key = f"{rule_id}|{file}|{start_line}|{end_line}|{discriminator}"
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
    return f"iac-{digest}"


def _resolve_file_path(check: dict) -> str:
    """Checkov's own `file_abs_path` is reliably absolute for
    Terraform and Ansible, but verified for real at implementation to
    be **left relative** (whatever path was passed on the command
    line, unresolved) specifically for CloudFormation — a genuine,
    framework-specific inconsistency in the tool itself, the same
    class of bug 009 found with Trivy's `Target` field. `.resolve()`
    against this process's own CWD fixes it uniformly for all three
    frameworks: a no-op for an already-absolute path, and a real fix
    for CloudFormation's relative one — safe because `run_checkov()`
    never changes this process's CWD before or after invoking
    checkov, so both processes agree on what "relative" means."""
    return str(Path(check["file_abs_path"]).resolve())


def map_checkov_check(check: dict, framework: str, checkov_version: str) -> dict | None:
    """Maps one Checkov failed-check object to a finding.schema.json
    dict, using this plan's own hand-authored rule catalog (Checkov's
    own check metadata has no CWE mapping, and its open-source CLI
    output has no severity either — verified `severity: null` on every
    finding in the free tier). Returns None for a Checkov check ID this
    plan doesn't have a curated mapping for (Checkov ships ~1500+
    checks across these three frameworks; this plan curates a focused
    IAM + public-exposure subset per the kickoff decision) — silently
    skipped, not an error."""
    rule = _CHECK_ID_INDEX.get((framework, check["check_id"]))
    if rule is None:
        return None

    start_line, end_line = check.get("file_line_range") or [1, 1]
    file = _resolve_file_path(check)

    return {
        "findingId": _finding_id(rule.rule_id, file, start_line, end_line, check["check_id"]),
        "ruleId": rule.rule_id,
        "subSkill": "iac",
        "artifactType": framework,
        "title": rule.title,
        "problem": rule.problem,
        "impact": rule.impact,
        "recommendation": rule.recommendation,
        "references": rule.references,
        "severity": rule.severity,
        "confidence": rule.confidence,
        "location": {"file": file, "startLine": start_line, "endLine": end_line},
        "detectorSource": {"name": DETECTOR_NAME, "version": checkov_version},
        "suppressed": False,
    }


def scan_paths(paths: list[str]) -> list[dict]:
    """Scans one or more files/directories (Terraform, CloudFormation,
    or Ansible content — any mix within a single path is auto-detected
    per-file by checkov itself) for this plan's curated IAM +
    public-exposure checklist.

    Invokes checkov once per path, not once for the whole list —
    verified for real that passing multiple paths to one invocation
    produces malformed concatenated JSON (see run_checkov())."""
    findings = []
    for path in paths:
        for result in run_checkov(str(path)):
            framework = result.get("check_type", "")
            checkov_version = result.get("summary", {}).get("checkov_version", CHECKOV_VERSION_UNKNOWN)
            for check in result.get("results", {}).get("failed_checks") or []:
                mapped = map_checkov_check(check, framework, checkov_version)
                if mapped is not None:
                    findings.append(mapped)

    return findings


def scan_file(path: Path) -> list[dict]:
    return scan_paths([str(path)])


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Scan Terraform/CloudFormation/Ansible for IAM + public-exposure misconfigurations via Checkov.")
    parser.add_argument("paths", nargs="+", type=Path)
    args = parser.parse_args(argv)

    try:
        findings = scan_paths([str(p) for p in args.paths])
    except ScannerError as e:
        print(f"SCANNER ERROR: {e}", file=sys.stderr)
        return 1

    print(json.dumps(findings, indent=2))
    return 0


if __name__ == "__main__":
    reconfigure_streams()
    sys.exit(main())
