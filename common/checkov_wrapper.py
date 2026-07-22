"""Shared Checkov CLI wrapper: subprocess invocation, error handling,
JSON-shape normalization, and result-to-finding.schema.json mapping.

Extracted from detectors/iac/scanner.py once plan 013 (CI/CD Pipeline
Skill) needed the same logic for `github_actions`/`gitlab_ci` frameworks
— matching plan 005's precedent that shared tool-wrapper logic moves to
`common/` once a *second* consumer exists (the same trigger that moved
Semgrep/Trivy wrapping here for 023/010). See plans/011-iac-skill.md
and plans/013-cicd-pipeline-skill.md in the security-skill-workspace
repo.

Every mapping/quirk choice here (exit-code contract, JSON-shape
normalization, `file_abs_path` resolution) was derived from *real*
Checkov output sampled while implementing plan 011, not guessed at from
documentation — see that plan's Implementation section for the exact
samples. Not yet re-verified for the `github_actions`/`gitlab_ci`
frameworks specifically at the time of this extraction — 013's own
kickoff flagged this as implementation-time verification work, not
assumed to be identical.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

CHECKOV_VERSION_UNKNOWN = "unknown"


class ScannerError(Exception):
    """Raised for a real invocation failure (checkov missing, a bad
    invocation) — fail loud rather than silently returning an empty
    findings list, which would look identical to "scanned cleanly, no
    issues found"."""


@dataclass(frozen=True)
class CheckovRule:
    rule_id: str
    title: str
    problem: str
    impact: str
    recommendation: str
    references: list[dict]
    severity: str
    confidence: int
    check_ids: dict[str, str]  # framework -> checkov check_id (one rule can span more than one framework)


def _check_checkov_available() -> None:
    if shutil.which("checkov") is None:
        raise ScannerError(
            "checkov CLI not found on PATH. Install with 'pip install checkov' — see plans/011-iac-skill.md."
        )


def build_check_id_index(rules: list[CheckovRule]) -> dict[tuple[str, str], CheckovRule]:
    """Builds a `(framework, check_id) -> CheckovRule` reverse index
    from a detector's own curated rule list — the same shape 011's
    kickoff found necessary because Checkov's check IDs are often
    framework-specific for the same logical concern (e.g. IAM privilege
    escalation is `CKV_AWS_286` in Terraform but `CKV_AWS_110` in
    CloudFormation)."""
    index: dict[tuple[str, str], CheckovRule] = {}
    for rule in rules:
        for framework, check_id in rule.check_ids.items():
            index[(framework, check_id)] = rule
    return index


def run_checkov(path: str, frameworks: tuple[str, ...]) -> list[dict]:
    """Invokes the real checkov CLI against exactly one path and
    returns a list of per-framework result dicts.

    Only one path per invocation: verified for real at 011's
    implementation that passing more than one `-d`/`-f` value to a
    single checkov invocation produces multiple JSON documents
    concatenated back to back in stdout — not a single valid JSON value
    and not a JSON array. `json.loads()` on that raw output raises
    "Extra data". Invoking once per path and aggregating avoids this
    entirely (mirrors 009/010's own one-Trivy-invocation-per-path
    constraint, for a different but equally real reason).

    Normalizes Checkov's three real, verified `-o json` output shapes:
    (1) a bare summary dict with no `check_type`/`results` keys when
    nothing matched any requested framework at all, (2) a single dict
    with `check_type`/`results`/`summary` when exactly one framework
    matched, (3) a list of such dicts when more than one framework
    matched within the same path."""
    _check_checkov_available()
    if not Path(path).exists():
        # Verified for real at 011's implementation: checkov's own exit
        # code and stdout cannot distinguish a nonexistent path from a
        # legitimately empty one — both report the identical zero-count
        # summary and exit 0; the only difference is a stderr log line,
        # too fragile to depend on. Validate the path ourselves instead
        # of trusting checkov's own error signaling.
        raise ScannerError(f"path does not exist: {path}")

    resolved = Path(path)
    target_flag = "-d" if resolved.is_dir() else "-f"
    cmd = ["checkov", target_flag, str(resolved), "--framework", *frameworks, "-o", "json", "--quiet", "--compact"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    except FileNotFoundError as e:  # pragma: no cover - _check_checkov_available covers the common case
        raise ScannerError(f"failed to execute checkov: {e}") from e

    # Verified for real at 011's implementation: checkov's exit-code
    # contract is a third, distinct convention from both Trivy's
    # (0=success regardless of findings, nonzero=failure) and 008's
    # osv-scanner's (0 or 1 both valid, content-dependent) — here `0`
    # means "ran cleanly, may or may not have findings", `1` means "ran
    # cleanly AND has findings" (not a failure), and only `2` (or a
    # crash) is a genuine invocation error.
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


def finding_id(id_prefix: str, rule_id: str, file: str, start_line: int, end_line: int, discriminator: str) -> str:
    key = f"{rule_id}|{file}|{start_line}|{end_line}|{discriminator}"
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
    return f"{id_prefix}-{digest}"


def _resolve_file_path(check: dict) -> str:
    """Checkov's own `file_abs_path` is reliably absolute for
    Terraform and Ansible, but verified for real at 011's implementation
    to be **left relative** (whatever path string was passed on the
    command line, unresolved) specifically for CloudFormation — a
    genuine, framework-specific inconsistency in the tool itself, the
    same class of bug 009 found with Trivy's `Target` field.
    `.resolve()` against this process's own CWD fixes it uniformly for
    every framework: a no-op for an already-absolute path, and a real
    fix for CloudFormation's relative one — correct as long as nothing
    changes CWD between invoking checkov and this call, which nothing
    here does. Not yet re-verified whether `github_actions`/`gitlab_ci`
    have their own version of this inconsistency — 013's own kickoff
    flagged this as implementation-time verification work."""
    return str(Path(check["file_abs_path"]).resolve())


def map_checkov_check(
    check: dict,
    framework: str,
    checkov_version: str,
    *,
    sub_skill: str,
    rule_catalog_index: dict[tuple[str, str], CheckovRule],
    id_prefix: str,
    detector_name: str,
    artifact_type_map: dict[str, str] | None = None,
) -> dict | None:
    """Maps one Checkov failed-check object to a finding.schema.json
    dict, using the caller's own hand-authored rule catalog (Checkov's
    own check metadata has no CWE mapping, and its open-source CLI
    output has no severity either — verified `severity: null` on every
    finding in the free tier). Returns None for a Checkov check ID the
    caller doesn't have a curated mapping for — silently skipped, not an
    error, since Checkov ships far more checks per framework than any
    one sub-skill plan curates.

    `artifact_type_map` translates Checkov's own `check_type` string
    (e.g. `"github_actions"`) to finding.schema.json's `artifactType`
    enum value (e.g. `"github-actions"`) when they differ — needed for
    013's frameworks specifically (Checkov uses underscores, the schema
    uses hyphens for these two), verified empirically at that plan's
    implementation. Frameworks not in the map (or when no map is given)
    pass through unchanged — correct for 011's frameworks
    (terraform/cloudformation/ansible), whose Checkov `check_type`
    values already match the schema's `artifactType` values exactly."""
    rule = rule_catalog_index.get((framework, check["check_id"]))
    if rule is None:
        return None

    start_line, end_line = check.get("file_line_range") or [1, 1]
    # Verified for real at 013's implementation: Checkov's graph-based
    # checks (`CKV2_*`, stored as JSON graph-check definitions rather
    # than a Python check class — e.g. github_actions' `CKV2_GHA_1`)
    # report a 0-indexed file_line_range, unlike every regular
    # (`CKV_*`) check, which reports a proper 1-indexed range. Clamping
    # to a minimum of 1 handles this without needing to special-case
    # graph checks by ID — finding.schema.json requires startLine >= 1
    # regardless of which check produced it.
    start_line = max(start_line, 1)
    end_line = max(end_line, start_line)
    file = _resolve_file_path(check)
    artifact_type = (artifact_type_map or {}).get(framework, framework)

    return {
        "findingId": finding_id(id_prefix, rule.rule_id, file, start_line, end_line, check["check_id"]),
        "ruleId": rule.rule_id,
        "subSkill": sub_skill,
        "artifactType": artifact_type,
        "title": rule.title,
        "problem": rule.problem,
        "impact": rule.impact,
        "recommendation": rule.recommendation,
        "references": rule.references,
        "severity": rule.severity,
        "confidence": rule.confidence,
        "location": {"file": file, "startLine": start_line, "endLine": end_line},
        "detectorSource": {"name": detector_name, "version": checkov_version},
        "suppressed": False,
    }


def scan_paths(
    paths: list[str],
    frameworks: tuple[str, ...],
    *,
    sub_skill: str,
    rule_catalog_index: dict[tuple[str, str], CheckovRule],
    id_prefix: str,
    detector_name: str,
    artifact_type_map: dict[str, str] | None = None,
) -> list[dict]:
    """Scans one or more files/directories via Checkov, invoking it
    once per path (not once for the whole list — see run_checkov()) and
    mapping every failed check the caller's rule_catalog_index
    recognizes to a finding.schema.json dict."""
    findings = []
    for path in paths:
        for result in run_checkov(str(path), frameworks):
            framework = result.get("check_type", "")
            checkov_version = result.get("summary", {}).get("checkov_version", CHECKOV_VERSION_UNKNOWN)
            for check in result.get("results", {}).get("failed_checks") or []:
                mapped = map_checkov_check(
                    check,
                    framework,
                    checkov_version,
                    sub_skill=sub_skill,
                    rule_catalog_index=rule_catalog_index,
                    id_prefix=id_prefix,
                    detector_name=detector_name,
                    artifact_type_map=artifact_type_map,
                )
                if mapped is not None:
                    findings.append(mapped)

    return findings
