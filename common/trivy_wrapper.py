"""Shared Trivy CLI wrapper: subprocess invocation, error handling, and
result-to-finding.schema.json mapping for Trivy's `config`
(misconfiguration) scan mode.

Extracted from detectors/docker/scanner.py once
detectors/kubernetes/scanner.py (plan 010) needed the exact same
subprocess/mapping logic — Trivy's `config` scan auto-detects file type
(Dockerfile vs. Kubernetes YAML vs. Helm chart) and the invocation
mechanics don't differ at all between them; only each plan's own
curated rule catalog does. Same "shared module once a second consumer
exists" precedent as `common/semgrep_wrapper.py` (007/023). See
plans/009-docker-skill.md, plans/010-kubernetes-skill.md, and
meetings/2026-07-22-2000-plan-010-kickoff.md in the
security-skill-workspace repo.

Every behavior here (single-target-per-invocation limit, the
always-relative `Target` field, the exit-code contract) was verified
against real Trivy output while implementing plan 009 — see that
plan's Implementation section for the exact samples.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from pathlib import Path

TRIVY_VERSION_UNKNOWN = "unknown"

_SEVERITY_MAP = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "UNKNOWN": "Medium"}


class ScannerError(Exception):
    """Raised for a real invocation failure (trivy missing, a bad
    invocation) — fail loud rather than silently returning an empty
    findings list, which would look identical to "scanned cleanly, no
    issues found"."""


def _check_trivy_available() -> None:
    if shutil.which("trivy") is None:
        raise ScannerError(
            "trivy CLI not found on PATH. Install with 'brew install trivy' or a prebuilt binary "
            "(Scoop/WinGet on Windows) — see plans/009-docker-skill.md."
        )


def run_trivy(path: str, excluded_check_ids: tuple[str, ...] = ()) -> dict:
    """Invokes the real trivy CLI (`config` scan mode) against exactly
    one path and returns its parsed JSON output.

    Only one path per invocation — verified for real at 009's
    implementation that `trivy config` rejects more than one target
    with a FATAL "multiple targets cannot be specified" error, unlike
    007's Semgrep or 008's osv-scanner, which both accept a path list.
    `iter_scanned_files()` below invokes this once per path and
    aggregates, rather than trying to pass a list through in one call.

    `excluded_check_ids` writes a temporary `--ignorefile` (not a real
    `.trivyignore` in the scanned repo, which could collide with one
    the target repo already has) — used by 009 to exclude Trivy's own
    secrets-in-ENV check (006 owns that exclusively); 010 doesn't need
    any exclusions for its curated scope.

    Not mocked anywhere in this module or its consumers' tests — same
    discipline as 007/008's external-tool wrappers."""
    _check_trivy_available()
    ignore_path = None
    if excluded_check_ids:
        with tempfile.NamedTemporaryFile("w", suffix=".trivyignore", delete=False, encoding="utf-8") as f:
            f.write("\n".join(excluded_check_ids) + "\n")
            ignore_path = f.name

    try:
        cmd = ["trivy", "config", "--format", "json"]
        if ignore_path:
            cmd.extend(["--ignorefile", ignore_path])
        cmd.append(path)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
        except FileNotFoundError as e:  # pragma: no cover - _check_trivy_available covers the common case
            raise ScannerError(f"failed to execute trivy: {e}") from e

        # Verified at 009's implementation: unlike 008's osv-scanner,
        # trivy's exit code IS a reliable success/failure signal on its
        # own — 0 regardless of findings, nonzero (confirmed rc=1) only
        # for a genuine invocation failure, with FATAL-prefixed stderr
        # and empty stdout in that case.
        if proc.returncode != 0:
            raise ScannerError(f"trivy exited {proc.returncode}: {proc.stderr.strip()[-2000:]}")

        try:
            output = json.loads(proc.stdout)
        except json.JSONDecodeError as e:
            raise ScannerError(f"trivy did not return valid JSON: {e}") from e
    finally:
        if ignore_path:
            Path(ignore_path).unlink(missing_ok=True)

    return output


def resolve_target_path(artifact_name: str, target: str) -> Path:
    """Trivy's per-result `Target` is always relative to whatever root
    it scanned (e.g. "Dockerfile"), never an absolute or CWD-relative
    path on its own — verified for real at 009's implementation, where
    this was a genuine bug: reading `Target` directly silently failed
    whenever the scanned path differed from the process's current
    working directory. The top-level `ArtifactName` gives the resolved
    root that was actually scanned (a directory, or the file itself if
    a single file was scanned directly) — join them for a real,
    readable path."""
    root = Path(artifact_name)
    return root / target if root.is_dir() else root


def iter_scanned_files(paths: list[str], excluded_check_ids: tuple[str, ...] = ()) -> Iterator[tuple[str, dict, str]]:
    """Invokes Trivy once per path in `paths` (required — see
    run_trivy()) and yields (file, result, trivy_version) for every
    file Trivy recognized as a config target, even ones with zero
    findings — its own JSON output still lists them, which is how a
    caller can run extra logic (e.g. 009's custom regex rules) against
    every discovered file, not just ones Trivy itself flagged."""
    for path in paths:
        output = run_trivy(str(path), excluded_check_ids)
        trivy_version = output.get("Trivy", {}).get("Version", TRIVY_VERSION_UNKNOWN)
        artifact_name = output.get("ArtifactName", str(path))
        for result in output.get("Results") or []:
            file = str(resolve_target_path(artifact_name, result.get("Target", "")))
            yield file, result, trivy_version


def severity_from_trivy(raw_severity: str | None) -> str:
    return _SEVERITY_MAP.get((raw_severity or "").upper(), "Medium")


def finding_id(id_prefix: str, rule_id: str, file: str, start_line: int, end_line: int, discriminator: str) -> str:
    key = f"{rule_id}|{file}|{start_line}|{end_line}|{discriminator}"
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
    return f"{id_prefix}-{digest}"


def map_trivy_misconfig(
    misconfig: dict,
    file: str,
    artifact_type: str,
    trivy_version: str,
    *,
    sub_skill: str,
    rule_catalog: dict,
    id_prefix: str,
    detector_name: str,
) -> dict | None:
    """Maps one Trivy misconfiguration object to a finding.schema.json
    dict, using the caller's own hand-authored rule catalog (Trivy's
    own check metadata has no CWE mapping). Returns None for a Trivy
    check ID the caller doesn't have a curated mapping for (Trivy's
    `config` scan has many more general-purpose checks beyond any one
    plan's declared scope) — silently skipped, not an error."""
    rule = rule_catalog.get(misconfig["ID"])
    if rule is None:
        return None

    cause = misconfig.get("CauseMetadata", {})
    start_line = cause.get("StartLine") or 1
    end_line = cause.get("EndLine") or start_line
    severity = severity_from_trivy(misconfig.get("Severity"))

    return {
        "findingId": finding_id(id_prefix, rule.rule_id, file, start_line, end_line, misconfig["ID"]),
        "ruleId": rule.rule_id,
        "subSkill": sub_skill,
        "artifactType": artifact_type,
        "title": rule.title,
        "problem": rule.problem,
        "impact": rule.impact,
        "recommendation": rule.recommendation,
        "references": rule.references,
        "severity": severity,
        "confidence": rule.confidence,
        "location": {"file": file, "startLine": start_line, "endLine": end_line},
        "detectorSource": {"name": detector_name, "version": trivy_version},
        "suppressed": False,
    }
