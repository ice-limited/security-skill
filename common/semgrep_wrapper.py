"""Shared Semgrep CLI wrapper: subprocess invocation, error handling,
and result-to-finding.schema.json mapping.

Extracted from detectors/code-review/scanner.py once 023's Semgrep-
subset half needed the same logic (`detectors/auth/semgrep_detector.py`)
— matching plan 005's precedent that shared logic moves to `common/`
once a second consumer exists, rather than staying duplicated across
detector directories. See plans/007-code-review-skill.md and
plans/023-authn-authz-code-review-skill.md in the
security-skill-workspace repo.

Every mapping choice here (byte offsets, severity/confidence tables,
reference extraction, error-level filtering) was derived from *real*
Semgrep JSON output sampled while implementing plan 007, not guessed at
from documentation — see that plan's Implementation section for the
exact samples.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

_common_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(next(p for p in _common_dir.parents if (p / "knowledge").is_dir()) / "knowledge"))
import standards  # noqa: E402

# Only this edition is seeded in knowledge/owasp-top10.json (plan 002's
# "current edition only" policy) — Semgrep's own metadata.owasp lists
# multiple editions per rule (e.g. "A01:2017", "A03:2021", "A05:2025"
# all on one rule); only the 2025-suffixed entry is ever usable here.
_OWASP_EDITION_PATTERN = re.compile(r"^(A\d{1,2}:2025)\b")
_CWE_ID_PATTERN = re.compile(r"^(CWE-\d+)\b")


class ScannerError(Exception):
    """Raised for a real invocation failure (semgrep missing, a bad
    --config, or semgrep itself reporting a hard error) — fail loud
    rather than silently returning an empty findings list, which would
    look identical to "scanned cleanly, no issues found"."""


def _check_semgrep_available() -> None:
    if shutil.which("semgrep") is None:
        raise ScannerError(
            "semgrep CLI not found on PATH. Install with 'pip install semgrep' "
            "or 'pipx install semgrep' (pipx/uv recommended on Windows, where "
            "Semgrep support is beta — see plans/007-code-review-skill.md)."
        )


def run_semgrep(paths: list[str], config: str) -> dict:
    """Invokes the real semgrep CLI and returns its parsed JSON output.
    Not mocked anywhere in this module's own tests, or any detector
    that calls it — per plan 007's kickoff testing discipline (มิ้นท์:
    mocking semgrep's subprocess output would defeat the point)."""
    _check_semgrep_available()
    cmd = ["semgrep", "--config", config, "--json", "--quiet", *paths]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    except FileNotFoundError as e:  # pragma: no cover - _check_semgrep_available covers the common case
        raise ScannerError(f"failed to execute semgrep: {e}") from e

    if proc.returncode != 0:
        raise ScannerError(
            f"semgrep exited {proc.returncode} for config {config!r}: {proc.stderr.strip()[-2000:]}"
        )

    try:
        output = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise ScannerError(f"semgrep did not return valid JSON: {e}") from e

    # A hard failure (bad scanning root, bad --config) already shows up
    # as a nonzero return code, caught above. `errors` can *also* be
    # non-empty on a rc=0 run for a much more common, non-fatal reason:
    # one file in a multi-file scan fails to parse (level "warn",
    # e.g. type "PartialParsing") while every other file still scans
    # fine — verified for real at 007's implementation by mixing a
    # syntactically-broken file into a scan directory alongside a
    # valid one. Discarding all results because of one unrelated bad
    # file would make this detector unusable on any real repo, so only
    # an "error"-level entry (a genuine hard failure) raises here.
    hard_errors = [e for e in output.get("errors", []) if e.get("level") == "error"]
    if hard_errors:
        raise ScannerError(f"semgrep reported error-level failures: {hard_errors}")

    return output


def severity(result_severity: str, impact: str | None) -> str:
    # Semgrep has 3 severities (ERROR/WARNING/INFO) vs. our 5
    # (Critical/High/Medium/Low/Info) — impact/likelihood metadata
    # disambiguates ERROR/WARNING into two tiers each. Derived from
    # real samples (see plan 007's Implementation section), not
    # invented: e.g. subprocess-shell-true was severity=ERROR but
    # impact=LOW (shell=True alone isn't immediately exploitable
    # without tainted input reaching it), while the same file's
    # subprocess-injection rule was severity=ERROR, impact=HIGH.
    impact = (impact or "").upper()
    if result_severity == "ERROR":
        return "Critical" if impact == "HIGH" else "High"
    if result_severity == "WARNING":
        return "High" if impact == "HIGH" else "Medium"
    return "Low"


def confidence(result_confidence: str | None) -> int:
    return {"HIGH": 85, "MEDIUM": 65, "LOW": 40}.get((result_confidence or "").upper(), 50)


def extract_references(metadata: dict) -> list[dict]:
    """Builds finding.schema.json's references[] from Semgrep rule
    metadata, keeping only what resolves in our knowledge base (we
    don't control what a registry rule cites, so this degrades
    gracefully rather than crashing on an unrecognized id)."""
    refs: list[dict] = []
    for raw_cwe in metadata.get("cwe", []):
        m = _CWE_ID_PATTERN.match(raw_cwe)
        if m and standards.exists("CWE", m.group(1)):
            refs.append({"standard": "CWE", "id": m.group(1)})
    for raw_owasp in metadata.get("owasp", []):
        m = _OWASP_EDITION_PATTERN.match(raw_owasp)
        if m and standards.exists("OWASP-Top10", m.group(1)):
            refs.append({"standard": "OWASP-Top10", "id": m.group(1)})
    return refs


def finding_id(id_prefix: str, rule_id: str, file: str, start_line: int, end_line: int, start_byte: int, end_byte: int) -> str:
    # Same shape as 006's findingId (includes byte offsets so two
    # matches of the same rule on one line get distinct ids).
    key = f"{rule_id}|{file}|{start_line}|{end_line}|{start_byte}|{end_byte}"
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
    return f"{id_prefix}-{digest}"


def problem_impact_recommendation(result: dict, metadata: dict) -> tuple[str, str, str]:
    # Semgrep's own message is already a detailed, rule-specific
    # description — used directly as `problem` rather than
    # re-authoring per check_id (packs like p/owasp-top-ten have ~80+
    # distinct check_ids, too many to hand-author text for the way 006
    # did for its 8 self-authored rules).
    problem = result["extra"]["message"].strip()

    vuln_classes = ", ".join(metadata.get("vulnerability_class", ["this class of vulnerability"]))
    likelihood = metadata.get("likelihood", "unknown")
    impact_level = metadata.get("impact", "unknown")
    impact = (
        f"If exploitable, this {vuln_classes} issue could allow an attacker to compromise "
        f"the affected functionality. The rule author rates likelihood {likelihood} and impact {impact_level}."
    )

    ref_urls = metadata.get("references") or []
    source_url = metadata.get("source")
    link = ref_urls[0] if ref_urls else source_url
    recommendation = "Review and remediate this finding."
    if link:
        recommendation += f" See: {link}"

    return problem, impact, recommendation


def map_result_to_finding(
    result: dict,
    artifact_type: str,
    semgrep_version: str,
    *,
    sub_skill: str,
    rule_id_prefix: str,
    id_prefix: str,
    detector_name: str,
    rule_id_overrides: dict[str, str] | None = None,
) -> dict:
    """Maps one Semgrep result object (from the real `results[]` array
    of its --json output) to a finding.schema.json-shaped dict.

    `rule_id_overrides` lets a caller map specific check_ids to an
    existing curated ruleId (e.g. detectors/auth/ reusing its own
    checklist item ruleIds for check_ids it recognizes) instead of the
    generic `{rule_id_prefix}.{check_id}` fallback — see
    detectors/auth/semgrep_detector.py."""
    metadata = result["extra"].get("metadata", {})
    start, end = result["start"], result["end"]
    start_byte = start.get("offset")
    end_byte = end.get("offset")
    check_id = result["check_id"]
    rule_id = (rule_id_overrides or {}).get(check_id, f"{rule_id_prefix}.{check_id}")
    file = result["path"]

    problem, impact, recommendation = problem_impact_recommendation(result, metadata)
    references = extract_references(metadata)
    if not references:
        # A curated pack/config is expected to be scoped to CWEs
        # already seeded in knowledge/ — an empty list here means
        # either the pack drifted outside that scope or a rule's
        # metadata is malformed. Fail loud rather than emit a
        # references=[] finding that would fail finding.schema.json's
        # minItems:1 anyway, with a much less useful error message.
        raise ScannerError(f"{rule_id} produced no recognized standards references (metadata={metadata})")

    location = {
        "file": file,
        "startLine": start["line"],
        "endLine": end["line"],
        "startColumn": start["col"],
        "endColumn": end["col"],
    }
    if start_byte is not None:
        location["startByte"] = start_byte
    if end_byte is not None:
        location["endByte"] = end_byte

    return {
        "findingId": finding_id(id_prefix, rule_id, file, start["line"], end["line"], start_byte or 0, end_byte or 0),
        "ruleId": rule_id,
        "subSkill": sub_skill,
        "artifactType": artifact_type,
        "title": check_id.rsplit(".", 1)[-1].replace("-", " ").capitalize(),
        "problem": problem,
        "impact": impact,
        "recommendation": recommendation,
        "references": references,
        "severity": severity(result["extra"]["severity"], metadata.get("impact")),
        "confidence": confidence(metadata.get("confidence")),
        "location": location,
        "detectorSource": {"name": detector_name, "version": semgrep_version},
        "suppressed": False,
    }


def scan_paths(
    paths: list[str],
    config: str,
    artifact_type: str,
    *,
    sub_skill: str,
    rule_id_prefix: str,
    id_prefix: str,
    detector_name: str,
    rule_id_overrides: dict[str, str] | None = None,
) -> list[dict]:
    """Scans one or more files/directories with Semgrep and returns
    findings matching finding.schema.json."""
    output = run_semgrep(paths, config)
    version = output.get("version", "unknown")
    return [
        map_result_to_finding(
            r,
            artifact_type,
            version,
            sub_skill=sub_skill,
            rule_id_prefix=rule_id_prefix,
            id_prefix=id_prefix,
            detector_name=detector_name,
            rule_id_overrides=rule_id_overrides,
        )
        for r in output["results"]
    ]
