"""Docker/Dockerfile hardening detection: unpinned base image, root
user, missing HEALTHCHECK (via Trivy's `config` scan mode), plus
hand-written custom rules for `apt-get upgrade`, `curl | bash`, and
`ADD` vs `COPY` (neither Trivy nor Hadolint has a security-specific
rule for these — verified at plan 009's kickoff).

Decided at kickoff: wraps Trivy (github.com/aquasecurity/trivy,
Apache-2.0), not Hadolint (GPL-3.0), even though Hadolint's coverage is
broader for some checks — see plans/009-docker-skill.md and
meetings/2026-07-22-1900-plan-009-kickoff.md in the
security-skill-workspace repo for design rationale and the exact
verification each mapping choice below was derived from.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from rules import ARCHIVE_EXTENSIONS, CUSTOM_RULES, TRIVY_RULES, CustomRule

_common_dir = next(p for p in Path(__file__).resolve().parents if (p / "common").is_dir()) / "common"
sys.path.insert(0, str(_common_dir))
from streams import reconfigure_streams  # noqa: E402

DETECTOR_NAME = "docker-trivy-wrapper"
TRIVY_VERSION_UNKNOWN = "unknown"

_TRIVY_SEVERITY_MAP = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "UNKNOWN": "Medium"}

# DS-0031 (secrets in ENV/build-args) is Trivy's own built-in check,
# found unexpectedly while verifying this plan at kickoff — excluded so
# 006 (Secret Detection) owns hardcoded-secret detection exclusively
# across every artifact type. Verified the exclusion mechanism actually
# works (a temp --ignorefile, not a real .trivyignore in the scanned
# repo, which could collide with one the target repo already has).
_EXCLUDED_TRIVY_CHECK_IDS = ("DS-0031",)


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


def run_trivy(path: str) -> dict:
    """Invokes the real trivy CLI (`config` scan mode) against exactly
    one path and returns its parsed JSON output.

    Only one path per invocation — verified for real at implementation
    that `trivy config` rejects more than one target with a FATAL
    "multiple targets cannot be specified" error, unlike 007's Semgrep
    or 008's osv-scanner, which both accept a path list. `scan_paths()`
    below invokes this once per path and aggregates, rather than trying
    to pass a list through in one call.

    Not mocked anywhere in this module or its tests — same discipline
    as 007/008's external-tool wrappers."""
    _check_trivy_available()
    with tempfile.NamedTemporaryFile("w", suffix=".trivyignore", delete=False, encoding="utf-8") as f:
        f.write("\n".join(_EXCLUDED_TRIVY_CHECK_IDS) + "\n")
        ignore_path = f.name

    try:
        cmd = ["trivy", "config", "--format", "json", "--ignorefile", ignore_path, path]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
        except FileNotFoundError as e:  # pragma: no cover - _check_trivy_available covers the common case
            raise ScannerError(f"failed to execute trivy: {e}") from e

        # Verified at implementation: unlike 008's osv-scanner, trivy's
        # exit code IS a reliable success/failure signal on its own —
        # 0 regardless of findings, nonzero (confirmed rc=1) only for a
        # genuine invocation failure (bad path, etc.), with FATAL-
        # prefixed stderr and empty stdout in that case.
        if proc.returncode != 0:
            raise ScannerError(f"trivy exited {proc.returncode}: {proc.stderr.strip()[-2000:]}")

        try:
            output = json.loads(proc.stdout)
        except json.JSONDecodeError as e:
            raise ScannerError(f"trivy did not return valid JSON: {e}") from e
    finally:
        Path(ignore_path).unlink(missing_ok=True)

    return output


def _finding_id(rule_id: str, file: str, start_line: int, end_line: int, discriminator: str) -> str:
    key = f"{rule_id}|{file}|{start_line}|{end_line}|{discriminator}"
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
    return f"docker-{digest}"


def map_trivy_misconfig(misconfig: dict, file: str, artifact_type: str, trivy_version: str) -> dict | None:
    """Maps one Trivy misconfiguration object to a finding.schema.json
    dict, using this plan's own hand-authored rule catalog (Trivy's own
    metadata has no CWE mapping). Returns None for a Trivy check ID
    this plan doesn't have a curated mapping for (Trivy's `config` scan
    has many more general-purpose checks beyond this plan's declared
    scope) — silently skipped, not an error."""
    rule = TRIVY_RULES.get(misconfig["ID"])
    if rule is None:
        return None

    cause = misconfig.get("CauseMetadata", {})
    start_line = cause.get("StartLine") or 1
    end_line = cause.get("EndLine") or start_line
    severity = _TRIVY_SEVERITY_MAP.get((misconfig.get("Severity") or "").upper(), "Medium")

    return {
        "findingId": _finding_id(rule.rule_id, file, start_line, end_line, misconfig["ID"]),
        "ruleId": rule.rule_id,
        "subSkill": "docker",
        "artifactType": artifact_type,
        "title": rule.title,
        "problem": rule.problem,
        "impact": rule.impact,
        "recommendation": rule.recommendation,
        "references": rule.references,
        "severity": severity,
        "confidence": rule.confidence,
        "location": {"file": file, "startLine": start_line, "endLine": end_line},
        "detectorSource": {"name": DETECTOR_NAME, "version": trivy_version},
        "suppressed": False,
    }


def _build_custom_finding(rule: CustomRule, file: str, start_line: int, end_line: int, artifact_type: str) -> dict:
    return {
        "findingId": _finding_id(rule.rule_id, file, start_line, end_line, str(start_line)),
        "ruleId": rule.rule_id,
        "subSkill": "docker",
        "artifactType": artifact_type,
        "title": rule.title,
        "problem": rule.problem,
        "impact": rule.impact,
        "recommendation": rule.recommendation,
        "references": rule.references,
        "severity": rule.severity,
        "confidence": rule.confidence,
        "location": {"file": file, "startLine": start_line, "endLine": end_line},
        "detectorSource": {"name": DETECTOR_NAME, "version": "custom-rules"},
        "suppressed": False,
    }


def _blank_out_comment_lines(content: str) -> str:
    """Replaces the content of any line that is a Dockerfile-level
    comment (first non-whitespace character is '#') with blanks,
    preserving line count/numbering so downstream line-number math
    stays correct. Found as a real bug during the "test plan 009"
    round, not theoretical: a comment merely *mentioning* an
    anti-pattern (e.g. "# Do NOT do this: curl ... | bash") was being
    flagged as if the anti-pattern were actually present."""
    return "\n".join("" if line.lstrip().startswith("#") else line for line in content.split("\n"))


def _join_continuation_lines(content: str) -> list[tuple[int, str]]:
    """Returns (start_line, joined_text) pairs. Dockerfile RUN
    instructions commonly wrap across multiple physical lines using a
    trailing backslash — matching against physical lines alone would
    miss a pattern split across the continuation (verified for real at
    implementation with a multi-line `curl | bash` fixture)."""
    raw_lines = content.split("\n")
    result: list[tuple[int, str]] = []
    buf: list[str] = []
    start: int | None = None
    for i, line in enumerate(raw_lines, start=1):
        if start is None:
            start = i
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            buf.append(stripped[:-1])
            continue
        buf.append(line)
        result.append((start, "\n".join(buf)))
        buf = []
        start = None
    if buf:
        result.append((start, "\n".join(buf)))
    return result


def _scan_pattern_rule(rule: CustomRule, content: str, file: str, artifact_type: str) -> list[dict]:
    findings = []
    lines = (
        _join_continuation_lines(content)
        if rule.join_continuations
        else [(i, line) for i, line in enumerate(content.split("\n"), start=1)]
    )
    for start_line, text in lines:
        if rule.pattern.search(text):
            end_line = start_line + text.count("\n")
            findings.append(_build_custom_finding(rule, file, start_line, end_line, artifact_type))
    return findings


def _scan_add_vs_copy(rule: CustomRule, content: str, file: str, artifact_type: str) -> list[dict]:
    findings = []
    for i, line in enumerate(content.split("\n"), start=1):
        m = rule.pattern.match(line)
        if not m:
            continue
        src = m.group(1)
        if src.lower().startswith(("http://", "https://")) or src.lower().endswith(ARCHIVE_EXTENSIONS):
            continue
        findings.append(_build_custom_finding(rule, file, i, i, artifact_type))
    return findings


_SPECIAL_CUSTOM_RULE_HANDLERS = {"docker.add-instead-of-copy": _scan_add_vs_copy}


def scan_custom_rules(content: str, file: str, artifact_type: str = "dockerfile") -> list[dict]:
    """Scans raw Dockerfile text content for the patterns neither
    Trivy nor Hadolint covers as a security-specific check. Does not
    read from disk — see scan_paths() for that."""
    content = _blank_out_comment_lines(content)
    findings = []
    for rule in CUSTOM_RULES:
        handler = _SPECIAL_CUSTOM_RULE_HANDLERS.get(rule.rule_id, _scan_pattern_rule)
        findings.extend(handler(rule, content, file, artifact_type))
    return findings


def _resolve_target_path(artifact_name: str, target: str) -> Path:
    """Trivy's per-result `Target` is always relative to whatever root
    it scanned (e.g. "Dockerfile"), never an absolute or CWD-relative
    path on its own — verified for real at implementation, where this
    was a genuine bug: reading `Target` directly silently failed
    whenever the scanned path differed from the process's current
    working directory. The top-level `ArtifactName` gives the resolved
    root that was actually scanned (a directory, or the file itself if
    a single file was scanned directly) — join them for a real,
    readable path."""
    root = Path(artifact_name)
    return root / target if root.is_dir() else root


def scan_paths(paths: list[str], artifact_type: str = "dockerfile") -> list[dict]:
    """Scans one or more files/directories: Trivy's `config` mode for
    unpinned-base-image/root-user/missing-healthcheck, plus this
    module's own custom rules run directly against each Dockerfile
    Trivy discovered (its own JSON output tells us which files were
    recognized as Dockerfiles, even ones with zero Trivy findings).

    Invokes Trivy once per path, not once for the whole list — verified
    for real that `trivy config` rejects more than one target per
    invocation (see run_trivy())."""
    findings = []
    for path in paths:
        output = run_trivy(str(path))
        trivy_version = output.get("Trivy", {}).get("Version", TRIVY_VERSION_UNKNOWN)
        artifact_name = output.get("ArtifactName", str(path))

        for result in output.get("Results") or []:
            file = str(_resolve_target_path(artifact_name, result.get("Target", "")))
            for misconfig in result.get("Misconfigurations") or []:
                mapped = map_trivy_misconfig(misconfig, file, artifact_type, trivy_version)
                if mapped is not None:
                    findings.append(mapped)

            try:
                content = Path(file).read_text(encoding="utf-8")
            except OSError:
                continue
            findings.extend(scan_custom_rules(content, file, artifact_type))

    return findings


def scan_file(path: Path, artifact_type: str = "dockerfile") -> list[dict]:
    return scan_paths([str(path)], artifact_type=artifact_type)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Scan Dockerfile(s)/directory for hardening issues via Trivy + custom rules.")
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--artifact-type", default="dockerfile")
    args = parser.parse_args(argv)

    try:
        findings = scan_paths(args.paths, artifact_type=args.artifact_type)
    except ScannerError as e:
        print(f"SCANNER ERROR: {e}", file=sys.stderr)
        return 1

    print(json.dumps(findings, indent=2))
    return 0


if __name__ == "__main__":
    reconfigure_streams()
    sys.exit(main())
