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

The actual subprocess/mapping logic lives in common/trivy_wrapper.py
— extracted there once 010's Kubernetes sub-skill needed the exact
same Trivy invocation/mapping mechanics, per plan 005's "shared module
once a second consumer exists" precedent (mirrors
common/semgrep_wrapper.py, shared between 007 and 023). This module is
now a thin, subSkill-specific wrapper over it: its own rule catalog
(rules.py) and its own custom-rules layer (apt-get upgrade/curl | bash/
ADD-vs-COPY — Docker-specific, not shared).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from rules import ARCHIVE_EXTENSIONS, CUSTOM_RULES, TRIVY_RULES, CustomRule

_common_dir = next(p for p in Path(__file__).resolve().parents if (p / "common").is_dir()) / "common"
sys.path.insert(0, str(_common_dir))
import trivy_wrapper as _tw  # noqa: E402
from streams import reconfigure_streams  # noqa: E402

DETECTOR_NAME = "docker-trivy-wrapper"
TRIVY_VERSION_UNKNOWN = _tw.TRIVY_VERSION_UNKNOWN

# DS-0031 (secrets in ENV/build-args) is Trivy's own built-in check,
# found unexpectedly while verifying this plan at kickoff — excluded so
# 006 (Secret Detection) owns hardcoded-secret detection exclusively
# across every artifact type. Verified the exclusion mechanism actually
# works (a temp --ignorefile, not a real .trivyignore in the scanned
# repo, which could collide with one the target repo already has).
_EXCLUDED_TRIVY_CHECK_IDS = ("DS-0031",)

ScannerError = _tw.ScannerError


def run_trivy(path: str) -> dict:
    return _tw.run_trivy(path, excluded_check_ids=_EXCLUDED_TRIVY_CHECK_IDS)


def _finding_id(rule_id: str, file: str, start_line: int, end_line: int, discriminator: str) -> str:
    return _tw.finding_id("docker", rule_id, file, start_line, end_line, discriminator)


def map_trivy_misconfig(misconfig: dict, file: str, artifact_type: str, trivy_version: str) -> dict | None:
    """Maps one Trivy misconfiguration object to a finding.schema.json
    dict, using this plan's own hand-authored rule catalog (Trivy's own
    metadata has no CWE mapping). Returns None for a Trivy check ID
    this plan doesn't have a curated mapping for (Trivy's `config` scan
    has many more general-purpose checks beyond this plan's declared
    scope) — silently skipped, not an error."""
    return _tw.map_trivy_misconfig(
        misconfig,
        file,
        artifact_type,
        trivy_version,
        sub_skill="docker",
        rule_catalog=TRIVY_RULES,
        id_prefix="docker",
        detector_name=DETECTOR_NAME,
    )


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
    return _tw.resolve_target_path(artifact_name, target)


def scan_paths(paths: list[str], artifact_type: str = "dockerfile") -> list[dict]:
    """Scans one or more files/directories: Trivy's `config` mode for
    unpinned-base-image/root-user/missing-healthcheck, plus this
    module's own custom rules run directly against each Dockerfile
    Trivy discovered (its own JSON output tells us which files were
    recognized as Dockerfiles, even ones with zero Trivy findings).

    Invokes Trivy once per path, not once for the whole list — verified
    for real that `trivy config` rejects more than one target per
    invocation (see common/trivy_wrapper.py's run_trivy())."""
    findings = []
    for file, result, trivy_version in _tw.iter_scanned_files(paths, excluded_check_ids=_EXCLUDED_TRIVY_CHECK_IDS):
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
