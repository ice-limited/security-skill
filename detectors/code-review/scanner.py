"""Code review detection: Injection & Request-Forgery classes (SQLi,
XSS, SSRF, Command Injection), via a thin wrapper around the Semgrep
CLI (subprocess), not a from-scratch AST/regex engine.

Decided at the plan 007 kickoff: cpmatch's stack is 13+ languages, so
building and maintaining per-language taint-tracking from scratch was
never a realistic MVP — wraps Semgrep instead, mirroring how 006
adapted gitleaks (an existing tool, one level up: a whole engine, not
just patterns). Semgrep CLI/engine is LGPL 2.1; its community/registry
rules are "Semgrep Rules License v1.0" (internal-business-use permitted,
redistribution/service-offering forbidden) — both verified at kickoff,
not assumed. See plans/007-code-review-skill.md and
meetings/2026-07-22-1430-plan-007-kickoff.md in the
security-skill-workspace repo for design rationale.

The actual subprocess/mapping logic lives in common/semgrep_wrapper.py
— extracted there once 023's Semgrep-subset half
(detectors/auth/semgrep_detector.py) needed the same logic, per plan
005's "shared module once a second consumer exists" precedent. This
module is now a thin, subSkill-specific wrapper over it: which rule
pack (`p/owasp-top-ten`, chosen empirically — see this plan's
Implementation section) and which subSkill/ruleId namespace
("code-review").
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_common_dir = next(p for p in Path(__file__).resolve().parents if (p / "common").is_dir()) / "common"
sys.path.insert(0, str(_common_dir))
import semgrep_wrapper as _sw  # noqa: E402
from streams import reconfigure_streams  # noqa: E402

DETECTOR_NAME = "code-review-semgrep-wrapper"

# p/owasp-top-ten: verified at implementation (real `semgrep --config`
# runs, not assumed) to catch all four in-scope classes — SQLi, XSS,
# SSRF, and Command Injection — across at least Python and JavaScript
# fixtures. Exact per-language coverage across cpmatch's full stack is
# not exhaustively verified (see plan's Open Questions); this is the
# starting default, overridable per call.
DEFAULT_CONFIG = "p/owasp-top-ten"

# 007's declared scope is exactly these four classes (CWE-77/78 Command
# Injection, CWE-79 XSS, CWE-89 SQLi, CWE-918 SSRF) — but p/owasp-top-ten
# is a broad, OWASP-Top10-themed pack, not a narrowly-scoped one, and
# also fires on unrelated categories it happens to include (e.g. a JWT
# weak-algorithm check, CWE-327 Cryptographic Failures). Found for real
# while testing this plan: scanning the same file with both this
# module (p/owasp-top-ten) and detectors/auth/semgrep_detector.py
# (p/jwt) produced two byte-identical-location findings for the same
# JWT bug under two different ruleIds — a real duplicate a downstream
# report would show twice, since decision/'s dedup key starts with
# ruleId and these differ. Filtering to 007's own declared CWE scope
# fixes this at the source: the JWT finding is 023's job, not 007's.
_IN_SCOPE_CWES = frozenset({"CWE-77", "CWE-78", "CWE-79", "CWE-89", "CWE-918"})

ScannerError = _sw.ScannerError
run_semgrep = _sw.run_semgrep


def _severity(result_severity: str, impact: str | None) -> str:
    return _sw.severity(result_severity, impact)


def _confidence(result_confidence: str | None) -> int:
    return _sw.confidence(result_confidence)


def _extract_references(metadata: dict) -> list[dict]:
    return _sw.extract_references(metadata)


def _rule_id(check_id: str) -> str:
    # Semgrep's check_id is already lowercase, dot-namespaced
    # (e.g. "python.lang.security.audit.subprocess-shell-true.
    # subprocess-shell-true") — matches finding.schema.json's ruleId
    # regex as-is once prefixed, no further slugging needed (verified
    # against real check_ids sampled at implementation, not assumed).
    return f"code-review.{check_id}"


def _finding_id(rule_id: str, file: str, start_line: int, end_line: int, start_byte: int, end_byte: int) -> str:
    return _sw.finding_id("code-review", rule_id, file, start_line, end_line, start_byte, end_byte)


def map_result_to_finding(result: dict, artifact_type: str, semgrep_version: str) -> dict:
    """Maps one Semgrep result object to a finding.schema.json-shaped
    dict, namespaced under the "code-review" subSkill/ruleId prefix."""
    return _sw.map_result_to_finding(
        result,
        artifact_type,
        semgrep_version,
        sub_skill="code-review",
        rule_id_prefix="code-review",
        id_prefix="code-review",
        detector_name=DETECTOR_NAME,
    )


def _is_in_scope(finding: dict) -> bool:
    return any(ref["standard"] == "CWE" and ref["id"] in _IN_SCOPE_CWES for ref in finding["references"])


def scan_paths(paths: list[str], artifact_type: str = "source-code", config: str = DEFAULT_CONFIG) -> list[dict]:
    """Scans one or more files/directories with Semgrep and returns
    findings matching finding.schema.json — filtered to this plan's
    declared scope (see _IN_SCOPE_CWES) so a broad pack's out-of-scope
    matches (e.g. a JWT check p/owasp-top-ten also happens to include)
    don't leak into code-review's output and duplicate another
    sub-skill's finding."""
    findings = _sw.scan_paths(
        [str(p) for p in paths],
        config,
        artifact_type,
        sub_skill="code-review",
        rule_id_prefix="code-review",
        id_prefix="code-review",
        detector_name=DETECTOR_NAME,
    )
    return [f for f in findings if _is_in_scope(f)]


def scan_file(path: Path, artifact_type: str = "source-code", config: str = DEFAULT_CONFIG) -> list[dict]:
    return scan_paths([str(path)], artifact_type=artifact_type, config=config)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Scan file(s)/directory for injection/SSRF-class vulnerabilities via Semgrep.")
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--config", default=DEFAULT_CONFIG)
    parser.add_argument("--artifact-type", default="source-code")
    args = parser.parse_args(argv)

    try:
        findings = scan_paths(args.paths, artifact_type=args.artifact_type, config=args.config)
    except ScannerError as e:
        print(f"SCANNER ERROR: {e}", file=sys.stderr)
        return 1

    print(json.dumps(findings, indent=2))
    return 0


if __name__ == "__main__":
    reconfigure_streams()
    sys.exit(main())
