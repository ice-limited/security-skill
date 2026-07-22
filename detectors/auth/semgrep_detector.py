"""AuthN/AuthZ Semgrep-subset detector — the deterministic half of 023,
deferred until 007 was implemented so its "invoke semgrep, parse JSON,
map to schema" core logic could be reused rather than rewritten (see
plans/023-authn-authz-code-review-skill.md's sequencing note). That
shared logic now lives in common/semgrep_wrapper.py.

This module is deliberately narrow, not a general authz/authn scanner:
verified at implementation (real `semgrep --config=p/jwt` runs against
synthetic fixtures, plus checking the pack's own per-language rule
counts) that Semgrep's registry coverage for this class is real but
thin, concentrated almost entirely on JWT signature/algorithm bypass
(`p/jwt`: 6 JS rules, 3 Python, 3 Go, 3 Java — nothing at all for
Kotlin, Swift, Dart, PHP). Everything this module *doesn't* catch is
still covered by playbook.py's checklist, which is the primary
mechanism for this sub-skill, not a fallback — see the kickoff's
"hybrid, not an even split" design.

`_RULE_ID_OVERRIDES` maps specific, individually-verified check_ids to
the matching checklist.json item's own ruleId, so the same underlying
weakness gets the same ruleId regardless of whether the playbook or
this deterministic detector caught it (only `detectorSource` differs).
Go's none-alg rule was verified and added during the "test plan 023"
round; Java's 3 rules were counted but never individually triggered
(no fixture shape found that fires them) — any check_id not in this
table falls back to the generic `auth.{check_id}` naming, same as 007 —
it will still produce a valid finding as long as its own CWE/OWASP
metadata resolves in the knowledge base.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_common_dir = next(p for p in Path(__file__).resolve().parents if (p / "common").is_dir()) / "common"
sys.path.insert(0, str(_common_dir))
import semgrep_wrapper as _sw  # noqa: E402
from streams import reconfigure_streams  # noqa: E402

DETECTOR_NAME = "auth-semgrep-wrapper"

# Verified at implementation: real semgrep --config=p/jwt runs against
# synthetic Python/JS fixtures actually fired these two distinct
# patterns. p/owasp-top-ten (007's pack) also happened to catch the
# jwt-none-alg case, but p/jwt is used here as the narrower, more
# clearly-scoped config for this sub-skill rather than reusing 007's
# broader pack and filtering its unrelated injection findings out.
DEFAULT_CONFIG = "p/jwt"

_RULE_ID_OVERRIDES = {
    # CWE-287 (Improper Authentication) — matches checklist.json's
    # auth.jwt-signature-not-verified exactly.
    "python.jwt.security.unverified-jwt-decode.unverified-jwt-decode": "auth.jwt-signature-not-verified",
    # CWE-327 (Broken/Risky Cryptographic Algorithm) — a distinct CWE
    # from the above per Semgrep's own metadata (verified at
    # implementation, not assumed to be the same weakness just because
    # both are "JWT bugs") — matches auth.jwt-weak-algorithm.
    "python.jwt.security.jwt-none-alg.jwt-python-none-alg": "auth.jwt-weak-algorithm",
    "javascript.jsonwebtoken.security.jwt-none-alg.jwt-none-alg": "auth.jwt-weak-algorithm",
    # Found during the "test plan 023" round: p/jwt also has a Go rule
    # for the exact same none-alg pattern (verified with a real
    # golang-jwt fixture, not assumed from the pack's rule count alone)
    # — added for consistency so the same weakness gets the same
    # ruleId across languages, not just Python/JS.
    "go.jwt-go.security.jwt-none-alg.jwt-go-none-algorithm": "auth.jwt-weak-algorithm",
}

ScannerError = _sw.ScannerError
run_semgrep = _sw.run_semgrep


def map_result_to_finding(result: dict, artifact_type: str, semgrep_version: str) -> dict:
    return _sw.map_result_to_finding(
        result,
        artifact_type,
        semgrep_version,
        sub_skill="auth",
        rule_id_prefix="auth",
        id_prefix="auth",
        detector_name=DETECTOR_NAME,
        rule_id_overrides=_RULE_ID_OVERRIDES,
    )


def scan_paths(paths: list[str], artifact_type: str = "source-code", config: str = DEFAULT_CONFIG) -> list[dict]:
    """Scans one or more files/directories with Semgrep for the narrow
    JWT-bypass patterns this sub-skill's registry coverage actually
    has, returning findings matching finding.schema.json."""
    return _sw.scan_paths(
        [str(p) for p in paths],
        config,
        artifact_type,
        sub_skill="auth",
        rule_id_prefix="auth",
        id_prefix="auth",
        detector_name=DETECTOR_NAME,
        rule_id_overrides=_RULE_ID_OVERRIDES,
    )


def scan_file(path: Path, artifact_type: str = "source-code", config: str = DEFAULT_CONFIG) -> list[dict]:
    return scan_paths([str(path)], artifact_type=artifact_type, config=config)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Scan file(s)/directory for JWT signature/algorithm bypass via Semgrep.")
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
