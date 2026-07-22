"""Open redirect (CWE-601) detection via Semgrep — the one class in
CONTEXT.md §7's API sub-skill scope with zero overlap with 007 (Code
Review, in-scope CWEs: 77/78/79/89/918 only) or 023 (AuthN/AuthZ),
verified at the plan 012 kickoff.

Verified empirically at implementation (not assumed from a registry
search): no single pack covers both Express (JS) and Flask (Python) —
`p/owasp-top-ten` (007's own pack) has
`javascript.express.security.audit.express-open-redirect.express-open-redirect`,
CWE-601, but nothing for Python; `p/security-audit` adds
`python.flask.security.open-redirect.open-redirect`, CWE-601, for
Flask. Both packs are invoked and merged.

A real duplicate-finding risk was found running both configs together
against the same fixture, similar in shape to the 007/023 JWT
duplicate 007's own scanner.py documents: `p/security-audit` fires
*two* distinct check_ids
(`javascript.express.security.audit.possible-user-input-redirect.unknown-value-in-redirect`
and `express-open-redirect` above) on the exact same file/line for one
Express redirect call. Unlike the 007/023 case (two independently
-shipped sub-skill scanners that couldn't easily share a ruleId),
this is all within one detector, so it's fixed directly: every known
open-redirect check_id is mapped to the single `api.open-redirect`
ruleId via `rule_id_overrides` (same mechanism 023 already uses for
its own JWT check_ids), and results are de-duplicated by
(file, startLine, endLine) before being returned — verified this
collapses the real duplicate found above to exactly one finding.

Results are filtered by raw `metadata.cwe` *before* calling
common/semgrep_wrapper.py's `map_result_to_finding` (rather than
scanning everything a broad pack matches and filtering afterward, the
way 007 does for its own in-scope CWEs) — `map_result_to_finding`
raises `ScannerError` if a result's CWE doesn't resolve in
knowledge/cwe.json, which a 217-rule pack like `p/owasp-top-ten` could
easily hit for an out-of-scope rule this module was never going to
report anyway. Pre-filtering the raw results avoids that crash risk
entirely rather than relying on every incidental match resolving.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_common_dir = next(p for p in Path(__file__).resolve().parents if (p / "common").is_dir()) / "common"
sys.path.insert(0, str(_common_dir))
import semgrep_wrapper as _sw  # noqa: E402
from streams import reconfigure_streams  # noqa: E402

DETECTOR_NAME = "api-open-redirect-semgrep-wrapper"

_CONFIGS = ("p/owasp-top-ten", "p/security-audit")

_RULE_ID_OVERRIDES = {
    "javascript.express.security.audit.express-open-redirect.express-open-redirect": "api.open-redirect",
    "javascript.express.security.audit.possible-user-input-redirect.unknown-value-in-redirect": "api.open-redirect",
    "python.flask.security.open-redirect.open-redirect": "api.open-redirect",
}

ScannerError = _sw.ScannerError


def _is_open_redirect(result: dict) -> bool:
    metadata = result.get("extra", {}).get("metadata", {})
    return any(str(c).startswith("CWE-601") for c in metadata.get("cwe", []))


def scan_paths(paths: list[str], artifact_type: str = "source-code") -> list[dict]:
    """Scans one or more files/directories for open-redirect (CWE-601)
    patterns, merging `p/owasp-top-ten` (Express/JS coverage) and
    `p/security-audit` (Flask/Python coverage), de-duplicated by
    (file, startLine, endLine) across both configs and every check_id
    each config might use for the same underlying weakness."""
    str_paths = [str(p) for p in paths]
    findings: list[dict] = []
    seen: set[tuple[str, int, int]] = set()

    for config in _CONFIGS:
        output = _sw.run_semgrep(str_paths, config)
        version = output.get("version", "unknown")
        for result in output.get("results", []):
            if not _is_open_redirect(result):
                continue
            finding = _sw.map_result_to_finding(
                result,
                artifact_type,
                version,
                sub_skill="api",
                rule_id_prefix="api",
                id_prefix="api",
                detector_name=DETECTOR_NAME,
                rule_id_overrides=_RULE_ID_OVERRIDES,
            )
            loc = finding["location"]
            key = (loc["file"], loc["startLine"], loc["endLine"])
            if key in seen:
                continue
            seen.add(key)
            findings.append(finding)

    return findings


def scan_file(path: Path, artifact_type: str = "source-code") -> list[dict]:
    return scan_paths([str(path)], artifact_type=artifact_type)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Scan file(s)/directory for open-redirect (CWE-601) via Semgrep.")
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--artifact-type", default="source-code")
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
