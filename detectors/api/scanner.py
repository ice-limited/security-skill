"""OpenAPI spec-lint detection: a curated subset of
`@stoplight/spectral-owasp-ruleset` (MIT), via a thin wrapper around the
Spectral CLI (subprocess) — the first tool in this project needing a
non-Python runtime (Node.js/npm), decided at the plan 012 kickoff after
verifying vacuum (Go binary) and a hand-rolled Python alternative; see
plans/012-api-skill.md and meetings/2026-07-22-2200-plan-012-kickoff.md
in the security-skill-workspace repo.

Kept self-contained here (not extracted to common/) per plan 005's
"share once a second consumer exists" precedent — no other sub-skill
needs Spectral.

**Setup**: `npm install` inside this directory (installs
`@stoplight/spectral-cli` + `@stoplight/spectral-owasp-ruleset` into a
local `node_modules/`, pinned via package.json) before running this
module — mirrors `pip install -r requirements.txt` for the Python-tool
detectors (009/011).

Invocation is `npx spectral lint <file> --ruleset .spectral.yaml
--format json --fail-severity=hint`, run with this directory as `cwd`
so `npx` resolves the locally-installed CLI/ruleset rather than
assuming (or silently falling back to fetching) a global install —
verified for real that a bare `npx --yes @stoplight/spectral-cli lint
...` from an arbitrary directory does NOT resolve the ruleset's
`extends` target (it only fetches the single named package, not its
own "peer" ruleset dependency), so a local `node_modules` + explicit
`--ruleset` path is required, not optional.

**Exit-code contract, verified empirically, not assumed** — a fourth
distinct convention among this project's four wrapped external tools
(Semgrep: nonzero-is-failure; Trivy: always-zero-check-content; Checkov:
0=clean, 1=findings, 2=CLI error; Spectral, here: 0=ran clean at or
above --fail-severity, 1=findings at or above --fail-severity **or** a
malformed input file reported as `code: "parser"` pseudo-findings in
the same JSON array — not a crash, exit 2=genuine invocation error,
e.g. file not found). `--fail-severity=hint` is always passed so exit
0 vs 1 tracks "any finding present at all" consistently, but this
module parses the JSON body regardless of exit 0/1 rather than
branching on it, and only treats exit >=2 (or non-JSON stdout) as a
`ScannerError`. `code: "parser"` pseudo-findings are not a distinct
error case to handle — they simply don't match any curated code in
`rules.py` and are silently skipped, same as any other uncurated
Spectral code.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

from rules import SPECTRAL_CODE_TO_RULE

_common_dir = next(p for p in Path(__file__).resolve().parents if (p / "common").is_dir()) / "common"
sys.path.insert(0, str(_common_dir))
from streams import reconfigure_streams  # noqa: E402

DETECTOR_NAME = "api-spectral-wrapper"
API_DIR = Path(__file__).parent
RULESET_PATH = API_DIR / ".spectral.yaml"

_SPEC_EXTENSIONS = (".yaml", ".yml", ".json")
_SPEC_TOP_LEVEL_KEYS = ("openapi", "swagger")


class ScannerError(Exception):
    """Raised for a real invocation failure (Spectral/its OWASP ruleset
    not installed, npx missing, a bad path, or a non-JSON/crashed
    invocation) — fail loud rather than silently returning an empty
    findings list, which would look identical to "scanned cleanly, no
    issues found"."""


def _check_spectral_available() -> None:
    if shutil.which("npx") is None:
        raise ScannerError(
            "npx not found on PATH. Install Node.js (https://nodejs.org) — see plans/012-api-skill.md."
        )
    spectral_pkg = API_DIR / "node_modules" / "@stoplight" / "spectral-cli"
    ruleset_pkg = API_DIR / "node_modules" / "@stoplight" / "spectral-owasp-ruleset"
    if not spectral_pkg.is_dir() or not ruleset_pkg.is_dir():
        raise ScannerError(
            f"Spectral CLI/OWASP ruleset not installed in {API_DIR}. Run 'npm install' in that directory first "
            "— see plans/012-api-skill.md."
        )


def _spectral_version() -> str:
    try:
        pkg = json.loads((API_DIR / "node_modules" / "@stoplight" / "spectral-cli" / "package.json").read_text(encoding="utf-8"))
        return str(pkg.get("version", "unknown"))
    except (OSError, json.JSONDecodeError):
        return "unknown"


def run_spectral(path: str) -> list[dict]:
    """Invokes the real Spectral CLI against one file and returns its
    parsed JSON violation list. Not mocked anywhere in this module's
    own tests — matches this project's standing "invoke the real tool"
    testing discipline."""
    _check_spectral_available()
    cmd = [
        "npx",
        "spectral",
        "lint",
        str(Path(path).resolve()),
        "--ruleset",
        str(RULESET_PATH.resolve()),
        "--format",
        "json",
        "--fail-severity=hint",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", cwd=str(API_DIR))
    except FileNotFoundError as e:  # pragma: no cover - _check_spectral_available covers the common case
        raise ScannerError(f"failed to execute npx/spectral: {e}") from e

    if proc.returncode >= 2:
        raise ScannerError(f"spectral exited {proc.returncode} for {path!r}: {proc.stderr.strip()[-2000:]}")

    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise ScannerError(f"spectral did not return valid JSON for {path!r}: {e}") from e


def _finding_id(rule_id: str, file: str, start_line: int, end_line: int, code: str) -> str:
    key = f"{rule_id}|{file}|{start_line}|{end_line}|{code}"
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
    return f"api-{digest}"


def map_violation_to_finding(violation: dict, file: str, spectral_version: str) -> dict | None:
    """Maps one Spectral violation object to a finding.schema.json dict,
    using this plan's own hand-authored rule catalog (the ruleset's own
    codes carry an OWASP category tag but no CWE). Returns None for an
    uncurated code (either a real Spectral rule this plan didn't curate,
    or a `code: "parser"` pseudo-finding for a malformed input file) —
    silently skipped, not an error, same precedent as 009/010/011."""
    rule = SPECTRAL_CODE_TO_RULE.get(violation.get("code"))
    if rule is None:
        return None

    rng = violation.get("range", {})
    start = rng.get("start", {})
    end = rng.get("end", {})
    # Spectral's range is 0-indexed (both line and character);
    # finding.schema.json requires 1-indexed startLine/startColumn
    # (minimum: 1) — verified for real against sampled Spectral JSON
    # output, not assumed.
    start_line = int(start.get("line", 0)) + 1
    end_line = int(end.get("line", start.get("line", 0))) + 1

    location: dict = {"file": file, "startLine": start_line, "endLine": end_line}
    if "character" in start:
        location["startColumn"] = int(start["character"]) + 1
    if "character" in end:
        location["endColumn"] = int(end["character"]) + 1
    path_segments = violation.get("path") or []
    if path_segments:
        location["astNodePath"] = ".".join(str(seg) for seg in path_segments)

    return {
        "findingId": _finding_id(rule.rule_id, file, start_line, end_line, violation["code"]),
        "ruleId": rule.rule_id,
        "subSkill": "api",
        "artifactType": "api-spec",
        "title": rule.title,
        "problem": rule.problem,
        "impact": rule.impact,
        "recommendation": rule.recommendation,
        "references": rule.references,
        "severity": rule.severity,
        "confidence": rule.confidence,
        "location": location,
        "detectorSource": {"name": DETECTOR_NAME, "version": spectral_version},
        "suppressed": False,
    }


def _looks_like_openapi_spec(path: Path) -> bool:
    """Cheap top-level-key sniff so pointing this detector at a
    directory doesn't feed unrelated YAML/JSON (docker-compose.yml, a
    Kubernetes manifest, package.json, ...) into Spectral. Skips
    (returns False) on any parse failure rather than raising — this is
    a discovery heuristic, not the real lint invocation, so a directory
    containing an unrelated malformed file shouldn't block discovery of
    the real spec sitting next to it."""
    if path.suffix.lower() not in _SPEC_EXTENSIONS:
        return False
    try:
        import yaml  # local import: only needed for this discovery heuristic

        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return False
    return isinstance(doc, dict) and any(key in doc for key in _SPEC_TOP_LEVEL_KEYS)


def _discover_spec_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    return sorted(p for p in path.rglob("*") if p.is_file() and _looks_like_openapi_spec(p))


def scan_paths(paths: list[str]) -> list[dict]:
    """Scans one or more OpenAPI spec files (or directories, searched
    for files that look like an OpenAPI spec — see
    `_looks_like_openapi_spec`) via Spectral, one invocation per
    discovered file (not one invocation for a whole directory/glob —
    matches 009/010/011's own "one tool invocation per path" precedent,
    avoiding any assumption about how Spectral would behave with
    multiple positional file arguments, which was not tested)."""
    version = _spectral_version()
    findings: list[dict] = []
    for raw_path in paths:
        p = Path(raw_path)
        if not p.exists():
            raise ScannerError(f"path does not exist: {raw_path}")
        for spec_file in _discover_spec_files(p):
            violations = run_spectral(str(spec_file))
            for violation in violations:
                mapped = map_violation_to_finding(violation, str(spec_file), version)
                if mapped is not None:
                    findings.append(mapped)
    return findings


def scan_file(path: Path) -> list[dict]:
    return scan_paths([str(path)])


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Scan OpenAPI spec file(s)/directory for OWASP API Security Top 10 issues via Spectral.")
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
