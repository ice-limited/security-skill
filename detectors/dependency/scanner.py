"""Dependency detection: CVEs, known-malicious packages, license
compliance, and deprecated packages across lockfiles — via a thin
wrapper around the osv-scanner CLI (subprocess), not hand-written
per-ecosystem lockfile parsers.

Decided at the plan 008 kickoff: osv-scanner (github.com/google/
osv-scanner, Apache-2.0) already parses lockfiles for every ecosystem
in cpmatch's stack (npm, PyPI, Go, Maven, Packagist, Pub, SwiftURL) and
queries the OSV database (which itself aggregates GitHub Advisory,
PyPI Advisory, Go vulnerability DB, and the OpenSSF Malicious Packages
feed) — covering all four of this plan's declared scope items in one
tool, the same "adapt an existing tool" pattern as 006 (gitleaks) and
007 (Semgrep). See plans/008-dependency-skill.md and
meetings/2026-07-22-1700-plan-008-kickoff.md in the
security-skill-workspace repo for design rationale.

Every mapping choice below (severity bands, exit-code handling,
reference selection) was derived from *real* osv-scanner JSON output
sampled while implementing this plan, not guessed at from
documentation — see the plan's Implementation section for the exact
samples.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

_common_dir = next(p for p in Path(__file__).resolve().parents if (p / "common").is_dir()) / "common"
sys.path.insert(0, str(_common_dir))
from streams import reconfigure_streams  # noqa: E402

sys.path.insert(0, str(_common_dir.parent / "knowledge"))
import standards  # noqa: E402

DETECTOR_NAME = "dependency-osv-scanner-wrapper"

# "native" queries OSV directly, the exact backend already verified via
# its live API at kickoff; "deps.dev" (osv-scanner's own default) is a
# separate Google-operated proxy service whose own terms weren't
# separately verified — native avoids depending on a second service.
# Confirmed at implementation: both returned identical results for the
# same real fixture, so this is a deliberate simplicity choice, not a
# response to any observed difference in correctness.
DEFAULT_DATA_SOURCE = "native"

# No cpmatch org-approved/denied license list exists yet (kickoff
# decision) — a permissive-only baseline, revisited once a real policy
# exists.
DEFAULT_LICENSE_ALLOWLIST: tuple[str, ...] = ("MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause")

# osv-scanner's own --experimental-flag-deprecated-packages naming — v1
# ships it (per kickoff), but findings from it get a lower confidence
# ceiling (see _DEPRECATED_CONFIDENCE) reflecting that caveat.
DEFAULT_FLAG_DEPRECATED = True

_OWASP_SUPPLY_CHAIN_REF = {"standard": "OWASP-Top10", "id": "A03:2025"}
_MALICIOUS_PACKAGE_REF = {"standard": "CWE", "id": "CWE-506"}
_DEPRECATED_OR_LICENSE_REF = {"standard": "CWE", "id": "CWE-1104"}
_GENERIC_VULNERABLE_DEPENDENCY_REF = {"standard": "CWE", "id": "CWE-1395"}

# CVSS v3.1 official qualitative rating scale (first.org/cvss/v3-1/
# specification-document, Table 14), verified at kickoff, not guessed.
_CVSS_QUALITATIVE_TO_SEVERITY = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MODERATE": "Medium",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "NONE": "Info",
}

_MALICIOUS_CONFIDENCE = 85  # curated OpenSSF feed, not a heuristic match
_CVE_REVIEWED_CONFIDENCE = 80  # database_specific.github_reviewed is True
_CVE_UNREVIEWED_CONFIDENCE = 60
_DEPRECATED_CONFIDENCE = 50  # osv-scanner marks this feature experimental
_LICENSE_CONFIDENCE = 90  # deterministic string match against an allowlist


class ScannerError(Exception):
    """Raised for a real invocation failure (osv-scanner missing, a bad
    invocation) — fail loud rather than silently returning an empty
    findings list, which would look identical to "scanned cleanly, no
    issues found"."""


def _check_osv_scanner_available() -> None:
    if shutil.which("osv-scanner") is None:
        raise ScannerError(
            "osv-scanner CLI not found on PATH. Install with 'go install "
            "github.com/google/osv-scanner/v2/cmd/osv-scanner@latest', "
            "'brew install osv-scanner', or download a prebuilt binary "
            "(Scoop/WinGet on Windows) — see plans/008-dependency-skill.md."
        )


def run_osv_scanner(
    paths: list[str],
    license_allowlist: tuple[str, ...] = DEFAULT_LICENSE_ALLOWLIST,
    flag_deprecated: bool = DEFAULT_FLAG_DEPRECATED,
    data_source: str = DEFAULT_DATA_SOURCE,
) -> dict:
    """Invokes the real osv-scanner CLI and returns its parsed JSON
    output.

    `--recursive` is always passed — found as a real bug during the
    "test plan 008" round: without it, osv-scanner only looks for
    lockfiles directly in the given path(s), not in subdirectories, so
    pointing this at a repository root whose lockfile lives one level
    down (an extremely common real layout) silently finds nothing —
    a false "no vulnerabilities" rather than a crash, exactly the kind
    of failure a security detector must not have.

    Not mocked anywhere in this module or its tests — same
    discipline as 007's Semgrep wrapper (mocking an external, evolving
    tool's output would defeat the point of wrapping it)."""
    _check_osv_scanner_available()
    cmd = [
        "osv-scanner",
        "scan",
        "source",
        "--format",
        "json",
        "--recursive",
        "--allow-no-lockfiles",
        "--all-packages",
        "--data-source",
        data_source,
    ]
    if license_allowlist:
        cmd.append(f"--licenses={','.join(license_allowlist)}")
    if flag_deprecated:
        cmd.append("--experimental-flag-deprecated-packages")
    cmd.extend(paths)

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    except FileNotFoundError as e:  # pragma: no cover - _check_osv_scanner_available covers the common case
        raise ScannerError(f"failed to execute osv-scanner: {e}") from e

    # osv-scanner's exit code does not reliably distinguish "scanned
    # cleanly, no findings" from "scanned cleanly, findings present" —
    # verified for real at kickoff: the exact same vulnerable package
    # returned rc=0 in one run and rc=1 in another otherwise-identical
    # run, and manifest-file scans (go.mod, requirements.txt) returned
    # rc=0 even with dozens of vulnerabilities present. Only treat a
    # code outside {0, 1} as a real invocation failure (confirmed for
    # real: rc=127 for a bad path or unknown flag).
    if proc.returncode not in (0, 1):
        raise ScannerError(
            f"osv-scanner exited {proc.returncode}: {proc.stderr.strip()[-2000:]}"
        )

    try:
        output = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise ScannerError(f"osv-scanner did not return valid JSON: {e}") from e

    return output


def _severity_from_cvss_score(score: float) -> str:
    # CVSS v3.1 official qualitative rating scale, verified against
    # first.org's specification document, not guessed.
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score >= 0.1:
        return "Low"
    return "Info"


def _vuln_severity(vuln: dict, group_max_severity: str | None) -> str:
    """Prefers the vulnerability's own qualitative database_specific
    severity (direct, no computation needed); falls back to banding
    the group's numeric max_severity CVSS score when the qualitative
    field is absent (common for non-GitHub-reviewed advisories);
    defaults to Medium if neither is available."""
    qualitative = vuln.get("database_specific", {}).get("severity")
    if qualitative and qualitative.upper() in _CVSS_QUALITATIVE_TO_SEVERITY:
        return _CVSS_QUALITATIVE_TO_SEVERITY[qualitative.upper()]
    if group_max_severity:
        try:
            return _severity_from_cvss_score(float(group_max_severity))
        except ValueError:
            pass
    return "Medium"


def _cve_confidence(vuln: dict) -> int:
    if vuln.get("database_specific", {}).get("github_reviewed"):
        return _CVE_REVIEWED_CONFIDENCE
    return _CVE_UNREVIEWED_CONFIDENCE


def _cve_references(vuln: dict) -> list[dict]:
    refs = []
    for raw_cwe in vuln.get("database_specific", {}).get("cwe_ids", []):
        if standards.exists("CWE", raw_cwe):
            refs.append({"standard": "CWE", "id": raw_cwe})
    if not refs:
        refs.append(dict(_GENERIC_VULNERABLE_DEPENDENCY_REF))
    refs.append(dict(_OWASP_SUPPLY_CHAIN_REF))
    return refs


def _finding_id(rule_id: str, file: str, package_name: str, package_version: str, discriminator: str) -> str:
    key = f"{rule_id}|{file}|{package_name}|{package_version}|{discriminator}"
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
    return f"dependency-{digest}"


def _base_location(file: str) -> dict:
    # A dependency lockfile has no one stable "the vulnerable line" the
    # way source code does (a package can appear as a transitive
    # dependency in multiple places) — decided at kickoff to use
    # file-level placeholder lines rather than a misleadingly-precise
    # lookup. osv-scanner's own JSON output is package-name+version
    # granular, not line-granular, which confirms this isn't something
    # being left on the table by not trying harder.
    return {"file": file, "startLine": 1, "endLine": 1}


def _map_vulnerability(pkg: dict, vuln: dict, group_max_severity: str | None, file: str, artifact_type: str) -> dict:
    package = pkg["package"]
    name, version = package["name"], package.get("version", "unknown")
    vuln_id = vuln["id"]
    is_malicious = vuln_id.startswith("MAL-")

    rule_id = "dependency.malicious-package" if is_malicious else "dependency.cve"
    summary = vuln.get("summary") or vuln.get("details", "").splitlines()[0] if vuln.get("details") else f"Known issue in {name}@{version}"
    problem = summary or f"{name}@{version} is affected by {vuln_id}."
    references = [dict(_MALICIOUS_PACKAGE_REF), dict(_OWASP_SUPPLY_CHAIN_REF)] if is_malicious else _cve_references(vuln)

    if is_malicious:
        severity = "Critical"
        confidence = _MALICIOUS_CONFIDENCE
        impact = (
            f"{name}@{version} has been identified as malicious by the OpenSSF Malicious Packages "
            "project. If actually present in a deployed build, it could execute arbitrary "
            "attacker-controlled code."
        )
        recommendation = f"Remove {name}@{version} immediately and audit for signs of compromise."
    else:
        severity = _vuln_severity(vuln, group_max_severity)
        confidence = _cve_confidence(vuln)
        impact = vuln.get("details") or f"If exploitable, {vuln_id} could compromise systems depending on {name}@{version}."
        ref_urls = [r["url"] for r in vuln.get("references", []) if r.get("url")]
        recommendation = f"Upgrade {name} to a version that fixes {vuln_id}."
        if ref_urls:
            recommendation += f" See: {ref_urls[0]}"

    return {
        "findingId": _finding_id(rule_id, file, name, version, vuln_id),
        "ruleId": rule_id,
        "subSkill": "dependency",
        "artifactType": artifact_type,
        "title": problem[:200],
        "problem": problem,
        "impact": impact,
        "recommendation": recommendation,
        "references": references,
        "severity": severity,
        "confidence": confidence,
        "location": _base_location(file),
        "detectorSource": {"name": DETECTOR_NAME, "version": "osv-scanner"},
        "suppressed": False,
    }


def _map_deprecated(pkg: dict, file: str, artifact_type: str) -> dict:
    package = pkg["package"]
    name, version = package["name"], package.get("version", "unknown")
    return {
        "findingId": _finding_id("dependency.deprecated-package", file, name, version, "deprecated"),
        "ruleId": "dependency.deprecated-package",
        "subSkill": "dependency",
        "artifactType": artifact_type,
        "title": f"Deprecated package: {name}@{version}",
        "problem": f"{name}@{version} is marked as deprecated by its maintainer/registry.",
        "impact": (
            "Deprecated packages no longer receive security updates or maintenance, increasing "
            "the risk of unpatched vulnerabilities accumulating over time."
        ),
        "recommendation": f"Migrate away from {name} to an actively maintained alternative.",
        "references": [dict(_DEPRECATED_OR_LICENSE_REF), dict(_OWASP_SUPPLY_CHAIN_REF)],
        "severity": "Medium",
        "confidence": _DEPRECATED_CONFIDENCE,
        "location": _base_location(file),
        "detectorSource": {"name": DETECTOR_NAME, "version": "osv-scanner"},
        "suppressed": False,
    }


def _map_license_violation(pkg: dict, license_name: str, file: str, artifact_type: str) -> dict:
    package = pkg["package"]
    name, version = package["name"], package.get("version", "unknown")
    return {
        "findingId": _finding_id("dependency.license-violation", file, name, version, f"license:{license_name}"),
        "ruleId": "dependency.license-violation",
        "subSkill": "dependency",
        "artifactType": artifact_type,
        "title": f"License violation: {name}@{version} ({license_name})",
        "problem": f'{name}@{version} is licensed under "{license_name}", which is not in the approved license allowlist.',
        "impact": (
            "Using a dependency outside the approved license list may create legal/compliance "
            "risk (e.g. copyleft obligations) for downstream distribution of this software."
        ),
        "recommendation": (
            f'Review whether "{license_name}" is acceptable for this project\'s distribution model, '
            f"or replace {name} with an alternative under an approved license."
        ),
        "references": [dict(_DEPRECATED_OR_LICENSE_REF), dict(_OWASP_SUPPLY_CHAIN_REF)],
        "severity": "Medium",
        "confidence": _LICENSE_CONFIDENCE,
        "location": _base_location(file),
        "detectorSource": {"name": DETECTOR_NAME, "version": "osv-scanner"},
        "suppressed": False,
    }


def _group_max_severity_lookup(groups: list[dict]) -> dict[str, str]:
    lookup: dict[str, str] = {}
    for group in groups:
        max_severity = group.get("max_severity")
        if not max_severity:
            continue
        for vuln_id in group.get("ids", []) + group.get("aliases", []):
            lookup[vuln_id] = max_severity
    return lookup


def _map_package(pkg: dict, file: str, artifact_type: str) -> list[dict]:
    findings = []
    severity_lookup = _group_max_severity_lookup(pkg.get("groups", []))
    for vuln in pkg.get("vulnerabilities", []):
        findings.append(_map_vulnerability(pkg, vuln, severity_lookup.get(vuln["id"]), file, artifact_type))
    if pkg.get("package", {}).get("deprecated"):
        findings.append(_map_deprecated(pkg, file, artifact_type))
    for license_name in pkg.get("license_violations", []):
        findings.append(_map_license_violation(pkg, license_name, file, artifact_type))
    return findings


def scan_paths(
    paths: list[str],
    artifact_type: str = "package-lock",
    license_allowlist: tuple[str, ...] = DEFAULT_LICENSE_ALLOWLIST,
    flag_deprecated: bool = DEFAULT_FLAG_DEPRECATED,
    data_source: str = DEFAULT_DATA_SOURCE,
) -> list[dict]:
    """Scans one or more files/directories with osv-scanner and returns
    findings matching finding.schema.json."""
    output = run_osv_scanner(
        [str(p) for p in paths],
        license_allowlist=license_allowlist,
        flag_deprecated=flag_deprecated,
        data_source=data_source,
    )
    findings = []
    for result in output.get("results") or []:
        file = result.get("source", {}).get("path", "unknown")
        for pkg in result.get("packages", []):
            findings.extend(_map_package(pkg, file, artifact_type))
    return findings


def scan_file(path: Path, artifact_type: str = "package-lock", **kwargs) -> list[dict]:
    return scan_paths([str(path)], artifact_type=artifact_type, **kwargs)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Scan directory/lockfile(s) for dependency issues via osv-scanner.")
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--artifact-type", default="package-lock")
    parser.add_argument("--data-source", default=DEFAULT_DATA_SOURCE)
    args = parser.parse_args(argv)

    try:
        findings = scan_paths(args.paths, artifact_type=args.artifact_type, data_source=args.data_source)
    except ScannerError as e:
        print(f"SCANNER ERROR: {e}", file=sys.stderr)
        return 1

    print(json.dumps(findings, indent=2))
    return 0


if __name__ == "__main__":
    reconfigure_streams()
    sys.exit(main())
