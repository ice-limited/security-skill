"""Tests for the code-review Semgrep wrapper: real subprocess
invocation (not mocked — see plans/007-code-review-skill.md's kickoff
note on why), result-to-finding mapping, schema conformance, and error
handling.

Requires the real `semgrep` CLI on PATH (pip install semgrep) and
network access for its registry config on first run. Run with:
python3 -m unittest test_scanner -v (from inside detectors/code-review/).
"""

from __future__ import annotations

import io
import json
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import scanner
from scanner import ScannerError

DETECTOR_DIR = Path(__file__).parent
SECURITY_SKILL_DIR = next(p for p in DETECTOR_DIR.resolve().parents if (p / "common").is_dir())
SCHEMA_DIR = SECURITY_SKILL_DIR / "schema"

sys.path.insert(0, str(SECURITY_SKILL_DIR / "common"))
from schema_validation import validate_against_schema  # noqa: E402

sys.path.insert(0, str(SECURITY_SKILL_DIR / "knowledge"))
import standards  # noqa: E402

# Deliberately obvious/synthetic vulnerable snippets, not real-world
# code — enough for Semgrep's p/owasp-top-ten pack (verified at
# implementation) to actually fire, not just "look" vulnerable.
SQLI_CMDI_SSRF_PY = '''import subprocess
import requests

def get_user(request, db):
    user_id = request.GET.get("id")
    query = "SELECT * FROM users WHERE id = " + user_id
    return db.execute(query)

def run_backup(request):
    filename = request.GET.get("filename")
    subprocess.run("tar -czf backup.tar.gz " + filename, shell=True)

def fetch_url(request):
    target = request.GET.get("url")
    return requests.get(target)
'''

XSS_JS = """app.get('/greet', function (req, res) {
  res.send("<div>" + req.query.bio + "</div>");
});
"""

# Out of 007's declared scope (CWE-327, Cryptographic Failures, not
# SQLi/XSS/SSRF/CmdInj) but p/owasp-top-ten fires on it anyway — see
# test_out_of_scope_pack_match_is_filtered_out.
JWT_WEAK_ALG_JS = """const jwt = require('jsonwebtoken');
function verifyToken2(token) {
  return jwt.verify(token, getSecret(), { algorithms: ['none'] });
}
"""

# Added during the "test plan 007" round to verify real coverage beyond
# Python/JS (previously only asserted, not tested) — SQLi in Go and PHP.
SQLI_GO = """package main

import (
	"database/sql"
	"net/http"
)

func getUser(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	id := r.URL.Query().Get("id")
	query := "SELECT * FROM users WHERE id = " + id
	db.Query(query)
}
"""

SQLI_PHP = """<?php
function getUser($conn, $id) {
    $query = "SELECT * FROM users WHERE id = " . $_GET['id'];
    return mysqli_query($conn, $query);
}
"""

CLEAN_PY = "def add(a, b):\n    return a + b\n"


def _semgrep_available() -> bool:
    return shutil.which("semgrep") is not None


@unittest.skipUnless(_semgrep_available(), "requires the real semgrep CLI on PATH")
class PerClassDetectionTests(unittest.TestCase):
    """Real semgrep subprocess calls — mirrors detectors/secret's
    per-rule detection tests, but for a wrapped external engine."""

    def test_finds_sql_command_injection_and_ssrf_in_python(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "vuln.py"
            path.write_text(SQLI_CMDI_SSRF_PY, encoding="utf-8")
            findings = scanner.scan_file(path)
        rule_ids = {f["ruleId"] for f in findings}
        self.assertTrue(any("sql-injection" in r for r in rule_ids), rule_ids)
        self.assertTrue(any("subprocess" in r or "command" in r for r in rule_ids), rule_ids)
        self.assertTrue(any("ssrf" in r for r in rule_ids), rule_ids)
        for f in findings:
            self.assertTrue(f["ruleId"].startswith("code-review."))
            self.assertEqual(f["subSkill"], "code-review")

    def test_finds_xss_in_javascript(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.js"
            path.write_text(XSS_JS, encoding="utf-8")
            findings = scanner.scan_file(path)
        self.assertTrue(any("xss" in f["ruleId"] or "html" in f["ruleId"] for f in findings), findings)

    def test_finds_sqli_in_go(self) -> None:
        # Closes a gap: 007's Open Questions previously only claimed
        # broader-than-Python/JS coverage without verifying it.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "vuln.go"
            path.write_text(SQLI_GO, encoding="utf-8")
            findings = scanner.scan_file(path)
        self.assertTrue(any("sql" in f["ruleId"] for f in findings), findings)
        for f in findings:
            self.assertIn({"standard": "CWE", "id": "CWE-89"}, f["references"])

    def test_finds_sqli_in_php(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "vuln.php"
            path.write_text(SQLI_PHP, encoding="utf-8")
            findings = scanner.scan_file(path)
        self.assertTrue(any("sql" in f["ruleId"] for f in findings), findings)

    def test_clean_file_produces_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "clean.py"
            path.write_text(CLEAN_PY, encoding="utf-8")
            findings = scanner.scan_file(path)
        self.assertEqual(findings, [])

    def test_out_of_scope_pack_match_is_filtered_out(self) -> None:
        # Found while testing this plan, not hypothetical: p/owasp-top-ten
        # (a broad, OWASP-Top10-themed pack) also fires on a JWT
        # weak-algorithm check (CWE-327, Cryptographic Failures) that is
        # entirely outside 007's declared scope (SQLi/XSS/SSRF/CmdInj).
        # Scanning the same file with detectors/auth/semgrep_detector.py
        # (p/jwt) produced a byte-identical-location finding under a
        # different ruleId ("auth.jwt-weak-algorithm") — a real
        # duplicate a combined report would show twice, since
        # decision/'s dedup key starts with ruleId. Must be filtered
        # out here, not left to a downstream layer to notice.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.js"
            path.write_text(JWT_WEAK_ALG_JS, encoding="utf-8")
            findings = scanner.scan_file(path)
        self.assertEqual(findings, [], f"out-of-scope CWE-327 finding leaked through: {findings}")


@unittest.skipUnless(_semgrep_available(), "requires the real semgrep CLI on PATH")
class SchemaConformanceTests(unittest.TestCase):
    def test_real_findings_validate_against_finding_schema(self) -> None:
        schema = json.loads((SCHEMA_DIR / "finding.schema.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "vuln.py"
            path.write_text(SQLI_CMDI_SSRF_PY, encoding="utf-8")
            findings = scanner.scan_file(path)
        self.assertGreaterEqual(len(findings), 1)
        for f in findings:
            errors = validate_against_schema(schema, f)
            self.assertEqual(errors, [], f"{f['ruleId']} finding is not schema-valid: {errors}")


@unittest.skipUnless(_semgrep_available(), "requires the real semgrep CLI on PATH")
class ErrorHandlingTests(unittest.TestCase):
    def test_bad_config_raises_scanner_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "clean.py"
            path.write_text(CLEAN_PY, encoding="utf-8")
            with self.assertRaises(ScannerError):
                scanner.scan_file(path, config="p/this-pack-does-not-exist-xyz")

    def test_nonexistent_path_raises_scanner_error(self) -> None:
        # Real semgrep behavior (verified at implementation, carefully
        # — an earlier check via a shell pipeline through `tail`
        # misreported this as exit 0 due to $? reflecting tail's exit
        # code, not semgrep's): a bad scanning root exits nonzero
        # (rc=2) with an error-level entry in `errors` — caught here by
        # the returncode check in run_semgrep.
        with self.assertRaises(ScannerError):
            scanner.scan_paths(["/tmp/definitely-does-not-exist-xyz-007.py"])

    def test_partial_parse_failure_on_one_file_does_not_discard_other_results(self) -> None:
        # Verified for real at implementation: scanning a directory
        # where one file fails to parse (warn-level "PartialParsing")
        # alongside a valid file returns rc=0 with a non-empty
        # `errors` array *and* real results for the good file. Must
        # not raise and discard those results — a single unrelated
        # broken file shouldn't nuke an entire repo scan's findings.
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "good.py").write_text(SQLI_CMDI_SSRF_PY, encoding="utf-8")
            (Path(tmp) / "bad.py").write_text("def f(:::: not valid python @#$%\n", encoding="utf-8")
            findings = scanner.scan_paths([tmp])
        self.assertGreaterEqual(len(findings), 1)

    def test_missing_semgrep_binary_raises_actionable_error(self) -> None:
        # run_semgrep() now delegates to common/semgrep_wrapper.py (see
        # plan 023's Semgrep-subset half, which needed the same logic)
        # — patch shutil.which where the check actually runs.
        with mock.patch("scanner._sw.shutil.which", return_value=None):
            with self.assertRaises(ScannerError) as ctx:
                scanner.run_semgrep(["irrelevant.py"], scanner.DEFAULT_CONFIG)
        self.assertIn("pip install semgrep", str(ctx.exception))


class MappingTests(unittest.TestCase):
    """Pure-function unit tests for the result-to-finding mapping — no
    semgrep subprocess needed, fast and deterministic."""

    def test_severity_error_high_impact_is_critical(self) -> None:
        self.assertEqual(scanner._severity("ERROR", "HIGH"), "Critical")

    def test_severity_error_low_impact_is_high(self) -> None:
        self.assertEqual(scanner._severity("ERROR", "LOW"), "High")

    def test_severity_warning_high_impact_is_high(self) -> None:
        self.assertEqual(scanner._severity("WARNING", "HIGH"), "High")

    def test_severity_warning_other_impact_is_medium(self) -> None:
        self.assertEqual(scanner._severity("WARNING", "MEDIUM"), "Medium")
        self.assertEqual(scanner._severity("WARNING", None), "Medium")

    def test_severity_info_is_low(self) -> None:
        self.assertEqual(scanner._severity("INFO", "HIGH"), "Low")

    def test_confidence_mapping(self) -> None:
        self.assertEqual(scanner._confidence("HIGH"), 85)
        self.assertEqual(scanner._confidence("MEDIUM"), 65)
        self.assertEqual(scanner._confidence("LOW"), 40)
        self.assertEqual(scanner._confidence(None), 50)
        self.assertEqual(scanner._confidence("nonsense"), 50)

    def test_rule_id_prefixes_check_id(self) -> None:
        self.assertEqual(
            scanner._rule_id("python.lang.security.audit.subprocess-shell-true.subprocess-shell-true"),
            "code-review.python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
        )

    def test_extract_references_filters_to_2025_owasp_edition(self) -> None:
        metadata = {
            "cwe": ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"],
            "owasp": ["A1: Injection", "A03:2021 - Injection", "A05:2025 - Injection"],
        }
        refs = scanner._extract_references(metadata)
        self.assertIn({"standard": "CWE", "id": "CWE-89"}, refs)
        self.assertIn({"standard": "OWASP-Top10", "id": "A05:2025"}, refs)
        self.assertEqual(len(refs), 2, refs)  # 2017/2021-only entries must not appear

    def test_extract_references_drops_unrecognized_ids(self) -> None:
        metadata = {"cwe": ["CWE-999999: Not A Real CWE"], "owasp": ["A99:2025 - Not Real"]}
        self.assertEqual(scanner._extract_references(metadata), [])

    def test_map_result_raises_when_no_references_resolve(self) -> None:
        result = {
            "check_id": "made.up.rule",
            "path": "x.py",
            "start": {"line": 1, "col": 1, "offset": 0},
            "end": {"line": 1, "col": 5, "offset": 4},
            "extra": {"message": "x", "severity": "ERROR", "metadata": {}},
        }
        with self.assertRaises(ScannerError):
            scanner.map_result_to_finding(result, "source-code", "0.0.0")


class FindingIdTests(unittest.TestCase):
    def test_deterministic_for_identical_input(self) -> None:
        a = scanner._finding_id("code-review.x", "f.py", 1, 1, 0, 5)
        b = scanner._finding_id("code-review.x", "f.py", 1, 1, 0, 5)
        self.assertEqual(a, b)

    def test_distinct_locations_get_distinct_ids(self) -> None:
        a = scanner._finding_id("code-review.x", "f.py", 1, 1, 0, 5)
        b = scanner._finding_id("code-review.x", "f.py", 2, 2, 10, 15)
        self.assertNotEqual(a, b)

    def test_distinct_byte_ranges_on_the_same_line_get_distinct_ids(self) -> None:
        # Same rule, same file, same line range — only the byte offsets
        # differ (e.g. two matches of the same check_id on one line).
        # Mirrors the exact test-quality bug plan 006 found: a test
        # that only varies line numbers never exercises this case.
        a = scanner._finding_id("code-review.x", "f.py", 1, 1, 0, 5)
        b = scanner._finding_id("code-review.x", "f.py", 1, 1, 10, 15)
        self.assertNotEqual(a, b)


class ConsistencyTests(unittest.TestCase):
    """The CWEs/OWASP entries this pack's rules are expected to cite
    (sampled from real Semgrep output at implementation) must actually
    resolve in the knowledge base — same discipline as 006/023."""

    def test_expected_cwe_ids_resolve_in_knowledge_base(self) -> None:
        for cwe_id in ("CWE-77", "CWE-78", "CWE-79", "CWE-89", "CWE-918"):
            self.assertTrue(standards.exists("CWE", cwe_id), cwe_id)

    def test_expected_owasp_top10_2025_ids_resolve(self) -> None:
        for owasp_id in ("A01:2025", "A05:2025"):
            self.assertTrue(standards.exists("OWASP-Top10", owasp_id), owasp_id)


@unittest.skipUnless(_semgrep_available(), "requires the real semgrep CLI on PATH")
class MainCliTests(unittest.TestCase):
    def test_prints_findings_as_json_and_returns_0(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "vuln.py"
            path.write_text(SQLI_CMDI_SSRF_PY, encoding="utf-8")
            out = io.StringIO()
            with redirect_stdout(out):
                code = scanner.main([str(path)])
        self.assertEqual(code, 0)
        parsed = json.loads(out.getvalue())
        self.assertGreaterEqual(len(parsed), 1)

    def test_bad_config_returns_1_and_prints_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "clean.py"
            path.write_text(CLEAN_PY, encoding="utf-8")
            err = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(err):
                code = scanner.main([str(path), "--config", "p/this-pack-does-not-exist-xyz"])
        self.assertEqual(code, 1)
        self.assertIn("SCANNER ERROR", err.getvalue())


class CrossPlatformEncodingTests(unittest.TestCase):
    def test_round_trip_non_ascii_content_with_explicit_utf8(self) -> None:
        text = "em dash — and middle dot · round-trip"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "roundtrip.txt"
            path.write_text(text, encoding="utf-8")
            self.assertEqual(path.read_text(encoding="utf-8"), text)


class SourceEncodingAuditTests(unittest.TestCase):
    def test_no_read_or_write_text_call_omits_encoding(self) -> None:
        import ast

        violations = []
        for path in sorted(DETECTOR_DIR.glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr in ("read_text", "write_text")
                ):
                    kwarg_names = {kw.arg for kw in node.keywords}
                    if "encoding" not in kwarg_names:
                        violations.append(f"{path.name}:{node.lineno} .{node.func.attr}() missing encoding=")
        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()
