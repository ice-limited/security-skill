"""Tests for the AuthN/AuthZ Semgrep-subset detector (023's
deterministic half, built once 007 existed to reuse). Real `semgrep`
subprocess calls, not mocked — same discipline as
detectors/code-review/test_scanner.py.

CrossPlatformEncodingTests/SourceEncodingAuditTests for this directory
already live in test_playbook.py (scans every .py file here) — not
duplicated in this file, same precedent as knowledge/'s two test files
(only test_knowledge.py carries them).

Run with: python3 -m unittest test_semgrep_detector -v (from inside
detectors/auth/).
"""

from __future__ import annotations

import io
import json
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import semgrep_detector
from semgrep_detector import ScannerError

DETECTOR_DIR = Path(__file__).parent
SECURITY_SKILL_DIR = next(p for p in DETECTOR_DIR.resolve().parents if (p / "common").is_dir())
SCHEMA_DIR = SECURITY_SKILL_DIR / "schema"

sys.path.insert(0, str(SECURITY_SKILL_DIR / "common"))
from schema_validation import validate_against_schema  # noqa: E402

sys.path.insert(0, str(SECURITY_SKILL_DIR / "knowledge"))
import standards  # noqa: E402

PYTHON_UNVERIFIED_DECODE = '''import jwt

def verify(token):
    return jwt.decode(token, options={"verify_signature": False})
'''

PYTHON_NONE_ALG = '''import jwt

def verify2(token, secret):
    return jwt.decode(token, secret, algorithms=["none"])
'''

JS_NONE_ALG = """const jwt = require('jsonwebtoken');

function verifyToken2(token) {
  return jwt.verify(token, getSecret(), { algorithms: ['none'] });
}
"""

# Found during the "test plan 023" round: p/jwt also has a Go rule for
# this exact pattern (not part of the original implementation's
# verified set, which only covered Python/JS).
GO_NONE_ALG = """package main

import "github.com/golang-jwt/jwt/v5"

func verify2(tokenString string) {
	parser := jwt.NewParser()
	parser.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodNone); ok {
			return jwt.UnsafeAllowNoneSignatureType, nil
		}
		return []byte("secret"), nil
	})
}
"""

CLEAN_PY = "def add(a, b):\n    return a + b\n"


def _semgrep_available() -> bool:
    return shutil.which("semgrep") is not None


@unittest.skipUnless(_semgrep_available(), "requires the real semgrep CLI on PATH")
class PerPatternDetectionTests(unittest.TestCase):
    def test_unverified_decode_maps_to_existing_checklist_rule_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "vuln.py"
            path.write_text(PYTHON_UNVERIFIED_DECODE, encoding="utf-8")
            findings = semgrep_detector.scan_file(path)
        rule_ids = {f["ruleId"] for f in findings}
        self.assertIn("auth.jwt-signature-not-verified", rule_ids)
        for f in findings:
            self.assertEqual(f["subSkill"], "auth")

    def test_none_algorithm_python_maps_to_weak_algorithm_rule_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "vuln.py"
            path.write_text(PYTHON_NONE_ALG, encoding="utf-8")
            findings = semgrep_detector.scan_file(path)
        self.assertIn("auth.jwt-weak-algorithm", {f["ruleId"] for f in findings})

    def test_none_algorithm_javascript_maps_to_weak_algorithm_rule_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "vuln.js"
            path.write_text(JS_NONE_ALG, encoding="utf-8")
            findings = semgrep_detector.scan_file(path)
        self.assertIn("auth.jwt-weak-algorithm", {f["ruleId"] for f in findings})

    def test_none_algorithm_go_maps_to_weak_algorithm_rule_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "vuln.go"
            path.write_text(GO_NONE_ALG, encoding="utf-8")
            findings = semgrep_detector.scan_file(path)
        self.assertIn("auth.jwt-weak-algorithm", {f["ruleId"] for f in findings})

    def test_clean_file_produces_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "clean.py"
            path.write_text(CLEAN_PY, encoding="utf-8")
            findings = semgrep_detector.scan_file(path)
        self.assertEqual(findings, [])


@unittest.skipUnless(_semgrep_available(), "requires the real semgrep CLI on PATH")
class SchemaConformanceTests(unittest.TestCase):
    def test_real_findings_validate_against_finding_schema(self) -> None:
        schema = json.loads((SCHEMA_DIR / "finding.schema.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "vuln.py"
            path.write_text(PYTHON_UNVERIFIED_DECODE + "\n" + PYTHON_NONE_ALG, encoding="utf-8")
            findings = semgrep_detector.scan_file(path)
        self.assertGreaterEqual(len(findings), 2)
        for f in findings:
            errors = validate_against_schema(schema, f)
            self.assertEqual(errors, [], f"{f['ruleId']} finding is not schema-valid: {errors}")


@unittest.skipUnless(_semgrep_available(), "requires the real semgrep CLI on PATH")
class MainCliTests(unittest.TestCase):
    def test_prints_findings_as_json_and_returns_0(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "vuln.py"
            path.write_text(PYTHON_UNVERIFIED_DECODE, encoding="utf-8")
            out = io.StringIO()
            with redirect_stdout(out):
                code = semgrep_detector.main([str(path)])
        self.assertEqual(code, 0)
        parsed = json.loads(out.getvalue())
        self.assertGreaterEqual(len(parsed), 1)


class ConsistencyTests(unittest.TestCase):
    """The CWEs this narrow pack is expected to cite (verified at
    implementation) must resolve in the knowledge base — CWE-287 was
    already seeded for the playbook half; CWE-327 was added
    specifically because this Semgrep-subset half needs it."""

    def test_expected_cwe_ids_resolve(self) -> None:
        for cwe_id in ("CWE-287", "CWE-327"):
            self.assertTrue(standards.exists("CWE", cwe_id), cwe_id)

    def test_expected_owasp_top10_2025_ids_resolve(self) -> None:
        for owasp_id in ("A04:2025", "A07:2025"):
            self.assertTrue(standards.exists("OWASP-Top10", owasp_id), owasp_id)

    def test_every_override_target_exists_as_a_real_checklist_item(self) -> None:
        # If a checklist item is ever renamed/removed, an override
        # pointing at its old ruleId would silently start producing
        # findings under a ruleId with no corresponding checklist
        # entry — this cross-checks that never drifts unnoticed.
        import playbook

        checklist = playbook.load_checklist()
        known_rule_ids = {item["ruleId"] for item in checklist["items"]}
        for target_rule_id in semgrep_detector._RULE_ID_OVERRIDES.values():
            self.assertIn(target_rule_id, known_rule_ids, target_rule_id)


if __name__ == "__main__":
    unittest.main()
