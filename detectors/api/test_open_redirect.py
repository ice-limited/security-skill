"""Tests for the open-redirect (CWE-601) detector: real Semgrep
subprocess calls (not mocked), the real cross-config duplicate found at
implementation (two check_ids firing on the same Express location),
schema conformance, and — per this plan's kickoff decision to avoid
duplicating 023's existing JWT/mass-assignment detection — a real,
subprocess-based proof that this module and detectors/auth's
semgrep_detector.py (023) never produce overlapping output on each
other's fixtures.

Requires the real `semgrep` CLI on PATH (`pip install semgrep`, see
../code-review/requirements.txt — same dependency, not duplicated
here, matching 023's own precedent of not re-declaring it). Run with:
python3 -m unittest test_open_redirect -v (from inside detectors/api/).
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

import open_redirect
from open_redirect import ScannerError

DETECTOR_DIR = Path(__file__).parent
SECURITY_SKILL_DIR = next(p for p in DETECTOR_DIR.resolve().parents if (p / "common").is_dir())
SCHEMA_DIR = SECURITY_SKILL_DIR / "schema"
AUTH_DIR = SECURITY_SKILL_DIR / "detectors" / "auth"

sys.path.insert(0, str(SECURITY_SKILL_DIR / "common"))
from schema_validation import validate_against_schema  # noqa: E402


def _semgrep_available() -> bool:
    return shutil.which("semgrep") is not None


# Deliberately obvious/synthetic fixtures. The Express case is written
# exactly as found at implementation to reproduce a real duplicate:
# `p/security-audit` fires *two* distinct check_ids
# (`express-open-redirect` and `possible-user-input-redirect.unknown-
# value-in-redirect`) on this exact line — verified empirically, not
# assumed — which this module's rule_id_overrides + de-dup must
# collapse to one finding.
EXPRESS_OPEN_REDIRECT_JS = """const express = require('express');
const app = express();

app.get('/go', (req, res) => {
  const target = req.query.url;
  res.redirect(target);
});
"""

FLASK_OPEN_REDIRECT_PY = """from flask import Flask, request, redirect

app = Flask(__name__)

@app.route("/go")
def go():
    target = request.args.get("url")
    return redirect(target)
"""

CLEAN_JS = """const express = require('express');
const app = express();

app.get('/go', (req, res) => {
  res.redirect('/home');
});
"""

# JWT-bypass fixtures matching 023's own test_semgrep_detector.py
# (detectors/auth/) verbatim in shape — used here only to prove this
# module's open-redirect detector produces zero output on 023's own
# vulnerability class, not to re-test 023 itself.
JWT_NONE_ALG_PY = """import jwt

def decode_token(token, secret):
    return jwt.decode(token, secret, algorithms=["none"])
"""


@unittest.skipUnless(_semgrep_available(), "requires the real semgrep CLI on PATH")
class SchemaConformanceAndDedupTests(unittest.TestCase):
    def test_express_duplicate_check_ids_collapse_to_one_finding(self) -> None:
        schema = json.loads((SCHEMA_DIR / "finding.schema.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.js"
            path.write_text(EXPRESS_OPEN_REDIRECT_JS, encoding="utf-8")
            findings = open_redirect.scan_paths([str(tmp)])

        self.assertEqual(len(findings), 1, findings)
        finding = findings[0]
        self.assertEqual(finding["ruleId"], "api.open-redirect")
        self.assertEqual(finding["location"]["startLine"], 6)
        errors = validate_against_schema(schema, finding)
        self.assertEqual(errors, [])

    def test_flask_open_redirect_detected_with_same_rule_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.py"
            path.write_text(FLASK_OPEN_REDIRECT_PY, encoding="utf-8")
            findings = open_redirect.scan_paths([str(tmp)])

        self.assertEqual(len(findings), 1, findings)
        self.assertEqual(findings[0]["ruleId"], "api.open-redirect")
        self.assertEqual(findings[0]["location"]["startLine"], 7)

    def test_clean_fixture_produces_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.js"
            path.write_text(CLEAN_JS, encoding="utf-8")
            findings = open_redirect.scan_paths([str(tmp)])
        self.assertEqual(findings, [])


@unittest.skipUnless(_semgrep_available(), "requires the real semgrep CLI on PATH")
class NoOverlapWith023Tests(unittest.TestCase):
    """Real, subprocess-based proof (not by-construction reasoning
    alone) that this plan's open-redirect detector and 023's own
    semgrep_detector.py never produce overlapping findings — the exact
    risk the plan 012 kickoff scoped this module to avoid."""

    def test_open_redirect_detector_finds_nothing_in_023s_own_jwt_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.py"
            path.write_text(JWT_NONE_ALG_PY, encoding="utf-8")
            findings = open_redirect.scan_paths([str(tmp)])
        self.assertEqual(findings, [])

    @unittest.skipUnless((AUTH_DIR / "semgrep_detector.py").is_file(), "requires detectors/auth/semgrep_detector.py (023)")
    def test_023s_jwt_detector_finds_nothing_in_this_plans_open_redirect_fixtures(self) -> None:
        # Invoked as a real subprocess (not an in-process import) —
        # each detector directory manages its own sys.path/module
        # names (both this module and 023 could plausibly define a
        # same-named module in the same process), so shelling out
        # mirrors how a human/CI would actually run these two
        # independent detectors, not an artificial in-process fixture.
        import subprocess

        with tempfile.TemporaryDirectory() as tmp:
            js_path = Path(tmp) / "app.js"
            js_path.write_text(EXPRESS_OPEN_REDIRECT_JS, encoding="utf-8")
            py_path = Path(tmp) / "app.py"
            py_path.write_text(FLASK_OPEN_REDIRECT_PY, encoding="utf-8")

            proc = subprocess.run(
                [sys.executable, "semgrep_detector.py", str(tmp)],
                cwd=str(AUTH_DIR),
                capture_output=True,
                text=True,
                encoding="utf-8",
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        findings = json.loads(proc.stdout)
        self.assertEqual(findings, [])


class ErrorHandlingTests(unittest.TestCase):
    def test_missing_semgrep_raises_actionable_error(self) -> None:
        with mock.patch("open_redirect._sw.shutil.which", return_value=None):
            with self.assertRaises(ScannerError) as ctx:
                open_redirect.scan_paths(["irrelevant"])
        self.assertIn("pip install semgrep", str(ctx.exception))


class ConsistencyTests(unittest.TestCase):
    def test_is_open_redirect_matches_only_cwe_601(self) -> None:
        matching = {"extra": {"metadata": {"cwe": ["CWE-601: URL Redirection to Untrusted Site ('Open Redirect')"]}}}
        not_matching = {"extra": {"metadata": {"cwe": ["CWE-79: Cross-site Scripting"]}}}
        no_metadata = {"extra": {}}
        self.assertTrue(open_redirect._is_open_redirect(matching))
        self.assertFalse(open_redirect._is_open_redirect(not_matching))
        self.assertFalse(open_redirect._is_open_redirect(no_metadata))

    def test_every_override_target_rule_id_matches_naming_convention(self) -> None:
        import re

        pattern = re.compile(r"^api\.[a-z0-9-]+$")
        for rule_id in open_redirect._RULE_ID_OVERRIDES.values():
            self.assertTrue(pattern.match(rule_id), rule_id)


@unittest.skipUnless(_semgrep_available(), "requires the real semgrep CLI on PATH")
class MainCliTests(unittest.TestCase):
    def test_prints_findings_as_json_and_returns_0(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.js"
            path.write_text(CLEAN_JS, encoding="utf-8")
            out = io.StringIO()
            with redirect_stdout(out):
                code = open_redirect.main([str(tmp)])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue()), [])

    def test_bad_path_returns_1_and_prints_error(self) -> None:
        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            code = open_redirect.main(["/tmp/definitely-does-not-exist-012-api-oredirect"])
        self.assertEqual(code, 1)
        self.assertIn("SCANNER ERROR", err.getvalue())


class CrossPlatformEncodingTests(unittest.TestCase):
    def test_round_trip_non_ascii_content_with_explicit_utf8(self) -> None:
        text = "em dash — and middle dot · round-trip"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "roundtrip.txt"
            path.write_text(text, encoding="utf-8")
            self.assertEqual(path.read_text(encoding="utf-8"), text)


if __name__ == "__main__":
    unittest.main()
