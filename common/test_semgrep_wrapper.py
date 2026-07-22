"""Tests for common/semgrep_wrapper.py — the shared Semgrep subprocess
wrapper and result-to-finding.schema.json mapping used by both
detectors/code-review/scanner.py (007) and
detectors/auth/semgrep_detector.py (023's Semgrep-subset half).

detector-specific behavior (which rule pack, which subSkill/ruleId
namespace) is exercised more thoroughly in each detector's own
test_*.py — this file focuses on the generic logic itself, especially
`rule_id_overrides`, which code-review's scanner.py never exercises
(only detectors/auth/ uses it).

Run with: python3 -m unittest test_semgrep_wrapper -v (from inside
common/).
"""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import semgrep_wrapper as sw

COMMON_DIR = Path(__file__).parent


def _semgrep_available() -> bool:
    return shutil.which("semgrep") is not None


class SeverityConfidenceTests(unittest.TestCase):
    def test_severity_error_high_impact_is_critical(self) -> None:
        self.assertEqual(sw.severity("ERROR", "HIGH"), "Critical")

    def test_severity_error_other_impact_is_high(self) -> None:
        self.assertEqual(sw.severity("ERROR", "LOW"), "High")
        self.assertEqual(sw.severity("ERROR", None), "High")

    def test_severity_warning_high_impact_is_high(self) -> None:
        self.assertEqual(sw.severity("WARNING", "HIGH"), "High")

    def test_severity_warning_other_impact_is_medium(self) -> None:
        self.assertEqual(sw.severity("WARNING", "MEDIUM"), "Medium")

    def test_severity_info_is_low(self) -> None:
        self.assertEqual(sw.severity("INFO", "HIGH"), "Low")

    def test_confidence_mapping(self) -> None:
        self.assertEqual(sw.confidence("HIGH"), 85)
        self.assertEqual(sw.confidence("MEDIUM"), 65)
        self.assertEqual(sw.confidence("LOW"), 40)
        self.assertEqual(sw.confidence(None), 50)


class ExtractReferencesTests(unittest.TestCase):
    def test_filters_to_2025_owasp_edition_and_known_cwe(self) -> None:
        metadata = {
            "cwe": ["CWE-287: Improper Authentication"],
            "owasp": ["A02:2017 - Broken Authentication", "A07:2021 - ...", "A07:2025 - Authentication Failures"],
        }
        refs = sw.extract_references(metadata)
        self.assertIn({"standard": "CWE", "id": "CWE-287"}, refs)
        self.assertIn({"standard": "OWASP-Top10", "id": "A07:2025"}, refs)
        self.assertEqual(len(refs), 2, refs)

    def test_drops_unrecognized_ids(self) -> None:
        metadata = {"cwe": ["CWE-999999: Not Real"], "owasp": ["A99:2025 - Not Real"]}
        self.assertEqual(sw.extract_references(metadata), [])


class FindingIdTests(unittest.TestCase):
    def test_deterministic(self) -> None:
        a = sw.finding_id("auth", "auth.x", "f.py", 1, 1, 0, 5)
        b = sw.finding_id("auth", "auth.x", "f.py", 1, 1, 0, 5)
        self.assertEqual(a, b)

    def test_prefix_is_used_verbatim(self) -> None:
        self.assertTrue(sw.finding_id("auth", "auth.x", "f.py", 1, 1, 0, 5).startswith("auth-"))
        self.assertTrue(sw.finding_id("code-review", "code-review.x", "f.py", 1, 1, 0, 5).startswith("code-review-"))

    def test_distinct_byte_ranges_on_same_line_get_distinct_ids(self) -> None:
        a = sw.finding_id("auth", "auth.x", "f.py", 1, 1, 0, 5)
        b = sw.finding_id("auth", "auth.x", "f.py", 1, 1, 10, 15)
        self.assertNotEqual(a, b)


class MapResultToFindingTests(unittest.TestCase):
    """The rule_id_overrides parameter is common/semgrep_wrapper.py's
    own feature — never exercised by detectors/code-review/, which
    doesn't use it (only detectors/auth/ does), so it needs direct
    coverage here rather than relying on a consumer's tests."""

    def _result(self, check_id: str) -> dict:
        return {
            "check_id": check_id,
            "path": "app.js",
            "start": {"line": 3, "col": 1, "offset": 20},
            "end": {"line": 3, "col": 10, "offset": 29},
            "extra": {
                "message": "example message",
                "severity": "ERROR",
                "metadata": {"cwe": ["CWE-287: Improper Authentication"], "owasp": ["A07:2025 - Authentication Failures"]},
            },
        }

    def _map(self, check_id: str, overrides: dict[str, str] | None = None) -> dict:
        return sw.map_result_to_finding(
            self._result(check_id),
            "source-code",
            "1.0.0",
            sub_skill="auth",
            rule_id_prefix="auth",
            id_prefix="auth",
            detector_name="auth-semgrep-wrapper",
            rule_id_overrides=overrides,
        )

    def test_without_overrides_uses_generic_prefix(self) -> None:
        finding = self._map("javascript.jsonwebtoken.security.jwt-none-alg.jwt-none-alg")
        self.assertEqual(finding["ruleId"], "auth.javascript.jsonwebtoken.security.jwt-none-alg.jwt-none-alg")

    def test_override_replaces_generic_rule_id(self) -> None:
        overrides = {"javascript.jsonwebtoken.security.jwt-none-alg.jwt-none-alg": "auth.jwt-weak-algorithm"}
        finding = self._map("javascript.jsonwebtoken.security.jwt-none-alg.jwt-none-alg", overrides)
        self.assertEqual(finding["ruleId"], "auth.jwt-weak-algorithm")

    def test_unmapped_check_id_falls_back_to_generic_prefix_even_with_overrides_given(self) -> None:
        overrides = {"some.other.check-id": "auth.something-else"}
        finding = self._map("javascript.jsonwebtoken.security.jwt-none-alg.jwt-none-alg", overrides)
        self.assertEqual(finding["ruleId"], "auth.javascript.jsonwebtoken.security.jwt-none-alg.jwt-none-alg")

    def test_no_recognized_references_raises(self) -> None:
        result = self._result("made.up.rule")
        result["extra"]["metadata"] = {}
        with self.assertRaises(sw.ScannerError):
            sw.map_result_to_finding(
                result, "source-code", "1.0.0",
                sub_skill="auth", rule_id_prefix="auth", id_prefix="auth", detector_name="auth-semgrep-wrapper",
            )


class RunSemgrepTests(unittest.TestCase):
    def test_missing_binary_raises_actionable_error(self) -> None:
        with mock.patch("semgrep_wrapper.shutil.which", return_value=None):
            with self.assertRaises(sw.ScannerError) as ctx:
                sw.run_semgrep(["irrelevant.py"], "p/jwt")
        self.assertIn("pip install semgrep", str(ctx.exception))

    @unittest.skipUnless(_semgrep_available(), "requires the real semgrep CLI on PATH")
    def test_clean_file_produces_no_results(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "clean.py"
            path.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
            output = sw.run_semgrep([str(path)], "p/jwt")
        self.assertEqual(output["results"], [])


class CrossPlatformEncodingTests(unittest.TestCase):
    def test_round_trip_non_ascii_content_with_explicit_utf8(self) -> None:
        text = "em dash — and middle dot · round-trip"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "roundtrip.txt"
            path.write_text(text, encoding="utf-8")
            self.assertEqual(path.read_text(encoding="utf-8"), text)


if __name__ == "__main__":
    unittest.main()
