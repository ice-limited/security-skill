"""Golden-file tests for the ScanReport renderers and schema conformance.

Run with: python3 -m unittest schema.test_renderers -v
(from the security-skill/ repo root), or `python3 test_renderers.py` from
inside schema/.
"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from render_html import render_html
from render_markdown import render_markdown
from validate import validate_report

SCHEMA_DIR = Path(__file__).parent
TESTDATA = SCHEMA_DIR / "testdata"

MINIMAL_FINDING = {
    "findingId": "f-min-001",
    "ruleId": "code-review.example-rule",
    "subSkill": "code-review",
    "artifactType": "source-code",
    "title": "Example finding",
    "problem": "Example problem.",
    "impact": "Example impact.",
    "recommendation": "Example recommendation.",
    "references": [{"standard": "CWE", "id": "CWE-1"}],
    "severity": "Info",
    "confidence": 50,
    "location": {"file": "src/example.py", "startLine": 1, "endLine": 1},
    "detectorSource": {"name": "example-detector", "version": "0.0.1"},
    "suppressed": False,
}


def _minimal_report(findings: list[dict]) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f["severity"].lower()] += 1
    return {
        "schemaVersion": "1.0.0",
        "scanId": "scan-min",
        "repository": "example/repo",
        "timestamp": "2026-07-22T00:00:00Z",
        "toolVersion": "0.1.0",
        "summary": {**counts, "total": len(findings)},
        "findings": findings,
    }


class RendererGoldenFileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.report = json.loads((TESTDATA / "sample-report.json").read_text())

    def test_sample_report_is_schema_valid(self) -> None:
        errors = validate_report(self.report)
        self.assertEqual(errors, [], f"sample-report.json should conform to scan-report.schema.json: {errors}")

    def test_markdown_matches_golden_file(self) -> None:
        actual = render_markdown(self.report)
        expected = (TESTDATA / "sample-report.md").read_text()
        self.assertEqual(actual, expected)

    def test_html_matches_golden_file(self) -> None:
        actual = render_html(self.report)
        expected = (TESTDATA / "sample-report.html").read_text()
        self.assertEqual(actual, expected)

    def test_suppressed_finding_is_rendered_not_dropped(self) -> None:
        # A suppressed finding is still part of the audit trail (per the
        # schema's description on `summary`) — it must still appear in
        # both renderers, just visually marked as suppressed.
        markdown = render_markdown(self.report)
        html = render_html(self.report)
        self.assertIn("hostPath volume mounted", markdown)
        self.assertIn("(suppressed)", markdown)
        self.assertIn("hostPath volume mounted", html)
        self.assertIn("suppressed", html)

    def test_html_escapes_untrusted_text(self) -> None:
        # Regression guard: finding text is attacker-influenced in
        # practice (it can quote source code back at the reader) and must
        # never be interpolated into HTML unescaped.
        report = json.loads(json.dumps(self.report))
        report["findings"][0]["title"] = '<script>alert(1)</script>'
        html = render_html(report)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)


class SchemaSelfCheckTests(unittest.TestCase):
    """The schema files themselves must be valid JSON Schema documents."""

    def test_finding_schema_is_valid_json_schema(self) -> None:
        schema = json.loads((SCHEMA_DIR / "finding.schema.json").read_text())
        Draft202012Validator.check_schema(schema)

    def test_scan_report_schema_is_valid_json_schema(self) -> None:
        schema = json.loads((SCHEMA_DIR / "scan-report.schema.json").read_text())
        Draft202012Validator.check_schema(schema)


class EdgeCaseTests(unittest.TestCase):
    """Cases not covered by the single fixed golden-file fixture."""

    def test_empty_findings_report_is_valid_and_renders(self) -> None:
        report = _minimal_report([])
        self.assertEqual(validate_report(report), [])

        markdown = render_markdown(report)
        self.assertIn("| **Total** | **0** |", markdown)
        # No severity section headings should appear when there are no
        # findings in that bucket.
        for severity in ("Critical", "High", "Medium", "Low", "Info"):
            self.assertNotIn(f"## {severity}", markdown)

        html = render_html(report)
        self.assertIn("<strong>0</strong>", html)

    def test_minimal_optional_fields_omitted(self) -> None:
        # No branch/commit/diffRange on the report, no suppressionReason/
        # metadata on the finding — everything not `required` should be
        # omittable without breaking validation or rendering.
        report = _minimal_report([dict(MINIMAL_FINDING)])
        self.assertEqual(validate_report(report), [])

        markdown = render_markdown(report)
        self.assertIn("Example finding", markdown)
        # No branch/commit line should be emitted when both are absent.
        self.assertNotIn("branch `", markdown)
        self.assertNotIn("commit `", markdown)

        html = render_html(report)
        self.assertIn("Example finding", html)

    def test_suppressed_without_reason_does_not_crash(self) -> None:
        finding = dict(MINIMAL_FINDING)
        finding["suppressed"] = True
        # suppressionReason intentionally omitted — renderers must not
        # assume it's present just because suppressed=True.
        report = _minimal_report([finding])
        self.assertEqual(validate_report(report), [])
        markdown = render_markdown(report)
        html = render_html(report)
        self.assertIn("(suppressed)", markdown)
        self.assertIn("suppressed", html)

    def test_severity_with_no_matching_findings_omits_table_row_content_but_keeps_count(self) -> None:
        report = _minimal_report([dict(MINIMAL_FINDING, severity="Critical", findingId="f-c")])
        markdown = render_markdown(report)
        self.assertIn("| Critical | 1 |", markdown)
        self.assertIn("| High | 0 |", markdown)

    def test_invalid_report_is_rejected(self) -> None:
        # Sanity check that validate_report actually rejects bad input —
        # guards against a validator that silently always passes.
        report = _minimal_report([dict(MINIMAL_FINDING)])
        del report["findings"][0]["recommendation"]
        report["findings"][0]["severity"] = "Extreme"
        errors = validate_report(report)
        self.assertEqual(len(errors), 2)


class CliInvocationTests(unittest.TestCase):
    """The renderers must also work as `python3 render_x.py < report.json`."""

    def setUp(self) -> None:
        self.report_json = (TESTDATA / "sample-report.json").read_text()

    def _run(self, script: str) -> str:
        result = subprocess.run(
            [sys.executable, script],
            input=self.report_json,
            capture_output=True,
            text=True,
            cwd=SCHEMA_DIR,
            check=True,
        )
        return result.stdout

    def test_render_markdown_cli(self) -> None:
        stdout = self._run("render_markdown.py")
        self.assertEqual(stdout, (TESTDATA / "sample-report.md").read_text())

    def test_render_html_cli(self) -> None:
        stdout = self._run("render_html.py")
        self.assertEqual(stdout, (TESTDATA / "sample-report.html").read_text())


if __name__ == "__main__":
    unittest.main()
