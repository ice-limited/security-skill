"""Tests for the decision layer: schema validity, dedup, exception
-based suppression, and the confidence-calibration plug-in point.

Run with: python3 -m unittest test_decision -v (from inside decision/).
"""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import date
from pathlib import Path

from jsonschema import Draft202012Validator

import decision
from validate import validate_exceptions

DECISION_DIR = Path(__file__).parent
SCHEMA_DIR = DECISION_DIR.parent / "schema"

VALID_EXCEPTIONS = {
    "exceptionsVersion": "1.0.0",
    "exceptions": [
        {"findingId": "f-1", "reason": "false positive, sandboxed eval"},
        {"findingId": "f-2", "reason": "accepted risk, expires end of year", "expiresAt": "2099-12-31"},
    ],
}


def _finding(
    finding_id: str,
    rule_id: str = "code-review.example",
    file: str = "src/x.py",
    start: int = 1,
    end: int = 1,
    start_byte: int | None = None,
    end_byte: int | None = None,
) -> dict:
    location = {"file": file, "startLine": start, "endLine": end}
    if start_byte is not None:
        location["startByte"] = start_byte
    if end_byte is not None:
        location["endByte"] = end_byte
    return {
        "findingId": finding_id,
        "ruleId": rule_id,
        "location": location,
        "suppressed": False,
    }


def _write_exceptions(repo_root: Path, data: dict) -> None:
    override_dir = repo_root / ".security-skill"
    override_dir.mkdir(parents=True, exist_ok=True)
    (override_dir / "exceptions.json").write_text(json.dumps(data), encoding="utf-8")


class SchemaSelfCheckTests(unittest.TestCase):
    def test_exceptions_schema_is_valid_json_schema(self) -> None:
        schema = json.loads((DECISION_DIR / "exceptions.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)

    def test_valid_exceptions_file_has_no_errors(self) -> None:
        self.assertEqual(validate_exceptions(VALID_EXCEPTIONS), [])

    def test_missing_reason_is_rejected(self) -> None:
        bad = {"exceptionsVersion": "1.0.0", "exceptions": [{"findingId": "f-1"}]}
        self.assertTrue(validate_exceptions(bad))

    def test_missing_finding_id_is_rejected(self) -> None:
        bad = {"exceptionsVersion": "1.0.0", "exceptions": [{"reason": "no id"}]}
        self.assertTrue(validate_exceptions(bad))

    def test_malformed_expires_at_is_rejected(self) -> None:
        bad = {
            "exceptionsVersion": "1.0.0",
            "exceptions": [{"findingId": "f-1", "reason": "x", "expiresAt": "not-a-date"}],
        }
        self.assertTrue(validate_exceptions(bad))

    def test_empty_exceptions_list_is_valid(self) -> None:
        self.assertEqual(validate_exceptions({"exceptionsVersion": "1.0.0", "exceptions": []}), [])


class LoadExceptionsTests(unittest.TestCase):
    def test_none_repo_root_returns_empty(self) -> None:
        self.assertEqual(decision.load_exceptions(None), {})

    def test_missing_file_returns_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(decision.load_exceptions(tmp), {})

    def test_security_skill_dir_present_but_no_exceptions_file_returns_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / ".security-skill").mkdir()
            self.assertEqual(decision.load_exceptions(tmp), {})

    def test_valid_file_loads_keyed_by_finding_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            _write_exceptions(Path(tmp), VALID_EXCEPTIONS)
            result = decision.load_exceptions(tmp)
            self.assertEqual(set(result), {"f-1", "f-2"})
            self.assertEqual(result["f-1"]["reason"], "false positive, sandboxed eval")

    def test_invalid_file_raises_rather_than_falling_back(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            _write_exceptions(Path(tmp), {"exceptionsVersion": "1.0.0", "exceptions": [{"findingId": "f-1"}]})
            with self.assertRaises(decision.DecisionError):
                decision.load_exceptions(tmp)

    def test_malformed_json_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            override_dir = Path(tmp) / ".security-skill"
            override_dir.mkdir()
            (override_dir / "exceptions.json").write_text("{not valid json", encoding="utf-8")
            with self.assertRaises(decision.DecisionError):
                decision.load_exceptions(tmp)

    def test_duplicate_finding_id_raises_rather_than_silently_last_wins(self) -> None:
        # Regression test for a real bug found while testing this plan:
        # two exceptions.json entries for the same findingId are
        # structurally valid per the schema (nothing forbids repeating a
        # findingId), but silently keeping whichever one happened to
        # come last in the file hides a real config conflict (possibly
        # contradictory reasons/expiry dates) from whoever wrote it.
        with tempfile.TemporaryDirectory() as tmp:
            _write_exceptions(
                Path(tmp),
                {
                    "exceptionsVersion": "1.0.0",
                    "exceptions": [
                        {"findingId": "f-1", "reason": "first reason"},
                        {"findingId": "f-1", "reason": "conflicting second reason"},
                    ],
                },
            )
            with self.assertRaises(decision.DecisionError):
                decision.load_exceptions(tmp)


class ApplyExceptionsTests(unittest.TestCase):
    def test_matching_non_expired_exception_suppresses(self) -> None:
        findings = [_finding("f-1")]
        exceptions = {"f-1": {"findingId": "f-1", "reason": "accepted"}}
        result = decision.apply_exceptions(findings, exceptions)
        self.assertTrue(result[0]["suppressed"])
        self.assertEqual(result[0]["suppressionReason"], "accepted")

    def test_no_matching_exception_leaves_finding_untouched(self) -> None:
        findings = [_finding("f-1")]
        result = decision.apply_exceptions(findings, {})
        self.assertFalse(result[0]["suppressed"])
        self.assertNotIn("suppressionReason", result[0])

    def test_expired_exception_does_not_suppress(self) -> None:
        findings = [_finding("f-1")]
        exceptions = {"f-1": {"findingId": "f-1", "reason": "was temporary", "expiresAt": "2020-01-01"}}
        result = decision.apply_exceptions(findings, exceptions, today=date(2026, 7, 22))
        self.assertFalse(result[0]["suppressed"])

    def test_expires_at_date_itself_is_still_valid(self) -> None:
        # "expiresAt: DATE" means valid through and including DATE
        # (same convention as a credit card's "valid thru" date), not
        # invalid starting that morning — expires the day *after*.
        findings = [_finding("f-1")]
        exceptions = {"f-1": {"findingId": "f-1", "reason": "x", "expiresAt": "2026-07-22"}}
        result = decision.apply_exceptions(findings, exceptions, today=date(2026, 7, 22))
        self.assertTrue(result[0]["suppressed"], "expiresAt date itself should still suppress")

    def test_day_after_expires_at_no_longer_suppresses(self) -> None:
        findings = [_finding("f-1")]
        exceptions = {"f-1": {"findingId": "f-1", "reason": "x", "expiresAt": "2026-07-22"}}
        result = decision.apply_exceptions(findings, exceptions, today=date(2026, 7, 23))
        self.assertFalse(result[0]["suppressed"])

    def test_does_not_mutate_input_findings(self) -> None:
        original = _finding("f-1")
        findings = [original]
        decision.apply_exceptions(findings, {"f-1": {"findingId": "f-1", "reason": "x"}})
        self.assertFalse(original["suppressed"], "input dict must not be mutated in place")

    def test_mixed_findings_only_matching_ones_suppressed(self) -> None:
        findings = [_finding("f-1"), _finding("f-2"), _finding("f-3")]
        exceptions = {"f-2": {"findingId": "f-2", "reason": "x"}}
        result = decision.apply_exceptions(findings, exceptions)
        suppressed = {f["findingId"] for f in result if f["suppressed"]}
        self.assertEqual(suppressed, {"f-2"})


class DedupFindingsTests(unittest.TestCase):
    def test_exact_duplicate_collapsed_to_first(self) -> None:
        findings = [_finding("f-1"), _finding("f-2", file="src/x.py", start=1, end=1)]
        result = decision.dedup_findings(findings)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["findingId"], "f-1")

    def test_different_rule_id_same_location_both_kept(self) -> None:
        findings = [
            _finding("f-1", rule_id="secret.aws-key"),
            _finding("f-2", rule_id="code-review.sqli"),
        ]
        result = decision.dedup_findings(findings)
        self.assertEqual(len(result), 2)

    def test_same_rule_id_different_location_both_kept(self) -> None:
        findings = [_finding("f-1", start=1, end=1), _finding("f-2", start=2, end=2)]
        result = decision.dedup_findings(findings)
        self.assertEqual(len(result), 2)

    def test_different_file_same_line_range_both_kept(self) -> None:
        findings = [_finding("f-1", file="a.py"), _finding("f-2", file="b.py")]
        result = decision.dedup_findings(findings)
        self.assertEqual(len(result), 2)

    def test_order_is_preserved(self) -> None:
        findings = [_finding("f-3", file="c.py"), _finding("f-1", file="a.py"), _finding("f-2", file="b.py")]
        result = decision.dedup_findings(findings)
        self.assertEqual([f["findingId"] for f in result], ["f-3", "f-1", "f-2"])

    def test_empty_list(self) -> None:
        self.assertEqual(decision.dedup_findings([]), [])

    def test_distinct_findings_on_same_line_with_different_byte_ranges_both_kept(self) -> None:
        # Regression test for a real bug found while testing this plan:
        # two different hardcoded secrets on one line, same rule, same
        # line range, but different byte offsets — the original dedup
        # key (ruleId + file + line range only) silently collapsed these
        # to one, dropping a real finding. Fixed by including
        # startByte/endByte in the key when present.
        findings = [
            _finding("f-1", rule_id="secret.generic", file="config.env", start=3, end=3, start_byte=10, end_byte=20),
            _finding("f-2", rule_id="secret.generic", file="config.env", start=3, end=3, start_byte=40, end_byte=50),
        ]
        result = decision.dedup_findings(findings)
        self.assertEqual(len(result), 2, "two distinct findings on the same line must not be collapsed")

    def test_identical_byte_range_is_still_treated_as_exact_duplicate(self) -> None:
        findings = [
            _finding("f-1", rule_id="secret.generic", file="config.env", start=3, end=3, start_byte=10, end_byte=20),
            _finding("f-2", rule_id="secret.generic", file="config.env", start=3, end=3, start_byte=10, end_byte=20),
        ]
        result = decision.dedup_findings(findings)
        self.assertEqual(len(result), 1)

    def test_missing_byte_offsets_on_both_sides_still_dedups_on_line_range(self) -> None:
        # Not every detector populates startByte/endByte (it's optional
        # in finding.schema.json) — the original line-range-only
        # behavior must still hold when neither finding has byte info.
        findings = [
            _finding("f-1", rule_id="r", file="a.py", start=1, end=1),
            _finding("f-2", rule_id="r", file="a.py", start=1, end=1),
        ]
        result = decision.dedup_findings(findings)
        self.assertEqual(len(result), 1)


class CalibrateConfidenceTests(unittest.TestCase):
    def test_is_currently_an_identity_function(self) -> None:
        # Documents the deliberate v1 scope cut from the kickoff: no
        # calibration model exists yet, so this must not silently alter
        # confidence in any way until one is actually built.
        finding = {"findingId": "f-1", "confidence": 42}
        self.assertEqual(decision.calibrate_confidence(finding), finding)
        self.assertIs(decision.calibrate_confidence(finding), finding)


class ProcessTests(unittest.TestCase):
    def test_full_pipeline_dedups_then_applies_exceptions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            _write_exceptions(
                Path(tmp), {"exceptionsVersion": "1.0.0", "exceptions": [{"findingId": "f-1", "reason": "x"}]}
            )
            findings = [_finding("f-1"), _finding("f-1-dup"), _finding("f-2", file="b.py")]
            # f-1-dup is an exact duplicate of f-1 (same ruleId+location)
            # but has a different findingId in this synthetic fixture —
            # dedup must key off ruleId+location, not findingId itself.
            result = decision.process(findings, repo_root=tmp)
            self.assertEqual(len(result), 2, "exact duplicate should have been collapsed")
            suppressed_ids = {f["findingId"] for f in result if f["suppressed"]}
            self.assertEqual(suppressed_ids, {"f-1"})

    def test_process_report_wraps_process_around_findings_key(self) -> None:
        report = {"scanId": "s-1", "findings": [_finding("f-1")]}
        result = decision.process_report(report)
        self.assertEqual(result["scanId"], "s-1")
        self.assertEqual(len(result["findings"]), 1)

    def test_process_report_handles_missing_findings_key(self) -> None:
        result = decision.process_report({})
        self.assertEqual(result["findings"], [])

    def test_process_report_does_not_mutate_input_report(self) -> None:
        report = {"findings": [_finding("f-1")]}
        decision.process_report(report)
        self.assertEqual(report["findings"][0]["suppressed"], False)


class MainCliTests(unittest.TestCase):
    def _run(self, argv: list[str]) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = decision.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_success_prints_processed_report_and_returns_0(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "report.json"
            report_path.write_text(json.dumps({"findings": [_finding("f-1")]}), encoding="utf-8")
            code, out, err = self._run([str(report_path)])
            self.assertEqual(code, 0)
            self.assertEqual(err, "")
            parsed = json.loads(out)
            self.assertEqual(len(parsed["findings"]), 1)

    def test_invalid_exceptions_file_prints_error_and_returns_1(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "report.json"
            report_path.write_text(json.dumps({"findings": []}), encoding="utf-8")
            _write_exceptions(Path(tmp), {"exceptionsVersion": "1.0.0", "exceptions": [{"findingId": "f-1"}]})
            code, out, err = self._run([str(report_path), "--repo-root", tmp])
            self.assertEqual(code, 1)
            self.assertEqual(out, "")
            self.assertIn("DECISION ERROR", err)

    def test_repo_root_flag_is_actually_applied(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "report.json"
            report_path.write_text(json.dumps({"findings": [_finding("f-1")]}), encoding="utf-8")
            _write_exceptions(
                Path(tmp), {"exceptionsVersion": "1.0.0", "exceptions": [{"findingId": "f-1", "reason": "x"}]}
            )
            code, out, _ = self._run([str(report_path), "--repo-root", tmp])
            self.assertEqual(code, 0)
            self.assertTrue(json.loads(out)["findings"][0]["suppressed"])


class ConsistencyTests(unittest.TestCase):
    """Nothing else would catch these drifting apart from what 001's
    finding schema actually defines — same pattern as plan 002/003's
    cross-repo consistency checks."""

    def test_finding_schema_requires_finding_id(self) -> None:
        finding_schema = json.loads((SCHEMA_DIR / "finding.schema.json").read_text(encoding="utf-8"))
        self.assertIn("findingId", finding_schema["required"])

    def test_finding_schema_requires_suppressed_field(self) -> None:
        finding_schema = json.loads((SCHEMA_DIR / "finding.schema.json").read_text(encoding="utf-8"))
        self.assertIn("suppressed", finding_schema["required"])


class CrossPlatformEncodingTests(unittest.TestCase):
    """Regression guard for plan 022 — see schema/test_renderers.py's
    class of the same name for the full rationale."""

    def test_exceptions_schema_contains_non_ascii_and_still_reads_cleanly(self) -> None:
        content = (DECISION_DIR / "exceptions.schema.json").read_text(encoding="utf-8")
        self.assertIn("—", content)

    def test_round_trip_non_ascii_content_with_explicit_utf8(self) -> None:
        text = "em dash — and middle dot · round-trip"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "roundtrip.txt"
            path.write_text(text, encoding="utf-8")
            self.assertEqual(path.read_text(encoding="utf-8"), text)


class SourceEncodingAuditTests(unittest.TestCase):
    """Static-analysis regression guard — see schema/test_renderers.py's
    class of the same name. Scans every .py file in this directory."""

    def test_no_read_or_write_text_call_omits_encoding(self) -> None:
        import ast

        violations = []
        for path in sorted(DECISION_DIR.glob("*.py")):
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
