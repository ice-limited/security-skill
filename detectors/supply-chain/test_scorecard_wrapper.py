"""Tests for the OpenSSF Scorecard wrapper: real subprocess calls (not
mocked), curated to `Binary-Artifacts`/`SAST` only, schema conformance,
and error handling — including the real symlink-crash limitation found
at implementation (see this module's own docstring).

Requires the real `scorecard` CLI on PATH (`brew install scorecard`).
Run with: python3 -m unittest test_scorecard_wrapper -v (from inside
detectors/supply-chain/).
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

import scorecard_wrapper
from scorecard_wrapper import ScannerError

DETECTOR_DIR = Path(__file__).parent
SECURITY_SKILL_DIR = next(p for p in DETECTOR_DIR.resolve().parents if (p / "common").is_dir())
SCHEMA_DIR = SECURITY_SKILL_DIR / "schema"

sys.path.insert(0, str(SECURITY_SKILL_DIR / "common"))
from schema_validation import validate_against_schema  # noqa: E402

sys.path.insert(0, str(SECURITY_SKILL_DIR / "knowledge"))
import standards  # noqa: E402


def _scorecard_available() -> bool:
    return shutil.which("scorecard") is not None


@unittest.skipUnless(_scorecard_available(), "requires the real scorecard CLI on PATH")
class RealInvocationTests(unittest.TestCase):
    def test_clean_directory_only_flags_missing_sast(self) -> None:
        # A directory with no binaries and no recognized SAST tool:
        # Binary-Artifacts should score a perfect 10 (no finding), SAST
        # should still fire (no CI config present at all).
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "README.md").write_text("hello", encoding="utf-8")
            findings = scorecard_wrapper.scan_paths([tmp])
        rule_ids = {f["ruleId"] for f in findings}
        self.assertEqual(rule_ids, {"supply-chain.missing-sast-tool"})

    def test_directory_with_compiled_pyc_flags_binary_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pycache = Path(tmp) / "__pycache__"
            pycache.mkdir()
            (pycache / "mod.cpython-312.pyc").write_bytes(b"\x00\x01fake bytecode")
            findings = scorecard_wrapper.scan_paths([tmp])
        rule_ids = {f["ruleId"] for f in findings}
        self.assertIn("supply-chain.binary-artifact-committed", rule_ids)

    def test_symlink_crash_raises_actionable_scanner_error(self) -> None:
        # Real, verified Scorecard limitation found at implementation:
        # a directory containing a symlink escaping its own parent
        # (the shape a macOS Python virtualenv's bin/ directory has)
        # crashes Scorecard's own file walker internally.
        with tempfile.TemporaryDirectory() as tmp:
            venv_bin = Path(tmp) / ".venv" / "bin"
            venv_bin.mkdir(parents=True)
            # Mirrors a real venv: bin/python -> a target outside .venv/bin's own tree.
            (venv_bin / "python").symlink_to(Path(tmp) / "python-outside-venv")
            (Path(tmp) / "python-outside-venv").write_text("", encoding="utf-8")
            with self.assertRaises(ScannerError) as ctx:
                scorecard_wrapper.scan_paths([tmp])
        self.assertIn("failed internally", str(ctx.exception))

    def test_findings_validate_against_finding_schema(self) -> None:
        schema = json.loads((SCHEMA_DIR / "finding.schema.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "README.md").write_text("hello", encoding="utf-8")
            findings = scorecard_wrapper.scan_paths([tmp])
        self.assertTrue(findings)
        for f in findings:
            errors = validate_against_schema(schema, f)
            self.assertEqual(errors, [], f"{f['ruleId']} finding is not schema-valid: {errors}")


class MockedInvocationTests(unittest.TestCase):
    """Pure-mapping tests independent of Scorecard's own real scoring
    behavior for a given directory (which could shift with a Scorecard
    version bump) — isolates _build_finding()'s own logic."""

    def test_perfect_score_produces_no_finding(self) -> None:
        check = {"name": "Binary-Artifacts", "score": 10, "reason": "no binaries found in the repo", "details": None}
        self.assertIsNone(scorecard_wrapper._build_finding(check, "/some/repo"))

    def test_imperfect_score_produces_a_finding(self) -> None:
        check = {"name": "SAST", "score": 0, "reason": "no SAST tool detected", "details": []}
        finding = scorecard_wrapper._build_finding(check, "/some/repo")
        self.assertIsNotNone(finding)
        self.assertEqual(finding["ruleId"], "supply-chain.missing-sast-tool")
        self.assertEqual(finding["metadata"]["scorecardScore"], 0)

    def test_unrecognized_check_name_returns_none(self) -> None:
        check = {"name": "Some-Other-Check", "score": 0, "reason": "x", "details": []}
        self.assertIsNone(scorecard_wrapper._build_finding(check, "/some/repo"))


class ErrorHandlingTests(unittest.TestCase):
    def test_missing_scorecard_raises_actionable_error(self) -> None:
        with mock.patch("scorecard_wrapper.shutil.which", return_value=None):
            with self.assertRaises(ScannerError) as ctx:
                scorecard_wrapper.run_scorecard("irrelevant")
        self.assertIn("brew install scorecard", str(ctx.exception))

    def test_nonexistent_path_raises_before_invoking_scorecard(self) -> None:
        with mock.patch("scorecard_wrapper.subprocess.run") as mocked_run:
            with self.assertRaises(ScannerError):
                scorecard_wrapper.run_scorecard("/tmp/definitely-does-not-exist-014-scorecard")
        mocked_run.assert_not_called()

    def test_non_json_stdout_raises(self) -> None:
        fake_proc = mock.Mock(returncode=0, stdout="not json", stderr="")
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch("scorecard_wrapper.subprocess.run", return_value=fake_proc):
                with self.assertRaises(ScannerError):
                    scorecard_wrapper.run_scorecard(tmp)


class ConsistencyTests(unittest.TestCase):
    def test_every_curated_rule_reference_resolves_in_the_knowledge_base(self) -> None:
        import rules

        for template in (rules.BINARY_ARTIFACT_COMMITTED, rules.MISSING_SAST_TOOL):
            for ref in template["references"]:
                self.assertTrue(standards.exists(ref["standard"], ref["id"]), f"{template['rule_id']} cites {ref}")

    def test_every_curated_check_name_has_a_rule_mapping(self) -> None:
        for check_name in scorecard_wrapper.CHECKS:
            self.assertIn(check_name, scorecard_wrapper._RULE_BY_CHECK_NAME)


@unittest.skipUnless(_scorecard_available(), "requires the real scorecard CLI on PATH")
class MainCliTests(unittest.TestCase):
    def test_prints_findings_as_json_and_returns_0(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "README.md").write_text("hello", encoding="utf-8")
            out = io.StringIO()
            with redirect_stdout(out):
                code = scorecard_wrapper.main([tmp])
        self.assertEqual(code, 0)
        parsed = json.loads(out.getvalue())
        self.assertTrue(parsed)

    def test_missing_scorecard_returns_1_and_prints_error(self) -> None:
        err = io.StringIO()
        with mock.patch("scorecard_wrapper.shutil.which", return_value=None):
            with redirect_stdout(io.StringIO()), redirect_stderr(err):
                code = scorecard_wrapper.main(["irrelevant"])
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
