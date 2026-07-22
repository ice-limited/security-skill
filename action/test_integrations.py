"""Tests for the Action Layer's Integration builder: gate-verdict
derivation, ticket/notification generation per policy action, schema
conformance, the CLI's exit-code contract, and a static-analysis proof
(per มิ้นท์'s requirement at this plan's kickoff) that no code path in
this module performs network I/O or shells out to `git`/`gh`.

Run with: python3 -m unittest test_integrations -v (from inside
action/).
"""

from __future__ import annotations

import ast
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import integrations
from integrations import IntegrationError, build_integrations

ACTION_DIR = Path(__file__).parent
SECURITY_SKILL_DIR = next(p for p in ACTION_DIR.resolve().parents if (p / "common").is_dir())
SCHEMA_DIR = SECURITY_SKILL_DIR / "schema"
POLICY_DIR = SECURITY_SKILL_DIR / "policy"


def _load_module(path: Path, alias: str):
    """See action/test_remediation.py's identical helper — loads a
    module from an arbitrary path under a unique sys.modules alias, so
    this file can import schema/validate.py's `validate_integration`
    without colliding with this directory's own validate.py (which
    this test file never imports, but keeping the same defensive
    pattern avoids depending on that staying true)."""
    parent = str(path.parent)
    if parent not in sys.path:
        sys.path.insert(0, parent)
    spec = importlib.util.spec_from_file_location(alias, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[alias] = module
    spec.loader.exec_module(module)
    return module


_schema_validate = _load_module(SCHEMA_DIR / "validate.py", "_schema_validate_for_integration_tests")
validate_integration = _schema_validate.validate_integration

if str(POLICY_DIR) not in sys.path:
    sys.path.insert(0, str(POLICY_DIR))
import engine as policy_engine  # noqa: E402


def _finding(finding_id: str, severity: str, sub_skill: str = "iac", rule_id: str = "iac.example-rule") -> dict:
    return {
        "findingId": finding_id,
        "ruleId": rule_id,
        "subSkill": sub_skill,
        "artifactType": "terraform",
        "title": f"Example finding {finding_id}",
        "problem": "Something insecure was found.",
        "impact": "Could be exploited.",
        "recommendation": "Fix it.",
        "references": [{"standard": "CWE", "id": "CWE-16"}, {"standard": "OWASP-Top10", "id": "A05:2021"}],
        "severity": severity,
        "confidence": 90,
        "location": {"file": "main.tf", "startLine": 3, "endLine": 3},
        "detectorSource": {"name": "test", "version": "1.0.0"},
        "suppressed": False,
    }


def _report(findings: list[dict]) -> dict:
    return {
        "schemaVersion": "1.2.0",
        "scanId": "scan-1",
        "repository": "cpmatch/example",
        "timestamp": "2026-07-23T00:00:00Z",
        "toolVersion": "1.0.0",
        "summary": {"total": len(findings), "bySeverity": {}},
        "findings": findings,
    }


_POLICY = policy_engine.load_default_policy()


class GateVerdictTests(unittest.TestCase):
    def test_block_merge_when_critical_finding_present(self) -> None:
        report = _report([_finding("f1", "Critical")])
        verdict = policy_engine.evaluate_report(report, _POLICY)
        records = build_integrations(report, verdict)
        gate = records[0]
        self.assertEqual(gate["kind"], "gate-verdict")
        self.assertEqual(gate["aggregateAction"], "block-merge")
        self.assertTrue(gate["shouldBlockMerge"])
        self.assertEqual(gate["findingCount"], 1)

    def test_no_block_when_only_low_severity(self) -> None:
        report = _report([_finding("f1", "Low")])
        verdict = policy_engine.evaluate_report(report, _POLICY)
        records = build_integrations(report, verdict)
        gate = records[0]
        self.assertEqual(gate["aggregateAction"], "notify")
        self.assertFalse(gate["shouldBlockMerge"])

    def test_no_findings_gives_none_action_and_no_block(self) -> None:
        report = _report([])
        verdict = policy_engine.evaluate_report(report, _POLICY)
        records = build_integrations(report, verdict)
        gate = records[0]
        self.assertEqual(gate["aggregateAction"], "none")
        self.assertFalse(gate["shouldBlockMerge"])
        self.assertEqual(gate["findingCount"], 0)
        self.assertEqual(len(records), 1)  # gate-verdict only, no ticket/notification


class PerFindingRecordTests(unittest.TestCase):
    def test_medium_finding_gets_a_ticket_only(self) -> None:
        report = _report([_finding("f1", "Medium")])
        verdict = policy_engine.evaluate_report(report, _POLICY)
        records = build_integrations(report, verdict)
        self.assertEqual(len(records), 2)
        ticket = records[1]
        self.assertEqual(ticket["kind"], "ticket")
        self.assertEqual(ticket["findingId"], "f1")
        self.assertIn("CWE CWE-16", ticket["description"])
        self.assertIn("OWASP-Top10 A05:2021", ticket["description"])
        self.assertEqual(ticket["severity"], "Medium")
        self.assertIn("severity:medium", ticket["labels"])
        self.assertIn("iac", ticket["labels"])

    def test_low_finding_gets_a_notification_only(self) -> None:
        report = _report([_finding("f1", "Low")])
        verdict = policy_engine.evaluate_report(report, _POLICY)
        records = build_integrations(report, verdict)
        self.assertEqual(len(records), 2)
        notification = records[1]
        self.assertEqual(notification["kind"], "notification")
        self.assertEqual(notification["findingId"], "f1")
        self.assertEqual(notification["severity"], "Low")

    def test_critical_finding_gets_no_separate_ticket_or_notification(self) -> None:
        # No-cascading decision at kickoff: block-merge/require-review
        # findings are folded into the gate verdict only.
        report = _report([_finding("f1", "Critical")])
        verdict = policy_engine.evaluate_report(report, _POLICY)
        records = build_integrations(report, verdict)
        self.assertEqual(len(records), 1)

    def test_high_finding_gets_no_separate_ticket_or_notification(self) -> None:
        report = _report([_finding("f1", "High")])
        verdict = policy_engine.evaluate_report(report, _POLICY)
        records = build_integrations(report, verdict)
        self.assertEqual(len(records), 1)

    def test_info_finding_gets_nothing_beyond_gate_verdict(self) -> None:
        report = _report([_finding("f1", "Info")])
        verdict = policy_engine.evaluate_report(report, _POLICY)
        records = build_integrations(report, verdict)
        self.assertEqual(len(records), 1)

    def test_mixed_severities_produce_one_record_per_actionable_finding(self) -> None:
        report = _report(
            [
                _finding("f-crit", "Critical"),
                _finding("f-med", "Medium"),
                _finding("f-low", "Low"),
                _finding("f-info", "Info"),
            ]
        )
        verdict = policy_engine.evaluate_report(report, _POLICY)
        records = build_integrations(report, verdict)
        kinds = [r["kind"] for r in records]
        self.assertEqual(kinds.count("gate-verdict"), 1)
        self.assertEqual(kinds.count("ticket"), 1)
        self.assertEqual(kinds.count("notification"), 1)
        self.assertEqual(len(records), 3)

    def test_suppressed_finding_is_excluded_entirely(self) -> None:
        finding = _finding("f1", "Critical")
        finding["suppressed"] = True
        report = _report([finding])
        verdict = policy_engine.evaluate_report(report, _POLICY)
        records = build_integrations(report, verdict)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["aggregateAction"], "none")

    def test_verdict_referencing_unknown_finding_id_raises(self) -> None:
        report = _report([_finding("f1", "Medium")])
        verdict = {"perFinding": [{"findingId": "does-not-exist", "severity": "Medium", "action": "create-ticket"}], "aggregateAction": "create-ticket"}
        with self.assertRaises(IntegrationError):
            build_integrations(report, verdict)


class SchemaConformanceTests(unittest.TestCase):
    def test_gate_verdict_validates(self) -> None:
        report = _report([_finding("f1", "Critical")])
        verdict = policy_engine.evaluate_report(report, _POLICY)
        records = build_integrations(report, verdict)
        self.assertEqual(validate_integration(records[0]), [])

    def test_ticket_validates(self) -> None:
        report = _report([_finding("f1", "Medium")])
        verdict = policy_engine.evaluate_report(report, _POLICY)
        records = build_integrations(report, verdict)
        self.assertEqual(validate_integration(records[1]), [])

    def test_notification_validates(self) -> None:
        report = _report([_finding("f1", "Low")])
        verdict = policy_engine.evaluate_report(report, _POLICY)
        records = build_integrations(report, verdict)
        self.assertEqual(validate_integration(records[1]), [])

    def test_validator_actually_rejects_an_invalid_integration(self) -> None:
        bad = {"kind": "ticket"}  # missing every other required field
        errors = validate_integration(bad)
        self.assertNotEqual(errors, [])

    def test_validator_rejects_unknown_kind(self) -> None:
        bad = {"kind": "carrier-pigeon", "findingId": "f1", "text": "x", "severity": "Low"}
        errors = validate_integration(bad)
        self.assertNotEqual(errors, [])


class MainCliTests(unittest.TestCase):
    def _write_report(self, report: dict) -> Path:
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8")
        json.dump(report, tmp)
        tmp.close()
        return Path(tmp.name)

    def test_exits_1_and_blocks_when_critical_finding_present(self) -> None:
        report = _report([_finding("f1", "Critical")])
        path = self._write_report(report)
        try:
            out = io.StringIO()
            with redirect_stdout(out):
                code = integrations.main([str(path)])
            self.assertEqual(code, 1)
            records = json.loads(out.getvalue())
            self.assertTrue(records[0]["shouldBlockMerge"])
        finally:
            path.unlink()

    def test_exits_0_when_no_blocking_findings(self) -> None:
        report = _report([_finding("f1", "Low")])
        path = self._write_report(report)
        try:
            out = io.StringIO()
            with redirect_stdout(out):
                code = integrations.main([str(path)])
            self.assertEqual(code, 0)
        finally:
            path.unlink()

    def test_missing_report_file_returns_1(self) -> None:
        err = io.StringIO()
        with redirect_stderr(err):
            code = integrations.main(["/no/such/report.json"])
        self.assertEqual(code, 1)
        self.assertIn("INTEGRATION ERROR", err.getvalue())


class SourceEncodingAuditTests(unittest.TestCase):
    """See common/test_common.py's class of the same name — same static
    check applied to this directory's new module."""

    def test_no_read_or_write_text_call_omits_encoding(self) -> None:
        violations = []
        tree = ast.parse((ACTION_DIR / "integrations.py").read_text(encoding="utf-8"), filename="integrations.py")
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in ("read_text", "write_text")
            ):
                kwarg_names = {kw.arg for kw in node.keywords}
                if "encoding" not in kwarg_names:
                    violations.append(f"integrations.py:{node.lineno} .{node.func.attr}() missing encoding=")
        self.assertEqual(violations, [])


class NoNetworkOrSubprocessIoTests(unittest.TestCase):
    """Static-analysis proof, per มิ้นท์'s explicit requirement at this
    plan's kickoff, that this module never performs network I/O or
    shells out to `git`/`gh` — the whole point of staying a pure data
    generator is undermined if this is merely asserted in a docstring
    rather than actually checked."""

    _FORBIDDEN_MODULES = frozenset(
        {"requests", "urllib", "urllib2", "http", "httpx", "socket", "subprocess", "os"}
    )

    def test_no_forbidden_imports(self) -> None:
        tree = ast.parse((ACTION_DIR / "integrations.py").read_text(encoding="utf-8"), filename="integrations.py")
        found = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top_level = alias.name.split(".")[0]
                    if top_level in self._FORBIDDEN_MODULES:
                        found.add(top_level)
            elif isinstance(node, ast.ImportFrom) and node.module:
                top_level = node.module.split(".")[0]
                if top_level in self._FORBIDDEN_MODULES:
                    found.add(top_level)
        self.assertEqual(found, set())

    def test_no_subprocess_or_git_gh_calls(self) -> None:
        tree = ast.parse((ACTION_DIR / "integrations.py").read_text(encoding="utf-8"), filename="integrations.py")
        violations = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
                if name in ("run", "Popen", "call", "check_call", "check_output", "system", "popen"):
                    violations.append(f"integrations.py:{node.lineno} calls {name}()")
        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()
