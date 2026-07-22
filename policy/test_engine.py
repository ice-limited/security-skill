"""Tests for the policy engine: schema validity, evaluation logic,
override resolution, and cross-file consistency.

Run with: python3 -m unittest test_engine -v (from inside policy/).
"""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from jsonschema import Draft202012Validator

import engine
from validate import validate_policy

POLICY_DIR = Path(__file__).parent
SCHEMA_DIR = POLICY_DIR.parent / "schema"

VALID_POLICY = {
    "policyVersion": "1.0.0",
    "actions": {
        "Critical": "block-merge",
        "High": "require-review",
        "Medium": "create-ticket",
        "Low": "notify",
        "Info": "none",
    },
}


def _finding(finding_id: str, severity: str, suppressed: bool = False) -> dict:
    return {"findingId": finding_id, "severity": severity, "suppressed": suppressed}


class SchemaSelfCheckTests(unittest.TestCase):
    def test_policy_schema_is_valid_json_schema(self) -> None:
        schema = json.loads((POLICY_DIR / "policy.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)

    def test_default_policy_validates(self) -> None:
        default = json.loads((POLICY_DIR / "default-policy.json").read_text(encoding="utf-8"))
        self.assertEqual(validate_policy(default), [])

    def test_default_policy_matches_spec(self) -> None:
        # CONTEXT.md §9: Critical->block merge, High->require review,
        # Medium->create ticket, Low->notify. Info->none is this repo's
        # own addition (no "do nothing" case named in the spec).
        default = json.loads((POLICY_DIR / "default-policy.json").read_text(encoding="utf-8"))
        self.assertEqual(
            default["actions"],
            {
                "Critical": "block-merge",
                "High": "require-review",
                "Medium": "create-ticket",
                "Low": "notify",
                "Info": "none",
            },
        )


class ValidationTests(unittest.TestCase):
    def test_valid_policy_has_no_errors(self) -> None:
        self.assertEqual(validate_policy(VALID_POLICY), [])

    def test_missing_severity_is_rejected(self) -> None:
        policy = json.loads(json.dumps(VALID_POLICY))
        del policy["actions"]["Info"]
        errors = validate_policy(policy)
        self.assertTrue(errors)

    def test_invalid_action_value_is_rejected(self) -> None:
        policy = json.loads(json.dumps(VALID_POLICY))
        policy["actions"]["Critical"] = "delete-repo"
        errors = validate_policy(policy)
        self.assertTrue(errors)

    def test_unknown_severity_key_is_rejected(self) -> None:
        policy = json.loads(json.dumps(VALID_POLICY))
        policy["actions"]["Extreme"] = "block-merge"
        errors = validate_policy(policy)
        self.assertTrue(errors)


class EvaluateTests(unittest.TestCase):
    def test_each_severity_maps_to_its_configured_action(self) -> None:
        findings = [_finding(f"f-{s}", s) for s in engine.SEVERITY_ORDER]
        result = engine.evaluate(findings, VALID_POLICY)
        actions = {d["severity"]: d["action"] for d in result["perFinding"]}
        self.assertEqual(actions, VALID_POLICY["actions"])

    def test_suppressed_findings_are_skipped_entirely(self) -> None:
        findings = [_finding("f-1", "Critical", suppressed=True)]
        result = engine.evaluate(findings, VALID_POLICY)
        self.assertEqual(result["perFinding"], [])
        self.assertEqual(result["aggregateAction"], "none")

    def test_aggregate_is_strictest_action_across_findings(self) -> None:
        # One Critical among a pile of Infos still blocks the merge.
        findings = [_finding("f-1", "Info")] * 9 + [_finding("f-2", "Critical")]
        result = engine.evaluate(findings, VALID_POLICY)
        self.assertEqual(result["aggregateAction"], "block-merge")

    def test_aggregate_ignores_suppressed_when_computing_strictest(self) -> None:
        findings = [
            _finding("f-1", "Critical", suppressed=True),
            _finding("f-2", "Medium"),
        ]
        result = engine.evaluate(findings, VALID_POLICY)
        self.assertEqual(result["aggregateAction"], "create-ticket")

    def test_empty_findings_list_yields_none(self) -> None:
        result = engine.evaluate([], VALID_POLICY)
        self.assertEqual(result, {"perFinding": [], "aggregateAction": "none"})

    def test_all_suppressed_yields_none(self) -> None:
        findings = [_finding("f-1", "Critical", suppressed=True), _finding("f-2", "High", suppressed=True)]
        result = engine.evaluate(findings, VALID_POLICY)
        self.assertEqual(result["aggregateAction"], "none")

    def test_evaluate_report_extracts_findings_from_envelope(self) -> None:
        report = {"findings": [_finding("f-1", "High")]}
        result = engine.evaluate_report(report, VALID_POLICY)
        self.assertEqual(result["aggregateAction"], "require-review")

    def test_per_finding_preserves_input_order(self) -> None:
        # Not documented behavior anyone asked for, but locking it in as
        # a regression guard: a future "optimization" that groups by
        # severity would silently reorder output consumers may depend on.
        findings = [_finding("f-low", "Low"), _finding("f-crit", "Critical"), _finding("f-med", "Medium")]
        result = engine.evaluate(findings, VALID_POLICY)
        self.assertEqual([d["findingId"] for d in result["perFinding"]], ["f-low", "f-crit", "f-med"])

    def test_every_pairwise_severity_produces_correct_relative_strictness(self) -> None:
        # test_aggregate_is_strictest_action_across_findings only proves
        # Critical beats Info. This proves the full order is actually
        # Critical > High > Medium > Low > Info, not just "the ends."
        for stricter, looser in zip(engine.SEVERITY_ORDER, engine.SEVERITY_ORDER[1:]):
            findings = [_finding("f-a", looser), _finding("f-b", stricter)]
            result = engine.evaluate(findings, VALID_POLICY)
            self.assertEqual(
                result["aggregateAction"],
                VALID_POLICY["actions"][stricter],
                f"{stricter} should have outranked {looser}",
            )

    def test_evaluate_trusts_its_policy_argument_rather_than_defaulting(self) -> None:
        # evaluate() doesn't validate `policy` itself (validate.py/
        # resolve_policy do that) — document and lock in that an
        # incomplete policy fails loud (KeyError) rather than silently
        # picking some default action for the missing severity.
        incomplete_policy = {"policyVersion": "1.0.0", "actions": {"Critical": "block-merge"}}
        with self.assertRaises(KeyError):
            engine.evaluate([_finding("f-1", "Info")], incomplete_policy)

    def test_evaluate_report_handles_missing_findings_key(self) -> None:
        result = engine.evaluate_report({}, VALID_POLICY)
        self.assertEqual(result, {"perFinding": [], "aggregateAction": "none"})


class ResolvePolicyTests(unittest.TestCase):
    def test_no_repo_root_returns_default(self) -> None:
        self.assertEqual(engine.resolve_policy(), engine.load_default_policy())

    def test_repo_root_without_override_file_returns_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(engine.resolve_policy(tmp), engine.load_default_policy())

    def test_repo_root_with_valid_override_returns_override_exactly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            override_dir = Path(tmp) / ".security-skill"
            override_dir.mkdir()
            custom = {
                "policyVersion": "1.0.0",
                "actions": {
                    "Critical": "block-merge",
                    "High": "block-merge",  # stricter than default, on purpose
                    "Medium": "notify",  # looser than default, on purpose
                    "Low": "none",
                    "Info": "none",
                },
            }
            (override_dir / "policy.json").write_text(json.dumps(custom), encoding="utf-8")

            resolved = engine.resolve_policy(tmp)
            self.assertEqual(resolved, custom)
            self.assertNotEqual(resolved, engine.load_default_policy())

    def test_repo_root_with_invalid_override_raises_rather_than_falling_back(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            override_dir = Path(tmp) / ".security-skill"
            override_dir.mkdir()
            incomplete = {"policyVersion": "1.0.0", "actions": {"Critical": "block-merge"}}
            (override_dir / "policy.json").write_text(json.dumps(incomplete), encoding="utf-8")

            with self.assertRaises(engine.PolicyError):
                engine.resolve_policy(tmp)

    def test_repo_root_with_malformed_json_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            override_dir = Path(tmp) / ".security-skill"
            override_dir.mkdir()
            (override_dir / "policy.json").write_text("{not valid json", encoding="utf-8")

            with self.assertRaises(engine.PolicyError):
                engine.resolve_policy(tmp)

    def test_security_skill_dir_present_but_no_policy_file_returns_default(self) -> None:
        # The .security-skill/ directory might exist for unrelated
        # reasons (e.g. a future 004 exceptions file) without a
        # policy.json in it — must not be mistaken for "override present".
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / ".security-skill").mkdir()
            self.assertEqual(engine.resolve_policy(tmp), engine.load_default_policy())


class LoaderTests(unittest.TestCase):
    def test_load_default_policy_matches_file_on_disk(self) -> None:
        on_disk = json.loads((POLICY_DIR / "default-policy.json").read_text(encoding="utf-8"))
        self.assertEqual(engine.load_default_policy(), on_disk)

    def test_load_repo_policy_returns_none_when_no_override_dir_at_all(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(engine.load_repo_policy(Path(tmp)))


class CliTests(unittest.TestCase):
    """Exercises main() directly (canned argv, real temp files) instead
    of shelling out — faster and isolates CLI logic from subprocess
    plumbing, same rationale as check_freshness.py's MainCliTests."""

    def _run(self, argv: list[str]) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = engine.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_success_prints_json_result_and_returns_0(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "report.json"
            report_path.write_text(json.dumps({"findings": [_finding("f-1", "Critical")]}), encoding="utf-8")

            code, out, err = self._run([str(report_path)])

            self.assertEqual(code, 0)
            self.assertEqual(err, "")
            parsed = json.loads(out)
            self.assertEqual(parsed["aggregateAction"], "block-merge")

    def test_invalid_repo_override_prints_error_and_returns_1(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "report.json"
            report_path.write_text(json.dumps({"findings": []}), encoding="utf-8")
            override_dir = Path(tmp) / ".security-skill"
            override_dir.mkdir()
            (override_dir / "policy.json").write_text(json.dumps({"policyVersion": "1.0.0", "actions": {}}), encoding="utf-8")

            code, out, err = self._run([str(report_path), "--repo-root", tmp])

            self.assertEqual(code, 1)
            self.assertEqual(out, "")
            self.assertIn("POLICY ERROR", err)

    def test_repo_root_flag_is_actually_applied(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "report.json"
            report_path.write_text(json.dumps({"findings": [_finding("f-1", "Critical")]}), encoding="utf-8")
            override_dir = Path(tmp) / ".security-skill"
            override_dir.mkdir()
            looser = {
                "policyVersion": "1.0.0",
                "actions": {"Critical": "notify", "High": "notify", "Medium": "notify", "Low": "none", "Info": "none"},
            }
            (override_dir / "policy.json").write_text(json.dumps(looser), encoding="utf-8")

            code, out, _ = self._run([str(report_path), "--repo-root", tmp])

            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out)["aggregateAction"], "notify")


class ConsistencyTests(unittest.TestCase):
    """Nothing else would catch these constants drifting apart from the
    schemas they're supposed to mirror — same pattern as plan 002's
    CrossRepoConsistencyTests."""

    def test_action_order_matches_schema_action_enum(self) -> None:
        schema = json.loads((POLICY_DIR / "policy.schema.json").read_text(encoding="utf-8"))
        schema_actions = set(schema["$defs"]["action"]["enum"])
        self.assertEqual(set(engine.ACTION_ORDER), schema_actions)

    def test_severity_order_matches_policy_schema_required_keys(self) -> None:
        schema = json.loads((POLICY_DIR / "policy.schema.json").read_text(encoding="utf-8"))
        required = set(schema["properties"]["actions"]["required"])
        self.assertEqual(set(engine.SEVERITY_ORDER), required)

    def test_severity_order_matches_finding_schema_severity_enum(self) -> None:
        finding_schema = json.loads((SCHEMA_DIR / "finding.schema.json").read_text(encoding="utf-8"))
        severity_enum = set(finding_schema["$defs"]["severity"]["enum"])
        self.assertEqual(set(engine.SEVERITY_ORDER), severity_enum)


class CrossPlatformEncodingTests(unittest.TestCase):
    """Regression guard for plan 022 — see schema/test_renderers.py's
    class of the same name for the full rationale."""

    def test_policy_schema_contains_non_ascii_and_still_reads_cleanly(self) -> None:
        content = (POLICY_DIR / "policy.schema.json").read_text(encoding="utf-8")
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
        for path in sorted(POLICY_DIR.glob("*.py")):
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
