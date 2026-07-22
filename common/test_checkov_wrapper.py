"""Tests for common/checkov_wrapper.py — the shared Checkov subprocess
wrapper and result-to-finding.schema.json mapping used by both
detectors/iac/scanner.py (011) and detectors/cicd/scanner.py (013).

detector-specific behavior (each plan's own curated rule catalog) is
exercised more thoroughly in each detector's own test_*.py — this file
focuses on the generic logic itself, especially the parametrization
axis a single consumer's tests don't exercise: two independent rule
catalogs/frameworks producing genuinely independent results.

Run with: python3 -m unittest test_checkov_wrapper -v (from inside
common/).
"""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import checkov_wrapper as cw


def _checkov_available() -> bool:
    return shutil.which("checkov") is not None


class _Rule:
    def __init__(self, rule_id: str, check_ids: dict[str, str]) -> None:
        self.rule_id = rule_id
        self.title = "title"
        self.problem = "problem"
        self.impact = "impact"
        self.recommendation = "recommendation"
        self.references: list[dict] = []
        self.severity = "High"
        self.confidence = 80
        self.check_ids = check_ids


class BuildCheckIdIndexTests(unittest.TestCase):
    def test_single_framework_rule_indexes_once(self) -> None:
        rule = _Rule("iac.thing", {"terraform": "CKV_X_1"})
        index = cw.build_check_id_index([rule])
        self.assertEqual(index, {("terraform", "CKV_X_1"): rule})

    def test_multi_framework_rule_indexes_once_per_framework(self) -> None:
        rule = _Rule("iac.thing", {"terraform": "CKV_X_1", "cloudformation": "CKV_X_2"})
        index = cw.build_check_id_index([rule])
        self.assertEqual(set(index.keys()), {("terraform", "CKV_X_1"), ("cloudformation", "CKV_X_2")})
        self.assertIs(index[("terraform", "CKV_X_1")], rule)
        self.assertIs(index[("cloudformation", "CKV_X_2")], rule)


class FindingIdTests(unittest.TestCase):
    def test_deterministic_for_identical_input(self) -> None:
        a = cw.finding_id("iac", "iac.x", "main.tf", 1, 1, "CKV_X_1")
        b = cw.finding_id("iac", "iac.x", "main.tf", 1, 1, "CKV_X_1")
        self.assertEqual(a, b)

    def test_id_prefix_is_used_verbatim(self) -> None:
        self.assertTrue(cw.finding_id("iac", "iac.x", "f", 1, 1, "d").startswith("iac-"))
        self.assertTrue(cw.finding_id("cicd", "cicd.x", "f", 1, 1, "d").startswith("cicd-"))

    def test_distinct_discriminators_get_distinct_ids(self) -> None:
        a = cw.finding_id("iac", "iac.x", "f", 1, 1, "CKV_X_1")
        b = cw.finding_id("iac", "iac.x", "f", 1, 1, "CKV_X_2")
        self.assertNotEqual(a, b)


class MapCheckovCheckTests(unittest.TestCase):
    """rule_catalog_index/sub_skill/id_prefix/detector_name are this
    module's own parametrization surface — two independent detectors
    (011, 013) using genuinely independent catalogs/frameworks needs
    direct coverage here, not just each detector's own single-catalog
    tests."""

    def _check(self, check_id: str, file_abs_path: str = "/some/file", start=10, end=20) -> dict:
        return {"check_id": check_id, "file_abs_path": file_abs_path, "file_line_range": [start, end]}

    def test_unknown_check_id_returns_none(self) -> None:
        result = cw.map_checkov_check(
            self._check("SOME-UNMAPPED-ID"), "terraform", "3.3.8",
            sub_skill="iac", rule_catalog_index={}, id_prefix="iac", detector_name="iac-checkov-wrapper",
        )
        self.assertIsNone(result)

    def test_two_distinct_catalogs_produce_independent_rule_ids(self) -> None:
        iac_rule = _Rule("iac.thing", {"terraform": "SAME-ID"})
        cicd_rule = _Rule("cicd.thing", {"github_actions": "SAME-ID"})

        iac_finding = cw.map_checkov_check(
            self._check("SAME-ID", "/repo/main.tf"), "terraform", "3.3.8",
            sub_skill="iac", rule_catalog_index=cw.build_check_id_index([iac_rule]),
            id_prefix="iac", detector_name="iac-checkov-wrapper",
        )
        cicd_finding = cw.map_checkov_check(
            self._check("SAME-ID", "/repo/.github/workflows/ci.yml"), "github_actions", "3.3.8",
            sub_skill="cicd", rule_catalog_index=cw.build_check_id_index([cicd_rule]),
            id_prefix="cicd", detector_name="cicd-checkov-wrapper",
        )
        self.assertEqual(iac_finding["ruleId"], "iac.thing")
        self.assertEqual(iac_finding["subSkill"], "iac")
        self.assertEqual(iac_finding["artifactType"], "terraform")
        self.assertEqual(cicd_finding["ruleId"], "cicd.thing")
        self.assertEqual(cicd_finding["subSkill"], "cicd")
        self.assertEqual(cicd_finding["artifactType"], "github_actions")
        self.assertNotEqual(iac_finding["findingId"], cicd_finding["findingId"])

    def test_same_check_id_different_framework_is_not_confused(self) -> None:
        # A check_id curated only under "github_actions" must not
        # accidentally match if the same raw ID string were ever seen
        # tagged as "gitlab_ci" (mirrors 011's own cross-framework-ID
        # nuance, generalized here for the shared index).
        rule = _Rule("cicd.gha-thing", {"github_actions": "CKV_SOMETHING_1"})
        index = cw.build_check_id_index([rule])
        result = cw.map_checkov_check(
            self._check("CKV_SOMETHING_1"), "gitlab_ci", "3.3.8",
            sub_skill="cicd", rule_catalog_index=index, id_prefix="cicd", detector_name="cicd-checkov-wrapper",
        )
        self.assertIsNone(result)

    def test_missing_file_line_range_defaults_to_line_1(self) -> None:
        rule = _Rule("iac.thing", {"terraform": "SOME-ID"})
        check = {"check_id": "SOME-ID", "file_abs_path": "/some/file.tf"}
        finding = cw.map_checkov_check(
            check, "terraform", "3.3.8",
            sub_skill="iac", rule_catalog_index=cw.build_check_id_index([rule]),
            id_prefix="iac", detector_name="iac-checkov-wrapper",
        )
        self.assertEqual(finding["location"], {"file": "/some/file.tf", "startLine": 1, "endLine": 1})

    def test_zero_indexed_graph_check_line_range_is_clamped_to_1(self) -> None:
        # Real quirk found at 013's implementation: Checkov's graph
        # checks (CKV2_*, e.g. github_actions' CKV2_GHA_1) report a
        # 0-indexed file_line_range, unlike regular (CKV_*) checks —
        # finding.schema.json requires startLine >= 1 regardless.
        rule = _Rule("cicd-pipeline.thing", {"github_actions": "CKV2_SOMETHING_1"})
        check = {"check_id": "CKV2_SOMETHING_1", "file_abs_path": "/some/workflow.yml", "file_line_range": [0, 1]}
        finding = cw.map_checkov_check(
            check, "github_actions", "3.3.8",
            sub_skill="cicd-pipeline", rule_catalog_index=cw.build_check_id_index([rule]),
            id_prefix="cicd-pipeline", detector_name="cicd-pipeline-checkov-wrapper",
        )
        self.assertEqual(finding["location"], {"file": "/some/workflow.yml", "startLine": 1, "endLine": 1})

    def test_artifact_type_map_translates_when_provided(self) -> None:
        rule = _Rule("cicd-pipeline.thing", {"github_actions": "SOME-ID"})
        check = self._check("SOME-ID", "/repo/.github/workflows/ci.yml")
        finding = cw.map_checkov_check(
            check, "github_actions", "3.3.8",
            sub_skill="cicd-pipeline", rule_catalog_index=cw.build_check_id_index([rule]),
            id_prefix="cicd-pipeline", detector_name="cicd-pipeline-checkov-wrapper",
            artifact_type_map={"github_actions": "github-actions", "gitlab_ci": "gitlab-ci"},
        )
        self.assertEqual(finding["artifactType"], "github-actions")

    def test_artifact_type_passes_through_unchanged_without_a_map(self) -> None:
        # 011's own frameworks (terraform/cloudformation/ansible) never
        # pass artifact_type_map at all — verifies the default (no map)
        # behavior stays identity, matching 011's pre-013 behavior
        # exactly (no regression from adding this parameter).
        rule = _Rule("iac.thing", {"terraform": "SOME-ID"})
        check = self._check("SOME-ID", "/repo/main.tf")
        finding = cw.map_checkov_check(
            check, "terraform", "3.3.8",
            sub_skill="iac", rule_catalog_index=cw.build_check_id_index([rule]),
            id_prefix="iac", detector_name="iac-checkov-wrapper",
        )
        self.assertEqual(finding["artifactType"], "terraform")


class ResolveFilePathTests(unittest.TestCase):
    def test_relative_path_becomes_absolute(self) -> None:
        check = {"file_abs_path": "template.yaml"}
        resolved = cw._resolve_file_path(check)
        self.assertTrue(Path(resolved).is_absolute(), resolved)
        self.assertTrue(resolved.endswith("template.yaml"))

    def test_already_absolute_path_stays_correct(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            real_file = Path(tmp) / "main.tf"
            real_file.write_text("", encoding="utf-8")
            check = {"file_abs_path": str(real_file)}
            resolved = cw._resolve_file_path(check)
        self.assertEqual(Path(resolved), real_file.resolve())


class RunCheckovTests(unittest.TestCase):
    def test_missing_binary_raises_actionable_error(self) -> None:
        with mock.patch("checkov_wrapper.shutil.which", return_value=None):
            with self.assertRaises(cw.ScannerError) as ctx:
                cw.run_checkov("irrelevant", ("terraform",))
        self.assertIn("pip install checkov", str(ctx.exception))

    def test_nonexistent_path_raises_before_invoking_checkov(self) -> None:
        with mock.patch("checkov_wrapper.subprocess.run") as mocked_run:
            with self.assertRaises(cw.ScannerError):
                cw.run_checkov("/tmp/definitely-does-not-exist-checkov-wrapper", ("terraform",))
        mocked_run.assert_not_called()

    def test_returncode_two_raises(self) -> None:
        fake_proc = mock.Mock(returncode=2, stdout="", stderr="mocked CLI error")
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch("checkov_wrapper.subprocess.run", return_value=fake_proc):
                with self.assertRaises(cw.ScannerError):
                    cw.run_checkov(tmp, ("terraform",))

    def test_returncode_zero_and_one_are_both_accepted(self) -> None:
        for code in (0, 1):
            fake_proc = mock.Mock(
                returncode=code,
                stdout='{"passed": 0, "failed": 0, "skipped": 0, "parsing_errors": 0, "resource_count": 0, "checkov_version": "3.3.8"}',
                stderr="",
            )
            with tempfile.TemporaryDirectory() as tmp:
                with mock.patch("checkov_wrapper.subprocess.run", return_value=fake_proc):
                    self.assertEqual(cw.run_checkov(tmp, ("terraform",)), [])

    def test_frameworks_passed_through_to_the_cli_invocation(self) -> None:
        fake_proc = mock.Mock(returncode=0, stdout="{}", stderr="")
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch("checkov_wrapper.subprocess.run", return_value=fake_proc) as mocked_run:
                cw.run_checkov(tmp, ("github_actions", "gitlab_ci"))
        cmd = mocked_run.call_args[0][0]
        framework_index = cmd.index("--framework")
        self.assertEqual(cmd[framework_index + 1 : framework_index + 3], ["github_actions", "gitlab_ci"])


class RunCheckovOutputNormalizationTests(unittest.TestCase):
    def _run_with_stdout(self, stdout: str):
        fake_proc = mock.Mock(returncode=0, stdout=stdout, stderr="")
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch("checkov_wrapper.subprocess.run", return_value=fake_proc):
                return cw.run_checkov(tmp, ("terraform",))

    def test_bare_summary_dict_with_no_check_type_normalizes_to_empty_list(self) -> None:
        result = self._run_with_stdout(
            '{"passed": 0, "failed": 0, "skipped": 0, "parsing_errors": 0, "resource_count": 0, "checkov_version": "3.3.8"}'
        )
        self.assertEqual(result, [])

    def test_single_dict_with_check_type_normalizes_to_one_element_list(self) -> None:
        result = self._run_with_stdout('{"check_type": "terraform", "results": {"failed_checks": []}, "summary": {}}')
        self.assertEqual(len(result), 1)

    def test_list_of_dicts_passes_through_unchanged(self) -> None:
        result = self._run_with_stdout(
            '[{"check_type": "terraform", "results": {"failed_checks": []}, "summary": {}}, '
            '{"check_type": "ansible", "results": {"failed_checks": []}, "summary": {}}]'
        )
        self.assertEqual(len(result), 2)


@unittest.skipUnless(_checkov_available(), "requires the real checkov CLI on PATH")
class RealCheckovInvocationTests(unittest.TestCase):
    def test_real_invocation_against_a_clean_terraform_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "main.tf"
            path.write_text('resource "aws_s3_bucket" "b" { bucket = "x" }\n', encoding="utf-8")
            results = cw.run_checkov(str(tmp), ("terraform",))
        self.assertTrue(any(r.get("check_type") == "terraform" for r in results))


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

        common_dir = Path(__file__).parent
        violations = []
        for path in sorted(common_dir.glob("*.py")):
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
