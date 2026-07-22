"""Tests for common/trivy_wrapper.py — the shared Trivy `config`-scan
subprocess wrapper and result-to-finding.schema.json mapping used by
both detectors/docker/scanner.py (009) and detectors/kubernetes/
scanner.py (010).

detector-specific behavior (each plan's own curated rule catalog) is
exercised more thoroughly in each detector's own test_*.py — this file
focuses on the generic logic itself, especially the parametrization
axes a single consumer's tests don't exercise: `excluded_check_ids`
(009 always passes one, 010 never does) and `iter_scanned_files()`
aggregating across more than one path.

Run with: python3 -m unittest test_trivy_wrapper -v (from inside
common/).
"""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import trivy_wrapper as tw


def _trivy_available() -> bool:
    return shutil.which("trivy") is not None


CLEAN_DOCKERFILE = "FROM alpine:3.20\nUSER nobody\nHEALTHCHECK CMD true\n"
VULNERABLE_DOCKERFILE = "FROM alpine\n"  # unpinned base image (DS-0001)


class SeverityMappingTests(unittest.TestCase):
    def test_known_severities(self) -> None:
        for raw, expected in [("CRITICAL", "Critical"), ("HIGH", "High"), ("MEDIUM", "Medium"), ("LOW", "Low")]:
            self.assertEqual(tw.severity_from_trivy(raw), expected)

    def test_unknown_or_missing_defaults_to_medium(self) -> None:
        self.assertEqual(tw.severity_from_trivy("UNKNOWN"), "Medium")
        self.assertEqual(tw.severity_from_trivy(None), "Medium")
        self.assertEqual(tw.severity_from_trivy(""), "Medium")

    def test_case_insensitive(self) -> None:
        self.assertEqual(tw.severity_from_trivy("high"), "High")


class FindingIdTests(unittest.TestCase):
    def test_deterministic_for_identical_input(self) -> None:
        a = tw.finding_id("docker", "docker.x", "Dockerfile", 1, 1, "DS-0001")
        b = tw.finding_id("docker", "docker.x", "Dockerfile", 1, 1, "DS-0001")
        self.assertEqual(a, b)

    def test_id_prefix_is_used_verbatim(self) -> None:
        self.assertTrue(tw.finding_id("docker", "docker.x", "f", 1, 1, "d").startswith("docker-"))
        self.assertTrue(tw.finding_id("kubernetes", "kubernetes.x", "f", 1, 1, "d").startswith("kubernetes-"))

    def test_distinct_discriminators_get_distinct_ids(self) -> None:
        a = tw.finding_id("docker", "docker.x", "f", 1, 1, "DS-0001")
        b = tw.finding_id("docker", "docker.x", "f", 1, 1, "DS-0002")
        self.assertNotEqual(a, b)


class ResolveTargetPathTests(unittest.TestCase):
    def test_directory_scan_joins_root_and_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = tw.resolve_target_path(tmp, "Dockerfile")
        self.assertEqual(result, Path(tmp) / "Dockerfile")

    def test_single_file_scan_ignores_target_and_uses_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            file_path = Path(tmp) / "Dockerfile"
            file_path.write_text(CLEAN_DOCKERFILE, encoding="utf-8")
            result = tw.resolve_target_path(str(file_path), "Dockerfile")
        self.assertEqual(result, file_path)


class MapTrivyMisconfigTests(unittest.TestCase):
    """rule_catalog/sub_skill/id_prefix/detector_name are this module's
    own parametrization surface — never exercised as *parameters* by
    detectors/docker/'s tests, which only ever pass its one fixed
    catalog, so the fact that two different catalogs/prefixes really
    produce independent results needs direct coverage here."""

    def _misconfig(self, check_id: str, severity: str = "HIGH") -> dict:
        return {"ID": check_id, "Severity": severity, "CauseMetadata": {"StartLine": 3, "EndLine": 5}}

    def test_unknown_check_id_returns_none(self) -> None:
        result = tw.map_trivy_misconfig(
            self._misconfig("SOME-UNMAPPED-ID"),
            "Dockerfile",
            "dockerfile",
            "0.72.0",
            sub_skill="docker",
            rule_catalog={},
            id_prefix="docker",
            detector_name="docker-trivy-wrapper",
        )
        self.assertIsNone(result)

    def test_two_distinct_catalogs_produce_independent_rule_ids(self) -> None:
        class _Rule:
            def __init__(self, rule_id: str) -> None:
                self.rule_id = rule_id
                self.title = "title"
                self.problem = "problem"
                self.impact = "impact"
                self.recommendation = "recommendation"
                self.references: list[dict] = []
                self.confidence = 80

        docker_finding = tw.map_trivy_misconfig(
            self._misconfig("SAME-ID"), "Dockerfile", "dockerfile", "0.72.0",
            sub_skill="docker", rule_catalog={"SAME-ID": _Rule("docker.thing")},
            id_prefix="docker", detector_name="docker-trivy-wrapper",
        )
        k8s_finding = tw.map_trivy_misconfig(
            self._misconfig("SAME-ID"), "deployment.yaml", "kubernetes-yaml", "0.72.0",
            sub_skill="kubernetes", rule_catalog={"SAME-ID": _Rule("kubernetes.thing")},
            id_prefix="kubernetes", detector_name="kubernetes-trivy-wrapper",
        )
        self.assertEqual(docker_finding["ruleId"], "docker.thing")
        self.assertEqual(docker_finding["subSkill"], "docker")
        self.assertEqual(k8s_finding["ruleId"], "kubernetes.thing")
        self.assertEqual(k8s_finding["subSkill"], "kubernetes")
        self.assertNotEqual(docker_finding["findingId"], k8s_finding["findingId"])

    def test_missing_cause_metadata_defaults_to_line_1(self) -> None:
        class _Rule:
            rule_id = "docker.thing"
            title = problem = impact = recommendation = "x"
            references: list[dict] = []
            confidence = 80

        misconfig = {"ID": "SOME-ID", "Severity": "HIGH"}
        finding = tw.map_trivy_misconfig(
            misconfig, "Dockerfile", "dockerfile", "0.72.0",
            sub_skill="docker", rule_catalog={"SOME-ID": _Rule()},
            id_prefix="docker", detector_name="docker-trivy-wrapper",
        )
        self.assertEqual(finding["location"], {"file": "Dockerfile", "startLine": 1, "endLine": 1})


class RunTrivyTests(unittest.TestCase):
    def test_missing_binary_raises_actionable_error(self) -> None:
        with mock.patch("trivy_wrapper.shutil.which", return_value=None):
            with self.assertRaises(tw.ScannerError) as ctx:
                tw.run_trivy("irrelevant")
        self.assertIn("brew install trivy", str(ctx.exception))

    def test_returncode_nonzero_raises_even_with_valid_json_stdout(self) -> None:
        fake_proc = mock.Mock(returncode=1, stdout='{"Results": []}', stderr="mocked failure")
        with mock.patch("trivy_wrapper.subprocess.run", return_value=fake_proc):
            with self.assertRaises(tw.ScannerError):
                tw.run_trivy("irrelevant")

    @unittest.skipUnless(_trivy_available(), "requires the real trivy CLI on PATH")
    def test_runs_with_no_excluded_check_ids_at_all(self) -> None:
        # 010 (Kubernetes) never passes excluded_check_ids — unlike 009,
        # which always excludes DS-0031. Verifies the no-ignorefile path
        # (the default empty tuple) really works against a real trivy
        # invocation, not just the exclusion path 009's own tests cover.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "Dockerfile"
            path.write_text(VULNERABLE_DOCKERFILE, encoding="utf-8")
            output = tw.run_trivy(str(path))
        self.assertIn("Results", output)


class IterScannedFilesTests(unittest.TestCase):
    @unittest.skipUnless(_trivy_available(), "requires the real trivy CLI on PATH")
    def test_yields_a_file_with_zero_findings_too(self) -> None:
        # iter_scanned_files() is documented to yield every file Trivy
        # recognized, even ones with no findings — verified for real
        # here rather than just asserted in the docstring.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "Dockerfile"
            path.write_text(CLEAN_DOCKERFILE, encoding="utf-8")
            files = list(tw.iter_scanned_files([str(tmp)]))
        self.assertEqual(len(files), 1)
        file, result, trivy_version = files[0]
        self.assertTrue(file.endswith("Dockerfile"))
        self.assertEqual(result.get("Misconfigurations") or [], [])
        self.assertNotEqual(trivy_version, tw.TRIVY_VERSION_UNKNOWN)

    @unittest.skipUnless(_trivy_available(), "requires the real trivy CLI on PATH")
    def test_aggregates_across_more_than_one_path(self) -> None:
        # Docker's own scan_paths() already loops iter_scanned_files
        # across multiple paths, but always with the DS-0031 exclusion
        # active — this isolates the aggregation behavior itself with
        # the default (no exclusions) parametrization 010 will use.
        with tempfile.TemporaryDirectory() as tmp_a, tempfile.TemporaryDirectory() as tmp_b:
            (Path(tmp_a) / "Dockerfile").write_text(CLEAN_DOCKERFILE, encoding="utf-8")
            (Path(tmp_b) / "Dockerfile").write_text(VULNERABLE_DOCKERFILE, encoding="utf-8")
            files = list(tw.iter_scanned_files([tmp_a, tmp_b]))
        self.assertEqual(len(files), 2)


class CrossPlatformEncodingTests(unittest.TestCase):
    def test_round_trip_non_ascii_content_with_explicit_utf8(self) -> None:
        text = "em dash — and middle dot · round-trip"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "roundtrip.txt"
            path.write_text(text, encoding="utf-8")
            self.assertEqual(path.read_text(encoding="utf-8"), text)


if __name__ == "__main__":
    unittest.main()
