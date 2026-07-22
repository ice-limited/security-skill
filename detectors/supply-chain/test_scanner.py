"""Tests for the CI-config-presence half: missing image signing,
missing SBOM generation, and missing SLSA provenance — pure Python, no
subprocess (this half never shells out to any tool, unlike
scorecard_wrapper.py).

Run with: python3 -m unittest test_scanner -v (from inside
detectors/supply-chain/).
"""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import ci_config
import scanner
from scanner import ScannerError

DETECTOR_DIR = Path(__file__).parent
SECURITY_SKILL_DIR = next(p for p in DETECTOR_DIR.resolve().parents if (p / "common").is_dir())
SCHEMA_DIR = SECURITY_SKILL_DIR / "schema"

sys.path.insert(0, str(SECURITY_SKILL_DIR / "common"))
from schema_validation import validate_against_schema  # noqa: E402

sys.path.insert(0, str(SECURITY_SKILL_DIR / "knowledge"))
import standards  # noqa: E402

# A build step with no cosign sign/SBOM step at all, and no SLSA
# provenance job — verified for real at implementation to fire all
# three ruleIds. This fixture directly reproduces the Checkov bug that
# was found: CKV_GHA_5/6 never fire on this exact shape (verified via
# a real checkov CLI run during this plan's own implementation), which
# is why this module exists as a hand-written replacement.
VULNERABLE_WORKFLOW = """name: Build
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build image
        run: docker build -t myimage:latest .
      - name: Push image
        run: docker push myimage:latest
"""

# Signs and generates an SBOM, but no SLSA provenance job — only the
# provenance finding should fire.
PARTIALLY_CLEAN_WORKFLOW = """name: Build
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build image
        run: docker build -t myimage:latest .
      - name: Push image
        run: docker push myimage:latest
      - name: Sign image
        run: cosign sign myimage:latest
      - name: Attest SBOM
        run: cosign attest --type sbom --predicate sbom.json myimage:latest
"""

# Signs, generates an SBOM, and includes a real SLSA provenance
# generator job — verified this specific job-level `uses:` shape
# (reusable-workflow call, not a step) is the one that matters; an
# earlier version of ci_config.py's own detection only checked the
# step-level shape and missed this real, more common pattern.
FULLY_CLEAN_WORKFLOW = """name: Build
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build image
        run: docker build -t myimage:latest .
      - name: Push image
        run: docker push myimage:latest
      - name: Sign image
        run: cosign sign myimage:latest
      - name: Attest SBOM
        run: cosign attest --type sbom --predicate sbom.json myimage:latest
  provenance:
    needs: build
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v2.0.0
"""

NO_BUILD_STEP_WORKFLOW = """name: Test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pytest
"""

MALFORMED_YAML = "on: [push]\n  bad indent: ["


class ScanWorkflowFileTests(unittest.TestCase):
    def _write(self, tmp: str, content: str) -> Path:
        path = Path(tmp) / ".github" / "workflows" / "ci.yml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def test_vulnerable_workflow_fires_all_three_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, VULNERABLE_WORKFLOW)
            findings = scanner.scan_workflow_file(path)
        rule_ids = {f["ruleId"] for f in findings}
        self.assertEqual(
            rule_ids,
            {
                "supply-chain.missing-image-signing",
                "supply-chain.missing-sbom-generation",
                "supply-chain.missing-slsa-provenance",
            },
        )

    def test_partially_clean_workflow_fires_only_provenance_finding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, PARTIALLY_CLEAN_WORKFLOW)
            findings = scanner.scan_workflow_file(path)
        rule_ids = {f["ruleId"] for f in findings}
        self.assertEqual(rule_ids, {"supply-chain.missing-slsa-provenance"})

    def test_fully_clean_workflow_produces_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, FULLY_CLEAN_WORKFLOW)
            findings = scanner.scan_workflow_file(path)
        self.assertEqual(findings, [])

    def test_workflow_with_no_build_step_produces_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, NO_BUILD_STEP_WORKFLOW)
            findings = scanner.scan_workflow_file(path)
        self.assertEqual(findings, [])

    def test_malformed_yaml_raises_scanner_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, MALFORMED_YAML)
            with self.assertRaises(ScannerError):
                scanner.scan_workflow_file(path)


class ScanPathsDiscoveryTests(unittest.TestCase):
    def test_directory_input_discovers_workflow_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workflow_dir = Path(tmp) / ".github" / "workflows"
            workflow_dir.mkdir(parents=True)
            (workflow_dir / "build.yml").write_text(VULNERABLE_WORKFLOW, encoding="utf-8")
            (Path(tmp) / "README.md").write_text("not a workflow", encoding="utf-8")
            findings = scanner.scan_paths([tmp])
        self.assertTrue(findings)

    def test_bad_path_raises_scanner_error(self) -> None:
        with self.assertRaises(ScannerError):
            scanner.scan_paths(["/tmp/definitely-does-not-exist-014-supply-chain"])


class SchemaConformanceTests(unittest.TestCase):
    def test_real_findings_validate_against_finding_schema(self) -> None:
        schema = json.loads((SCHEMA_DIR / "finding.schema.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".github" / "workflows" / "ci.yml"
            path.parent.mkdir(parents=True)
            path.write_text(VULNERABLE_WORKFLOW, encoding="utf-8")
            findings = scanner.scan_workflow_file(path)
        self.assertEqual(len(findings), 3)
        for f in findings:
            errors = validate_against_schema(schema, f)
            self.assertEqual(errors, [], f"{f['ruleId']} finding is not schema-valid: {errors}")


class ConsistencyTests(unittest.TestCase):
    def test_every_rule_reference_resolves_in_the_knowledge_base(self) -> None:
        import rules

        for template in (rules.MISSING_IMAGE_SIGNING, rules.MISSING_SBOM_GENERATION, rules.MISSING_SLSA_PROVENANCE):
            for ref in template["references"]:
                self.assertTrue(standards.exists(ref["standard"], ref["id"]), f"{template['rule_id']} cites {ref}")

    def test_every_rule_id_matches_naming_convention(self) -> None:
        import re

        import rules

        pattern = re.compile(r"^supply-chain\.[a-z0-9-]+$")
        for template in (rules.MISSING_IMAGE_SIGNING, rules.MISSING_SBOM_GENERATION, rules.MISSING_SLSA_PROVENANCE):
            self.assertTrue(pattern.match(template["rule_id"]), template["rule_id"])


class CiConfigUnitTests(unittest.TestCase):
    """Pure-function tests of ci_config.py's own detection logic —
    isolates the job-level-vs-step-level `uses:` distinction found
    while building the fixtures above."""

    def test_job_level_uses_is_detected(self) -> None:
        workflow = {"jobs": {"provenance": {"uses": "slsa-framework/slsa-github-generator/.github/workflows/x.yml@v2"}}}
        self.assertTrue(ci_config.has_slsa_provenance_generator(workflow))

    def test_step_level_uses_is_also_detected(self) -> None:
        workflow = {
            "jobs": {
                "provenance": {"steps": [{"uses": "slsa-framework/slsa-github-generator@v2"}]}
            }
        }
        self.assertTrue(ci_config.has_slsa_provenance_generator(workflow))

    def test_unrelated_uses_is_not_a_false_positive(self) -> None:
        workflow = {"jobs": {"build": {"uses": "some-org/some-other-reusable-workflow.yml@v1"}}}
        self.assertFalse(ci_config.has_slsa_provenance_generator(workflow))

    def test_no_jobs_key_is_handled_without_crashing(self) -> None:
        self.assertEqual(ci_config.analyze_jobs({}), [])
        self.assertFalse(ci_config.has_slsa_provenance_generator({}))


class MainCliTests(unittest.TestCase):
    def test_prints_findings_as_json_and_returns_0(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".github" / "workflows" / "ci.yml"
            path.parent.mkdir(parents=True)
            path.write_text(FULLY_CLEAN_WORKFLOW, encoding="utf-8")
            out = io.StringIO()
            with redirect_stdout(out):
                code = scanner.main([tmp])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue()), [])

    def test_bad_path_returns_1_and_prints_error(self) -> None:
        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            code = scanner.main(["/tmp/definitely-does-not-exist-014-supply-chain"])
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
