"""Tests for the CI/CD pipeline playbook: checklist loading/validation,
rendering, checklist-item lookup, and schema conformance of the
findings an agent would produce from following it.

Run with: python3 -m unittest test_playbook -v (from inside
detectors/cicd/).
"""

from __future__ import annotations

import io
import json
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import playbook
from playbook import PlaybookError

DETECTOR_DIR = Path(__file__).parent
SECURITY_SKILL_DIR = next(p for p in DETECTOR_DIR.resolve().parents if (p / "common").is_dir())
KNOWLEDGE_DIR = SECURITY_SKILL_DIR / "knowledge"

sys.path.insert(0, str(KNOWLEDGE_DIR))
import standards  # noqa: E402

RULE_ID_PATTERN = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$")  # finding.schema.json's own regex


def _real_checklist() -> dict:
    return playbook.load_checklist()


class LoaderTests(unittest.TestCase):
    def test_real_checklist_loads_and_validates(self) -> None:
        checklist = _real_checklist()
        self.assertIn("items", checklist)
        self.assertEqual(len(checklist["items"]), 4)

    def test_invalid_checklist_raises_playbook_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "broken-checklist.json"
            path.write_text(json.dumps({"items": [{"ruleId": "cicd-pipeline.x"}]}), encoding="utf-8")
            with self.assertRaises(PlaybookError):
                playbook.load_checklist(path)

    def test_valid_minimal_checklist_loads_without_error(self) -> None:
        real_item = _real_checklist()["items"][0]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "minimal-checklist.json"
            path.write_text(json.dumps({"items": [real_item]}), encoding="utf-8")
            checklist = playbook.load_checklist(path)
            self.assertEqual(len(checklist["items"]), 1)


class ConsistencyTests(unittest.TestCase):
    def test_every_item_reference_resolves_in_the_knowledge_base(self) -> None:
        for item in _real_checklist()["items"]:
            for ref in item["references"]:
                self.assertTrue(
                    standards.exists(ref["standard"], ref["id"]),
                    f"{item['ruleId']} cites {ref['standard']} {ref['id']}, not found in knowledge base",
                )

    def test_every_rule_id_matches_naming_convention(self) -> None:
        for item in _real_checklist()["items"]:
            self.assertTrue(RULE_ID_PATTERN.match(item["ruleId"]), f"{item['ruleId']} doesn't match the ruleId convention")

    def test_no_duplicate_rule_ids(self) -> None:
        ids = [item["ruleId"] for item in _real_checklist()["items"]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_all_four_weakness_classes_are_represented(self) -> None:
        # Guards against the checklist silently collapsing to fewer
        # classes, which would defeat the point of covering the full
        # gap Checkov's deterministic catalog doesn't reach.
        classes = {item["weaknessClass"] for item in _real_checklist()["items"]}
        self.assertEqual(classes, {"code-injection", "excessive-privilege", "supply-chain-integrity", "information-exposure"})

    def test_no_ruleid_overlaps_with_the_deterministic_catalog(self) -> None:
        # The playbook and rules.py's Checkov catalog must never claim
        # the same ruleId — they're deliberately non-overlapping halves
        # of this plan's scope (see plans/013-cicd-pipeline-skill.md).
        import rules

        deterministic_rule_ids = {r.rule_id for r in rules.CHECKOV_RULES}
        playbook_rule_ids = {item["ruleId"] for item in _real_checklist()["items"]}
        self.assertEqual(deterministic_rule_ids & playbook_rule_ids, set())


class RenderTests(unittest.TestCase):
    def test_render_without_format_includes_every_item(self) -> None:
        checklist = _real_checklist()
        text = playbook.render_playbook(checklist)
        for item in checklist["items"]:
            self.assertIn(item["ruleId"], text)
            self.assertIn(item["guidance"], text)

    def test_render_with_format_includes_that_formats_notes(self) -> None:
        checklist = _real_checklist()
        item = playbook.checklist_item(checklist, "cicd-pipeline.unpinned-external-reference")
        self.assertIn("github-actions", item["formatNotes"])  # fixture assumption, guards the test itself
        text = playbook.render_playbook(checklist, pipeline_format="github-actions")
        self.assertIn(item["formatNotes"]["github-actions"], text)

    def test_render_with_unknown_format_omits_notes_without_crashing(self) -> None:
        checklist = _real_checklist()
        text = playbook.render_playbook(checklist, pipeline_format="circleci")
        self.assertIn("cicd-pipeline.unpinned-external-reference", text)


class ChecklistItemLookupTests(unittest.TestCase):
    def test_known_rule_id_returns_the_item(self) -> None:
        item = playbook.checklist_item(_real_checklist(), "cicd-pipeline.secrets-in-logs")
        self.assertEqual(item["ruleId"], "cicd-pipeline.secrets-in-logs")

    def test_unknown_rule_id_raises(self) -> None:
        with self.assertRaises(PlaybookError):
            playbook.checklist_item(_real_checklist(), "cicd-pipeline.does-not-exist")


class SchemaConformanceTests(unittest.TestCase):
    """Every checklist item must be able to produce a finding that
    actually validates against finding.schema.json — not just "looks
    right" by inspection. Mirrors detectors/auth/test_playbook.py's
    class of the same name."""

    def _synthetic_finding(self, item: dict) -> dict:
        template_kwargs = dict(
            file=".github/workflows/ci.yml",
            line=12,
            reference="actions/checkout@v4",
            job="build",
            grantedScope="write-all",
            untrustedValue="github.event.pull_request.title",
            step="Run tests",
            secretName="API_TOKEN",
        )
        return {
            "findingId": f"cicd-pipeline-{abs(hash(item['ruleId'])) % (10 ** 12):012x}"[:24],
            "ruleId": item["ruleId"],
            "subSkill": "cicd-pipeline",
            "artifactType": "github-actions",
            "title": item["title"],
            "problem": item["problemTemplate"].format(**template_kwargs),
            "impact": item["impactTemplate"].format(**template_kwargs),
            "recommendation": item["recommendationTemplate"].format(**template_kwargs),
            "references": item["references"],
            "severity": item["suggestedSeverity"],
            "confidence": item["confidenceGuidance"]["defaultMax"],
            "location": {"file": ".github/workflows/ci.yml", "startLine": 12, "endLine": 15},
            "detectorSource": {"name": "cicd-pipeline-playbook", "version": "0.1.0"},
            "suppressed": False,
        }

    def test_every_checklist_item_produces_a_schema_valid_finding(self) -> None:
        checklist = _real_checklist()
        self.assertEqual(len(checklist["items"]), 4)
        for item in checklist["items"]:
            finding = self._synthetic_finding(item)
            errors = playbook.validate_agent_finding(finding)
            self.assertEqual(errors, [], f"{item['ruleId']} synthetic finding is not schema-valid: {errors}")

    def test_validator_actually_rejects_an_invalid_finding(self) -> None:
        item = _real_checklist()["items"][0]
        finding = self._synthetic_finding(item)
        del finding["severity"]
        errors = playbook.validate_agent_finding(finding)
        self.assertNotEqual(errors, [])


class MainCliTests(unittest.TestCase):
    def test_prints_rendered_playbook_and_returns_0(self) -> None:
        out = io.StringIO()
        with redirect_stdout(out):
            code = playbook.main(["--format", "gitlab-ci"])
        self.assertEqual(code, 0)
        self.assertIn("cicd-pipeline.unpinned-external-reference", out.getvalue())


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
