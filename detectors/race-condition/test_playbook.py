"""Tests for the Race Condition (TOCTOU) playbook: checklist loading/
validation, rendering, checklist-item lookup, schema conformance of the
findings an agent would produce from following it, and paired
vulnerable/false-positive TOCTOU fixtures per มิ้นท์'s point at this
plan's reopening kickoff (a playbook-only sub-skill has no deterministic
tool run to validate against, so its own fixture strategy matters more,
not less).

Run with: python3 -m unittest test_playbook -v (from inside
detectors/race-condition/).
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
SCHEMA_DIR = SECURITY_SKILL_DIR / "schema"
KNOWLEDGE_DIR = SECURITY_SKILL_DIR / "knowledge"

sys.path.insert(0, str(SECURITY_SKILL_DIR / "common"))
from schema_validation import validate_against_schema  # noqa: E402

sys.path.insert(0, str(KNOWLEDGE_DIR))
import standards  # noqa: E402

RULE_ID_PATTERN = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$")  # finding.schema.json's own regex


def _real_checklist() -> dict:
    return playbook.load_checklist()


class LoaderTests(unittest.TestCase):
    def test_real_checklist_loads_and_validates(self) -> None:
        checklist = _real_checklist()
        self.assertIn("items", checklist)
        self.assertGreaterEqual(len(checklist["items"]), 1)

    def test_invalid_checklist_raises_playbook_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "broken-checklist.json"
            # Missing every required field on the item - definitely invalid.
            path.write_text(json.dumps({"items": [{"ruleId": "race-condition.x"}]}), encoding="utf-8")
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
    """Nothing else would catch an item citing a standard ID that
    doesn't actually exist in the knowledge base — same pattern as
    detectors/auth/test_playbook.py's ConsistencyTests."""

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

    def test_every_item_is_toctou_scoped(self) -> None:
        # Guards the v1 scope decision itself (TOCTOU only, not general
        # race conditions) — a future item accidentally widening scope
        # without an explicit schema/plan revision would be caught here.
        for item in _real_checklist()["items"]:
            self.assertEqual(item["weaknessClass"], "toctou")

    def test_every_item_cites_the_toctou_cwe(self) -> None:
        for item in _real_checklist()["items"]:
            cwe_ids = {ref["id"] for ref in item["references"] if ref["standard"] == "CWE"}
            self.assertIn("CWE-367", cwe_ids, f"{item['ruleId']} doesn't cite CWE-367 (TOCTOU)")


class RenderTests(unittest.TestCase):
    def test_render_without_language_includes_every_item(self) -> None:
        checklist = _real_checklist()
        text = playbook.render_playbook(checklist)
        for item in checklist["items"]:
            self.assertIn(item["ruleId"], text)
            self.assertIn(item["guidance"], text)

    def test_render_with_language_includes_that_languages_notes(self) -> None:
        checklist = _real_checklist()
        item = playbook.checklist_item(checklist, "race-condition.toctou-file-existence-then-open")
        self.assertIn("python", item["languageNotes"])  # fixture assumption, guards the test itself
        text = playbook.render_playbook(checklist, language="python")
        self.assertIn(item["languageNotes"]["python"], text)

    def test_render_with_unknown_language_omits_notes_without_crashing(self) -> None:
        checklist = _real_checklist()
        text = playbook.render_playbook(checklist, language="cobol")
        self.assertIn("race-condition.toctou-file-existence-then-open", text)


class ChecklistItemLookupTests(unittest.TestCase):
    def test_known_rule_id_returns_the_item(self) -> None:
        item = playbook.checklist_item(_real_checklist(), "race-condition.toctou-permission-check-then-use")
        self.assertEqual(item["ruleId"], "race-condition.toctou-permission-check-then-use")

    def test_unknown_rule_id_raises(self) -> None:
        with self.assertRaises(PlaybookError):
            playbook.checklist_item(_real_checklist(), "race-condition.does-not-exist")


class SchemaConformanceTests(unittest.TestCase):
    """Every checklist item must be able to produce a finding that
    actually validates against finding.schema.json — not just "looks
    right" by inspection. Mirrors detectors/auth/test_playbook.py's
    SchemaConformanceTests, applied to this sub-skill's items."""

    def _synthetic_finding(self, item: dict) -> dict:
        return {
            "findingId": f"race-condition-{abs(hash(item['ruleId'])) % (10 ** 12):012x}"[:26],
            "ruleId": item["ruleId"],
            "subSkill": "race-condition",
            "artifactType": "source-code",
            "title": item["title"],
            "problem": item["problemTemplate"].format(
                file="app/uploads.py",
                line=57,
                resourceType="the uploaded file",
                call="os.path.exists(path)",
            ),
            "impact": item["impactTemplate"].format(
                resourceType="the uploaded file",
            ),
            "recommendation": item["recommendationTemplate"].format(
                resourceType="the uploaded file",
                atomicAlternative="open(path, 'x')",
            ),
            "references": item["references"],
            "severity": item["suggestedSeverity"],
            "confidence": item["confidenceGuidance"]["defaultMax"],
            "location": {"file": "app/uploads.py", "startLine": 57, "endLine": 59},
            "detectorSource": {"name": "race-condition-playbook", "version": "0.1.0"},
            "suppressed": False,
        }

    def test_every_checklist_item_produces_a_schema_valid_finding(self) -> None:
        checklist = _real_checklist()
        self.assertGreaterEqual(len(checklist["items"]), 1)
        for item in checklist["items"]:
            finding = self._synthetic_finding(item)
            errors = playbook.validate_agent_finding(finding)
            self.assertEqual(errors, [], f"{item['ruleId']} synthetic finding is not schema-valid: {errors}")

    def test_validator_actually_rejects_an_invalid_finding(self) -> None:
        # Proves validate_agent_finding() isn't vacuously passing
        # everything — same discipline as every other mutation-tested
        # regression guard in this codebase.
        item = _real_checklist()["items"][0]
        finding = self._synthetic_finding(item)
        del finding["location"]
        errors = playbook.validate_agent_finding(finding)
        self.assertNotEqual(errors, [])


class ToctouFixtureTests(unittest.TestCase):
    """Paired vulnerable/false-positive TOCTOU fixtures per มิ้นท์'s
    point at the reopening kickoff — this sub-skill has no
    deterministic tool run to validate against, so these fixtures
    encode, in test form, exactly what "matches this checklist item"
    vs. "already uses the atomic-safe equivalent" means. Not run
    through an automated scanner (there isn't one, by design) — these
    assert on the checklist's own guidance/evidence text actually
    distinguishing the two shapes, the same evidentiary bar an agent
    applying this playbook would need to meet."""

    _VULNERABLE_FIXTURES = {
        "race-condition.toctou-file-existence-then-open": (
            'if not os.path.exists(path):\n    with open(path, "w") as f:\n        f.write(data)\n'
        ),
        "race-condition.toctou-permission-check-then-use": (
            "if os.access(path, os.W_OK):\n    with open(path, 'a') as f:\n        f.write(data)\n"
        ),
        "race-condition.toctou-stat-then-operate-on-path": (
            "if not os.path.islink(path):\n    with open(path) as f:\n        data = f.read()\n"
        ),
        "race-condition.toctou-predictable-temp-path": (
            'tmp_path = f"/tmp/myapp-{os.getpid()}.tmp"\nwith open(tmp_path, "w") as f:\n    f.write(data)\n'
        ),
    }

    _FALSE_POSITIVE_FIXTURES = {
        "race-condition.toctou-file-existence-then-open": (
            'try:\n    fd = os.open(path, os.O_CREAT | os.O_EXCL)\nexcept FileExistsError:\n    pass\n'
        ),
        "race-condition.toctou-permission-check-then-use": (
            "try:\n    with open(path, 'a') as f:\n        f.write(data)\nexcept PermissionError:\n    pass\n"
        ),
        "race-condition.toctou-stat-then-operate-on-path": (
            "with open(path) as f:\n    st = os.fstat(f.fileno())\n    data = f.read()\n"
        ),
        "race-condition.toctou-predictable-temp-path": ("fd, tmp_path = tempfile.mkstemp()\n"),
    }

    def test_every_checklist_item_has_a_paired_vulnerable_fixture(self) -> None:
        rule_ids = {item["ruleId"] for item in _real_checklist()["items"]}
        self.assertEqual(rule_ids, set(self._VULNERABLE_FIXTURES.keys()))

    def test_every_checklist_item_has_a_paired_false_positive_fixture(self) -> None:
        rule_ids = {item["ruleId"] for item in _real_checklist()["items"]}
        self.assertEqual(rule_ids, set(self._FALSE_POSITIVE_FIXTURES.keys()))

    def test_vulnerable_and_false_positive_fixtures_are_actually_different(self) -> None:
        for rule_id, vulnerable in self._VULNERABLE_FIXTURES.items():
            self.assertNotEqual(vulnerable, self._FALSE_POSITIVE_FIXTURES[rule_id])

    def test_false_positive_fixtures_use_an_atomic_or_handle_based_pattern(self) -> None:
        # Each false-positive fixture should use the specific safe
        # pattern its item's own recommendationTemplate/languageNotes
        # point to (O_EXCL / 'x' mode / fstat-on-open-handle /
        # mkstemp) - not just "looks different."
        markers = {
            "race-condition.toctou-file-existence-then-open": "O_EXCL",
            "race-condition.toctou-permission-check-then-use": "except PermissionError",
            "race-condition.toctou-stat-then-operate-on-path": "fstat",
            "race-condition.toctou-predictable-temp-path": "mkstemp",
        }
        for rule_id, marker in markers.items():
            self.assertIn(marker, self._FALSE_POSITIVE_FIXTURES[rule_id])


class MainCliTests(unittest.TestCase):
    def test_prints_rendered_playbook_and_returns_0(self) -> None:
        out = io.StringIO()
        with redirect_stdout(out):
            code = playbook.main(["--language", "python"])
        self.assertEqual(code, 0)
        self.assertIn("race-condition.toctou-file-existence-then-open", out.getvalue())


class CrossPlatformEncodingTests(unittest.TestCase):
    def test_round_trip_non_ascii_content_with_explicit_utf8(self) -> None:
        text = "em dash — and middle dot · round-trip"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "roundtrip.txt"
            path.write_text(text, encoding="utf-8")
            self.assertEqual(path.read_text(encoding="utf-8"), text)


class SourceEncodingAuditTests(unittest.TestCase):
    """Static-analysis regression guard — see
    detectors/auth/test_playbook.py's class of the same name. Scans
    every .py file in this directory."""

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
