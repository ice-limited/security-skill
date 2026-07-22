"""Static checks for the Claude Code adapter (plan 017): the one piece
of "does this Skill work" that *can* be automated, per มิ้นท์'s point at
kickoff — whether Claude actually decides to invoke it is a real,
human-observed Claude Code session (see MANUAL_TEST_LOG.md), not
something a unit test can prove.

Checks: SKILL.md's frontmatter parses and has the fields Claude Code
actually reads (`name`, `description`), the description stays under the
1,536-character description+when_to_use cap Anthropic's docs specify,
SKILL.md's body stays within the ~500-line guidance, and every
subSkill enum value from finding.schema.json has a matching
reference/*.md file (no silent gaps).

Run with: python3 -m unittest test_skill_structure -v (from inside
adapters/claude-code/).
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

ADAPTER_DIR = Path(__file__).parent
SKILL_DIR = ADAPTER_DIR / "security-review"
SKILL_MD = SKILL_DIR / "SKILL.md"
REFERENCE_DIR = SKILL_DIR / "reference"

SECURITY_SKILL_DIR = next(p for p in ADAPTER_DIR.resolve().parents if (p / "common").is_dir())

# Anthropic's documented cap on description + when_to_use combined.
_DESCRIPTION_CAP = 1536
# Anthropic's own guidance: keep SKILL.md itself lean.
_SKILL_MD_LINE_GUIDANCE = 500


def _parse_frontmatter(text: str) -> dict[str, str]:
    """Minimal frontmatter parser — this project has no other YAML
    dependency to justify adding PyYAML just for this. Sufficient for
    SKILL.md's flat, single-line-value fields (name/description/
    allowed-tools); would need a real YAML parser if a future field
    needs nested structure."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        raise ValueError("no opening --- frontmatter delimiter")
    end = next((i for i in range(1, len(lines)) if lines[i].strip() == "---"), None)
    if end is None:
        raise ValueError("no closing --- frontmatter delimiter")
    fields = {}
    for line in lines[1:end]:
        if not line.strip():
            continue
        key, sep, value = line.partition(":")
        if not sep:
            raise ValueError(f"malformed frontmatter line: {line!r}")
        fields[key.strip()] = value.strip()
    return fields


def _finding_schema_sub_skills() -> list[str]:
    schema = json.loads((SECURITY_SKILL_DIR / "schema" / "finding.schema.json").read_text(encoding="utf-8"))
    return schema["properties"]["subSkill"]["enum"]


class SkillMdFrontmatterTests(unittest.TestCase):
    def test_skill_md_exists(self) -> None:
        self.assertTrue(SKILL_MD.is_file())

    def test_frontmatter_parses_and_has_required_fields(self) -> None:
        fields = _parse_frontmatter(SKILL_MD.read_text(encoding="utf-8"))
        self.assertIn("name", fields)
        self.assertIn("description", fields)
        self.assertEqual(fields["name"], "security-review")

    def test_description_stays_under_the_documented_cap(self) -> None:
        fields = _parse_frontmatter(SKILL_MD.read_text(encoding="utf-8"))
        # No separate when_to_use field in this skill — description
        # alone must stay under the combined cap.
        self.assertLessEqual(len(fields["description"]), _DESCRIPTION_CAP)

    def test_skill_md_stays_within_line_count_guidance(self) -> None:
        line_count = len(SKILL_MD.read_text(encoding="utf-8").splitlines())
        self.assertLessEqual(line_count, _SKILL_MD_LINE_GUIDANCE)

    def test_a_real_malformed_frontmatter_is_actually_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _parse_frontmatter("no frontmatter here at all\n")


class ReferenceDocCoverageTests(unittest.TestCase):
    def test_every_sub_skill_has_a_reference_doc(self) -> None:
        missing = [
            sub_skill
            for sub_skill in _finding_schema_sub_skills()
            if not (REFERENCE_DIR / f"{sub_skill}.md").is_file()
        ]
        self.assertEqual(missing, [])

    def test_no_orphan_reference_docs_for_unknown_sub_skills(self) -> None:
        known = set(_finding_schema_sub_skills())
        orphans = [p.stem for p in REFERENCE_DIR.glob("*.md") if p.stem not in known]
        self.assertEqual(orphans, [])

    def test_reference_docs_are_non_trivial(self) -> None:
        empty = [p.name for p in REFERENCE_DIR.glob("*.md") if len(p.read_text(encoding="utf-8").strip()) < 50]
        self.assertEqual(empty, [])


if __name__ == "__main__":
    unittest.main()
