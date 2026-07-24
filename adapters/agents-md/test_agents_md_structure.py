"""Static checks for the AGENTS.md adapter (plan 018): the one piece of
"does this content actually cover the ground it claims to" that can be
automated. Whether an agent actually follows AGENTS.md is a real,
human/agent-observed run (see MANUAL_TEST_LOG.md), not something a
unit test can prove — AGENTS.md has no discrete "did it trigger" event
the way a Claude Code Skill does (it's always-on ambient context), so
there's nothing analogous to 017's frontmatter/description checks here.

Run with: python3 -m unittest test_agents_md_structure -v (from inside
adapters/agents-md/).
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

ADAPTER_DIR = Path(__file__).parent
AGENTS_MD = ADAPTER_DIR / "AGENTS.md"

SECURITY_SKILL_DIR = next(p for p in ADAPTER_DIR.resolve().parents if (p / "common").is_dir())

_HARD_RULE_PHRASE = "always invoke the real detector"


def _normalize_whitespace(text: str) -> str:
    """Markdown line-wrapping inserts newlines mid-phrase — collapse
    all whitespace runs to single spaces before substring checks, so
    these tests assert on content, not on where a line happens to
    wrap."""
    return " ".join(text.split())


def _finding_schema_sub_skills() -> list[str]:
    schema = json.loads((SECURITY_SKILL_DIR / "schema" / "finding.schema.json").read_text(encoding="utf-8"))
    return schema["properties"]["subSkill"]["enum"]


# Maps each finding.schema.json subSkill value to the detector command
# fragment that must appear in AGENTS.md for that sub-skill — a real,
# specific check per sub-skill, not just "the word appears somewhere."
_EXPECTED_COMMAND_FRAGMENT = {
    "secret": "detectors/secret/scanner.py",
    "code-review": "detectors/code-review/scanner.py",
    "auth": "detectors/auth/semgrep_detector.py",
    "dependency": "detectors/dependency/scanner.py",
    "docker": "detectors/docker/scanner.py",
    "kubernetes": "detectors/kubernetes/scanner.py",
    "iac": "detectors/iac/scanner.py",
    "api": "detectors/api/scanner.py",
    "supply-chain": "detectors/supply-chain/scanner.py",
    "cicd-pipeline": "detectors/cicd/scanner.py",
    "race-condition": "detectors/race-condition/playbook.py",
}


class AgentsMdContentTests(unittest.TestCase):
    def test_agents_md_exists(self) -> None:
        self.assertTrue(AGENTS_MD.is_file())

    def test_hard_rule_present(self) -> None:
        text = _normalize_whitespace(AGENTS_MD.read_text(encoding="utf-8"))
        self.assertIn(_HARD_RULE_PHRASE, text)

    def test_never_substitute_language_present(self) -> None:
        # วิน's requirement at kickoff must be visible in the main body
        # itself, not buried in a rarely-opened reference file (there
        # is no reference file here, unlike 017).
        text = _normalize_whitespace(AGENTS_MD.read_text(encoding="utf-8"))
        self.assertIn("never", text.lower())
        self.assertIn("silently fall back", text)

    def test_every_sub_skill_has_its_detector_command_referenced(self) -> None:
        text = AGENTS_MD.read_text(encoding="utf-8")
        missing = [
            sub_skill
            for sub_skill in _finding_schema_sub_skills()
            if _EXPECTED_COMMAND_FRAGMENT[sub_skill] not in text
        ]
        self.assertEqual(missing, [])

    def test_command_fragment_table_has_no_stale_entries(self) -> None:
        # Regression guard for the mapping table above itself: every
        # finding.schema.json subSkill must have an entry, and every
        # entry must correspond to a real subSkill (no leftover/typo'd
        # keys from a future schema change).
        known = set(_finding_schema_sub_skills())
        self.assertEqual(set(_EXPECTED_COMMAND_FRAGMENT.keys()), known)

    def test_locating_security_skill_note_present(self) -> None:
        # Same real gap 017's manual test found and fixed — must be
        # present here too, not just in the Claude Code adapter.
        text = _normalize_whitespace(AGENTS_MD.read_text(encoding="utf-8"))
        self.assertIn("ask the user where it is", text)


if __name__ == "__main__":
    unittest.main()
