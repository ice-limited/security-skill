"""Tests for common/streams.py and common/schema_validation.py.

Run with: python3 -m unittest test_common -v (from inside common/).
"""

from __future__ import annotations

import io
import sys
import tempfile
import unittest
from pathlib import Path

from referencing import Registry, Resource

from schema_validation import validate_against_schema
from streams import reconfigure_streams

COMMON_DIR = Path(__file__).parent


class ReconfigureStreamsTests(unittest.TestCase):
    def test_stdout_and_stderr_reconfigured_to_utf8_by_default(self) -> None:
        reconfigure_streams()
        self.assertEqual(sys.stdout.encoding.lower().replace("-", ""), "utf8")
        self.assertEqual(sys.stderr.encoding.lower().replace("-", ""), "utf8")

    def test_stdin_left_alone_by_default(self) -> None:
        original_encoding = sys.stdin.encoding
        reconfigure_streams()
        self.assertEqual(sys.stdin.encoding, original_encoding, "stdin=False by default must not touch stdin")

    def test_stdin_reconfigured_when_requested(self) -> None:
        reconfigure_streams(stdin=True)
        self.assertEqual(sys.stdin.encoding.lower().replace("-", ""), "utf8")

    def test_stdout_can_be_opted_out(self) -> None:
        # Reconfigure to something non-default first, then confirm
        # calling with stdout=False leaves it alone.
        sys.stdout.reconfigure(encoding="utf-8")
        original = sys.stdout.encoding
        reconfigure_streams(stdout=False, stderr=False)
        self.assertEqual(sys.stdout.encoding, original)


class ValidateAgainstSchemaTests(unittest.TestCase):
    SIMPLE_SCHEMA = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["name"],
        "properties": {
            "name": {"type": "string"},
            "startedAt": {"type": "string", "format": "date"},
        },
    }

    def test_valid_instance_has_no_errors(self) -> None:
        self.assertEqual(validate_against_schema(self.SIMPLE_SCHEMA, {"name": "x"}), [])

    def test_missing_required_field_is_an_error(self) -> None:
        errors = validate_against_schema(self.SIMPLE_SCHEMA, {})
        self.assertTrue(errors)

    def test_format_checker_is_attached_by_default(self) -> None:
        # This is the exact bug found during plan 004's testing:
        # "format": "date" is annotation-only in jsonschema unless a
        # format_checker is attached. Centralizing means every caller
        # gets this by construction now, not only callers who remembered.
        errors = validate_against_schema(self.SIMPLE_SCHEMA, {"name": "x", "startedAt": "not-a-date"})
        self.assertTrue(errors, "malformed date should be rejected when format_checker is attached")

    def test_registry_resolves_cross_file_refs(self) -> None:
        # Minimal version of what schema/validate.py needs: a schema
        # that $refs another schema by $id, resolved via a Registry.
        referenced = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "urn:test:widget",
            "type": "object",
            "required": ["id"],
            "properties": {"id": {"type": "string"}},
        }
        container = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {"widget": {"$ref": "urn:test:widget"}},
        }
        registry = Registry().with_resource("urn:test:widget", Resource.from_contents(referenced))

        self.assertEqual(validate_against_schema(container, {"widget": {"id": "w-1"}}, registry=registry), [])
        self.assertTrue(validate_against_schema(container, {"widget": {}}, registry=registry))


class CrossPlatformEncodingTests(unittest.TestCase):
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
        for path in sorted(COMMON_DIR.glob("*.py")):
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


class PathDiscoveryPatternTests(unittest.TestCase):
    """Every importing file uses:

        _common_dir = next(p for p in Path(__file__).resolve().parents
                            if (p / "common").is_dir()) / "common"

    to locate common/ before it's on sys.path. Regression test for a
    real bug found while testing this plan: the *original* version of
    this snippet was `Path(__file__).parent.parent / "common"` — a fixed
    depth that happens to work for the 1-level-deep directories that
    exist today (schema/, knowledge/, policy/, decision/) but silently
    resolves to the wrong path for Phase 1's 2-level-deep
    `detectors/{sub-skill}/` layout, which this exact snippet is
    documented in security-skill/README.md as the pattern to copy.
    Caught by literally building both directory shapes and running the
    snippet against each, not by reasoning about it."""

    @staticmethod
    def _discover_common_dir(caller_file: Path) -> Path:
        # The exact expression used verbatim in all 9 refactored files —
        # kept here as a single copy so this test and those files can't
        # silently drift apart without a passing test masking it.
        return next(p for p in caller_file.resolve().parents if (p / "common").is_dir()) / "common"

    def test_resolves_correctly_one_level_deep(self) -> None:
        # Matches schema/, knowledge/, policy/, decision/ today.
        with tempfile.TemporaryDirectory() as tmp:
            # .resolve() here too — on macOS /tmp (and /var) are symlinks,
            # and the snippet under test calls .resolve() on the caller
            # path (deliberately, so it's robust to symlinked checkouts),
            # so the expected value needs the same normalization or this
            # comparison fails on a path-representation technicality that
            # has nothing to do with the logic being tested.
            root = Path(tmp).resolve()
            (root / "common").mkdir()
            (root / "schema").mkdir()
            caller = root / "schema" / "validate.py"
            self.assertEqual(self._discover_common_dir(caller), root / "common")

    def test_resolves_correctly_two_levels_deep(self) -> None:
        # Matches Phase 1's detectors/{sub-skill}/ layout — this is the
        # exact case the original fixed-`.parent.parent` version got
        # wrong (it would have resolved to detectors/common, which
        # doesn't exist).
        with tempfile.TemporaryDirectory() as tmp:
            # .resolve() here too — on macOS /tmp (and /var) are symlinks,
            # and the snippet under test calls .resolve() on the caller
            # path (deliberately, so it's robust to symlinked checkouts),
            # so the expected value needs the same normalization or this
            # comparison fails on a path-representation technicality that
            # has nothing to do with the logic being tested.
            root = Path(tmp).resolve()
            (root / "common").mkdir()
            (root / "detectors" / "secret").mkdir(parents=True)
            caller = root / "detectors" / "secret" / "scanner.py"
            self.assertEqual(self._discover_common_dir(caller), root / "common")

    def test_resolves_correctly_three_levels_deep(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            # .resolve() here too — on macOS /tmp (and /var) are symlinks,
            # and the snippet under test calls .resolve() on the caller
            # path (deliberately, so it's robust to symlinked checkouts),
            # so the expected value needs the same normalization or this
            # comparison fails on a path-representation technicality that
            # has nothing to do with the logic being tested.
            root = Path(tmp).resolve()
            (root / "common").mkdir()
            (root / "detectors" / "secret" / "rules").mkdir(parents=True)
            caller = root / "detectors" / "secret" / "rules" / "aws.py"
            self.assertEqual(self._discover_common_dir(caller), root / "common")

    def test_all_nine_refactored_files_use_the_current_pattern_not_the_old_fixed_depth_one(self) -> None:
        security_skill_dir = COMMON_DIR.parent
        expected_files = [
            security_skill_dir / "schema" / "validate.py",
            security_skill_dir / "schema" / "render_markdown.py",
            security_skill_dir / "schema" / "render_html.py",
            security_skill_dir / "knowledge" / "validate_references.py",
            security_skill_dir / "knowledge" / "check_freshness.py",
            security_skill_dir / "policy" / "validate.py",
            security_skill_dir / "policy" / "engine.py",
            security_skill_dir / "decision" / "validate.py",
            security_skill_dir / "decision" / "decision.py",
        ]
        stale_pattern = 'Path(__file__).parent.parent / "common"'
        current_pattern = '(p / "common").is_dir()'
        for f in expected_files:
            content = f.read_text(encoding="utf-8")
            self.assertNotIn(stale_pattern, content, f"{f} still uses the depth-fragile pattern")
            self.assertIn(current_pattern, content, f"{f} doesn't use the depth-robust pattern")


if __name__ == "__main__":
    unittest.main()
