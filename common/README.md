# common/

Shared utilities used by every other directory in this repo. See
`plans/005-repo-scaffolding-adapter-architecture.md` and
`meetings/2026-07-22-1327-plan-005-kickoff.md` in the
security-skill-workspace repo for why this exists — it replaces
boilerplate that had been duplicated 8 times across `schema/`,
`knowledge/`, `policy/`, `decision/` before Phase 1 was about to
duplicate it 8 more.

## `streams.py`

`reconfigure_streams(stdin=False, stdout=True, stderr=True)` — UTF-8
-reconfigures the requested std streams (plan 022's cross-platform
requirement). Call it only from a `if __name__ == "__main__":` guard,
never from inside a function tests might call with stdout/stderr
redirected to an `io.StringIO` (which has no `.reconfigure()`).

## `schema_validation.py`

`validate_against_schema(schema, instance, registry=None) -> list[str]`
— the shared `Draft202012Validator` pattern, with `format_checker`
attached by construction (the exact gap that let a malformed
`expiresAt` date silently pass validation in plan 004, before it was
fixed there and then centralized here). Pass `registry` for a schema
that `$ref`s another schema file (see `schema/validate.py`); omit it for
a self-contained schema (`policy/policy.schema.json`,
`decision/exceptions.schema.json`).

## How other directories use this

Since this repo has no package/install infrastructure (no
`pyproject.toml`, no `__init__.py`, everything runs as plain scripts —
deliberately, matching every other module here), importing across
directories uses a `sys.path.insert` at the top of the importing file.
**Walk upward to find `common/`, don't hardcode `.parent.parent`** — a
fixed depth works for 1-level-deep directories but silently breaks for
Phase 1's 2-level-deep `detectors/{sub-skill}/` layout (a real bug found
and fixed while testing plan 005, covered by
`PathDiscoveryPatternTests` in `test_common.py`):

```python
_common_dir = next(p for p in Path(__file__).resolve().parents if (p / "common").is_dir()) / "common"
sys.path.insert(0, str(_common_dir))
from streams import reconfigure_streams
```

## Cross-platform

Every file read/write here specifies `encoding="utf-8"` explicitly
(plan 022). Verify with:
`LC_ALL=en_US.US-ASCII LANG=en_US.US-ASCII python3 -m unittest test_common -v`
(macOS/Linux; see the top-level `security-skill/README.md`).
