"""Deterministic OpenAPI spec parsing: extracts, for every declared
operation, whether it is secured (has a non-empty `security` at the
operation level, or inherits a non-empty global `security` when the
operation omits the keyword entirely) — with real line numbers via
ruamel.yaml's round-trip loader (`.lc.line`/`.lc.col`), not just a
parsed-dict-with-no-location.

This is the deterministic half of this plan's spec-aware cross-
reference mechanism (the other half, `crossref.py`, renders this
extraction as playbook guidance for the invoking agent to correlate
against the implementation's route handlers). Splitting the mechanism
this way — deterministic extraction + playbook guidance for the part
that genuinely needs code-level judgment — mirrors detectors/auth's
(023) own precedent exactly: 023's own README states plainly that it
"has no deterministic scanner for most of cpmatch's stack" and instead
renders a checklist for the invoking agent to reason over the code
directly. Building a bespoke per-framework route-extractor (Flask,
Express, FastAPI, Spring, ...) to achieve full determinism here would
either be dishonest about its real coverage (cpmatch's stack is 13+
languages, per plan 007) or a large multi-framework engineering effort
this plan's kickoff explicitly deferred ("exact mechanism ... this
plan's hardest design problem") — reusing 023's already-accepted hybrid
shape is the more honest, better-precedented choice, decided here at
implementation rather than at the kickoff.

See plans/012-api-skill.md in the security-skill-workspace repo.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from ruamel.yaml import YAML

_HTTP_METHODS = frozenset({"get", "put", "post", "delete", "options", "head", "patch", "trace"})

_yaml = YAML(typ="rt")


class SpecParseError(Exception):
    """Raised when the spec file cannot be parsed at all (not valid YAML/JSON,
    or its top level isn't a mapping) — fail loud rather than silently
    reporting zero operations, which would look identical to "parsed
    fine, API has no security-relevant operations."""


@dataclass(frozen=True)
class Operation:
    path: str
    method: str
    line: int
    security_schemes: tuple[str, ...]
    explicitly_unsecured: bool

    @property
    def is_secured(self) -> bool:
        return len(self.security_schemes) > 0


def load_spec(path: Path) -> object:
    """Loads an OpenAPI spec (YAML or JSON — JSON is a valid subset of
    YAML, so ruamel's YAML round-trip loader parses both, preserving
    line numbers either way, verified for real against a `.json` fixture
    at implementation)."""
    text = path.read_text(encoding="utf-8")
    try:
        doc = _yaml.load(text)
    except Exception as e:  # ruamel raises various yaml.YAMLError subclasses
        raise SpecParseError(f"{path}: not valid YAML/JSON: {e}") from e
    if not isinstance(doc, dict):
        raise SpecParseError(f"{path}: top-level document is not a mapping (got {type(doc).__name__})")
    return doc


def _security_scheme_names(security_entry: list) -> tuple[str, ...]:
    names: list[str] = []
    for requirement in security_entry:
        if isinstance(requirement, dict):
            names.extend(requirement.keys())
    return tuple(names)


def extract_operations(spec: dict) -> list[Operation]:
    """Walks `paths`, returning one Operation per (path, HTTP method)
    found. `parameters`/`summary`/`description`/`$ref`/`servers` and any
    other non-method key under a path item are skipped, not
    misidentified as a method."""
    global_security = spec.get("security")
    global_schemes = _security_scheme_names(global_security) if isinstance(global_security, list) else ()

    operations: list[Operation] = []
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return operations

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method not in _HTTP_METHODS or not isinstance(operation, dict):
                continue

            line = 1
            try:
                line = path_item.lc.data[method][0] + 1  # ruamel: 0-indexed -> 1-indexed
            except (AttributeError, KeyError, TypeError):
                pass

            if "security" in operation:
                op_security = operation.get("security")
                schemes = _security_scheme_names(op_security) if isinstance(op_security, list) else ()
                explicitly_unsecured = len(schemes) == 0
            else:
                schemes = global_schemes
                explicitly_unsecured = False

            operations.append(
                Operation(
                    path=str(path),
                    method=str(method),
                    line=line,
                    security_schemes=schemes,
                    explicitly_unsecured=explicitly_unsecured,
                )
            )

    return operations


def secured_operations(operations: list[Operation]) -> list[Operation]:
    """Operations this spec declares as requiring at least one security
    scheme — the candidates for this plan's cross-reference check
    (does the implementation actually enforce what the spec declares?).
    Excludes operations that are unsecured either explicitly
    (`security: []`) or by omission with no applicable global
    security."""
    return [op for op in operations if op.is_secured]


def load_and_extract(path: Path) -> list[Operation]:
    return extract_operations(load_spec(path))
