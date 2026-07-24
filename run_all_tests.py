"""Cross-sub-skill evaluation harness (plan 020).

Discovers every `test_*.py` file in this repo and runs each one as its
own `python3 -m unittest <module>` subprocess, invoked from its own
file's directory — the same way every directory's own README already
documents running it (several rely on a cwd-relative `sys.path` trick
to find sibling modules, so running from elsewhere would break them).
Reports a per-directory pass/fail/skip summary and exits non-zero only
if something actually failed or errored.

**Skips are not failures.** A subprocess-driving test skipping itself
because a real external tool (`semgrep`/`trivy`/`checkov`/
`osv-scanner`/`scorecard`/`helm`) isn't on `PATH` is expected, documented
behavior (see docs/testing-standards.md) — this harness reports skip
counts separately and never lets them affect the exit code.

Prefers `.venv/bin/python`/`.venv/bin/python3` at this repo's root if it
exists (this project's own real, populated venv — see README.md), since
several suites need real packages (`jsonschema`, `checkov`, `semgrep`,
...) that aren't guaranteed to be on the system `python3`. Falls back to
`sys.executable` otherwise.

Usage: python3 run_all_tests.py [--verbose]
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).parent

_EXCLUDE_DIR_NAMES = {".venv", "__pycache__", "node_modules", ".git"}

_RAN_RE = re.compile(r"Ran (\d+) tests? in [\d.]+s")
_RESULT_RE = re.compile(r"^(OK|FAILED)(?: \(([^)]*)\))?\s*$", re.MULTILINE)


def _venv_python_and_env() -> tuple[str, dict[str, str]]:
    """Returns the interpreter to use plus a subprocess environment with
    the venv's own bin/ prepended to PATH.

    Calling `.venv/bin/python3` by absolute path runs the right
    interpreter, but does **not** put `.venv/bin` on PATH the way
    `source .venv/bin/activate` would — a real gap this harness found:
    `common/test_checkov_wrapper.py` and `detectors/iac/test_scanner.py`
    mock `subprocess.run` for their own output-normalization tests, but
    still call the real `_check_checkov_available()` first, which uses
    `shutil.which("checkov")` against the *inherited* PATH. Without this
    fix, those tests fail in any shell that hasn't manually activated the
    venv - not a bug in the tests or in checkov_wrapper.py, an
    environment gap in how this harness invoked them."""
    env = os.environ.copy()
    venv_bin = REPO_ROOT / ".venv" / "bin"
    for name in ("python3", "python"):
        candidate = venv_bin / name
        if candidate.is_file():
            env["PATH"] = f"{venv_bin}{os.pathsep}{env.get('PATH', '')}"
            return str(candidate), env
    return sys.executable, env


def _discover_test_modules() -> list[Path]:
    modules = []
    for path in sorted(REPO_ROOT.rglob("test_*.py")):
        if any(part in _EXCLUDE_DIR_NAMES for part in path.relative_to(REPO_ROOT).parts):
            continue
        modules.append(path)
    return modules


@dataclass
class ModuleResult:
    path: Path
    ran: int = 0
    failures: int = 0
    errors: int = 0
    skipped: int = 0
    crashed: bool = False
    raw_tail: str = ""

    @property
    def ok(self) -> bool:
        return not self.crashed and self.failures == 0 and self.errors == 0


def _parse_detail(detail: str | None) -> dict[str, int]:
    if not detail:
        return {}
    return {key: int(value) for key, value in re.findall(r"(\w+)=(\d+)", detail)}


def _run_module(python_exe: str, env: dict[str, str], path: Path) -> ModuleResult:
    module_name = path.stem
    result = ModuleResult(path=path)
    try:
        proc = subprocess.run(
            [python_exe, "-m", "unittest", module_name],
            cwd=path.parent,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=300,
            env=env,
        )
    except subprocess.TimeoutExpired:
        result.crashed = True
        result.raw_tail = "timed out after 300s"
        return result

    output = proc.stdout + proc.stderr
    ran_match = _RAN_RE.search(output)
    result_match = _RESULT_RE.search(output)

    if ran_match is None or result_match is None:
        # No parseable unittest summary at all (e.g. an import error
        # before any test ran) - a real failure, not a silent skip.
        result.crashed = True
        result.raw_tail = "\n".join(output.strip().splitlines()[-15:])
        return result

    result.ran = int(ran_match.group(1))
    status, detail = result_match.group(1), result_match.group(2)
    counts = _parse_detail(detail)
    result.failures = counts.get("failures", 0)
    result.errors = counts.get("errors", 0)
    result.skipped = counts.get("skipped", 0)
    if status == "FAILED" and result.failures == 0 and result.errors == 0:
        # Defensive: a FAILED status with neither count parsed would
        # otherwise silently read as passing.
        result.errors = 1
    return result


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    verbose = "--verbose" in argv

    python_exe, env = _venv_python_and_env()
    modules = _discover_test_modules()
    if not modules:
        print("No test_*.py files found.", file=sys.stderr)
        return 1

    results_by_dir: dict[Path, list[ModuleResult]] = {}
    for path in modules:
        rel_dir = path.parent.relative_to(REPO_ROOT)
        result = _run_module(python_exe, env, path)
        results_by_dir.setdefault(rel_dir, []).append(result)
        if verbose:
            label = "OK" if result.ok else ("CRASHED" if result.crashed else "FAILED")
            print(f"  {path.relative_to(REPO_ROOT)}: {label}")

    total_ran = total_failures = total_errors = total_skipped = 0
    any_failed = False

    print(f"\n{'Directory':<35} {'Tests':>6} {'Fail':>5} {'Err':>5} {'Skip':>5}  Status")
    print("-" * 75)
    for rel_dir in sorted(results_by_dir, key=str):
        dir_results = results_by_dir[rel_dir]
        ran = sum(r.ran for r in dir_results)
        failures = sum(r.failures for r in dir_results)
        errors = sum(r.errors for r in dir_results)
        skipped = sum(r.skipped for r in dir_results)
        crashed = any(r.crashed for r in dir_results)
        ok = all(r.ok for r in dir_results)

        total_ran += ran
        total_failures += failures
        total_errors += errors
        total_skipped += skipped
        if not ok:
            any_failed = True

        status = "ok" if ok else ("CRASHED" if crashed else "FAILED")
        print(f"{str(rel_dir):<35} {ran:>6} {failures:>5} {errors:>5} {skipped:>5}  {status}")

        if not ok:
            for result in dir_results:
                if not result.ok:
                    print(f"    -> {result.path.name}: {result.raw_tail or 'see failures/errors above'}")

    print("-" * 75)
    print(
        f"{'TOTAL':<35} {total_ran:>6} {total_failures:>5} {total_errors:>5} {total_skipped:>5}  "
        f"{'ok' if not any_failed else 'FAILED'}"
    )
    print(
        f"\n{len(modules)} test file(s) across {len(results_by_dir)} directorie(s). "
        f"Skips ({total_skipped}) do not affect exit status."
    )

    return 1 if any_failed else 0


if __name__ == "__main__":
    sys.exit(main())
