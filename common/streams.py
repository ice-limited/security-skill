"""Shared stdio UTF-8 reconfiguration, used by every CLI entry point in
this repo.

See plans/022-cross-platform-compatibility.md in the
security-skill-workspace repo for why this exists: Python's stdin/stdout
default to the OS locale's preferred encoding (commonly UTF-8 on
macOS/Linux, commonly something else, e.g. cp1252, on Windows), and this
codebase's own data already contains non-ASCII characters that crash
under a non-UTF-8 default.

Centralized here (plan 005) after the same 2-3 line block was duplicated
8 times across schema/, knowledge/, policy/, decision/.
"""

from __future__ import annotations

import sys


def reconfigure_streams(stdin: bool = False, stdout: bool = True, stderr: bool = True) -> None:
    """Reconfigures the requested std streams to UTF-8 explicitly.

    Call this ONLY from a `if __name__ == "__main__":` guard, never from
    inside a function a test might call with stdout/stderr redirected to
    an `io.StringIO` — `io.StringIO` has no `.reconfigure()` method, so
    calling this from shared logic (e.g. a testable `main()`) breaks
    those tests. This is why every CLI entry point in this repo puts
    `main()`'s actual logic in a plain function and reserves the
    `__main__` guard for exactly two things: this call, then
    `sys.exit(main())`.
    """
    if stdin:
        sys.stdin.reconfigure(encoding="utf-8")
    if stdout:
        sys.stdout.reconfigure(encoding="utf-8", newline="\n")
    if stderr:
        sys.stderr.reconfigure(encoding="utf-8", newline="\n")
