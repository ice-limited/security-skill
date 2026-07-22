"""Check whether the vendored OWASP standards' recorded `_edition` still
matches each standard's current edition on GitHub.

Detection signal decided at plan 021's kickoff: the GitHub Contents API
on each standard's own edition/version directory — verified live during
that kickoff after the original candidate (GitHub Releases API for
ASVS) turned out to point at an auto-generated "Bleeding Edge" build,
not the stable release. See
plans/021-knowledge-base-freshness-checker.md in the
security-skill-workspace repo for the full reasoning trail.

This is a *checker*, not an updater: on drift, a standard is flagged for
the same manual WebFetch-and-verify pass used in plan 002 — it does not
rewrite knowledge/*.json itself.

Usage:
    python3 check_freshness.py
    GITHUB_TOKEN=ghp_... python3 check_freshness.py   # higher rate limit
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.request
from pathlib import Path
from typing import Callable

KNOWLEDGE_DIR = Path(__file__).parent

# (knowledge file, GitHub repo, path within repo, folder-name shape)
STANDARDS = {
    "OWASP-Top10": {
        "file": "owasp-top10.json",
        "repo": "OWASP/Top10",
        "path": "",
        "kind": "year",
    },
    "OWASP-ASVS": {
        "file": "owasp-asvs.json",
        "repo": "OWASP/ASVS",
        "path": "",
        "kind": "semver",
    },
    "OWASP-API-Top10": {
        "file": "owasp-api-top10.json",
        "repo": "OWASP/API-Security",
        "path": "editions",
        "kind": "year",
    },
}

_YEAR_RE = re.compile(r"^(19|20)\d{2}$")
_SEMVER_RE = re.compile(r"^\d+(\.\d+){1,2}$")

HttpGet = Callable[[str, "str | None"], list]


class FreshnessCheckError(Exception):
    """Raised when the live edition can't be confidently determined.

    Fail loud rather than silently reporting "up to date" — a missed
    drift is worse than a false alarm (decided at the 021 kickoff)."""


def default_http_get(url: str, token: str | None = None) -> list:
    """Real GitHub Contents API call. Tests inject a fake in its place —
    never hit the network in the default test run."""
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "security-skill-freshness-checker")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def _year_max(names: list[str]) -> str | None:
    years = [n for n in names if _YEAR_RE.match(n)]
    return max(years) if years else None


def _semver_tuple(s: str) -> tuple[int, int, int]:
    parts = [int(p) for p in s.split(".")]
    padded = (parts + [0, 0, 0])[:3]
    return (padded[0], padded[1], padded[2])


def _semver_max(names: list[str]) -> str | None:
    candidates = [n for n in names if _SEMVER_RE.match(n)]
    if not candidates:
        return None
    return max(candidates, key=_semver_tuple)


def _live_max_edition(kind: str, names: list[str]) -> str | None:
    if kind == "year":
        return _year_max(names)
    if kind == "semver":
        return _semver_max(names)
    raise ValueError(f"unknown edition kind: {kind}")


def _normalize(kind: str, value: str) -> tuple[int, ...]:
    if kind == "year":
        return (int(value),)
    return _semver_tuple(value)


def get_recorded_edition(standard: str) -> str:
    data = json.loads((KNOWLEDGE_DIR / STANDARDS[standard]["file"]).read_text(encoding="utf-8"))
    return data["_edition"]


def check_standard(
    standard: str,
    http_get: HttpGet = default_http_get,
    token: str | None = None,
) -> dict:
    """Returns {"standard", "recorded", "live", "status"} where status is
    "ok" (live == recorded), "stale" (live > recorded — the real drift
    case this plan exists for), or "anomaly" (live < recorded — almost
    certainly a fetch/parsing issue, not a real standards regression, but
    still surfaced rather than silently ignored)."""
    config = STANDARDS[standard]
    recorded = get_recorded_edition(standard)

    url = f"https://api.github.com/repos/{config['repo']}/contents/{config['path']}".rstrip("/")
    try:
        entries = http_get(url, token)
        names = [e["name"] for e in entries if e.get("type") == "dir"]
    except FreshnessCheckError:
        raise
    except Exception as e:
        raise FreshnessCheckError(f"{standard}: could not fetch {url}: {e}") from e

    live = _live_max_edition(config["kind"], names)
    if live is None:
        raise FreshnessCheckError(
            f"{standard}: found no {config['kind']}-shaped edition folder among {names!r}"
        )

    live_t = _normalize(config["kind"], live)
    recorded_t = _normalize(config["kind"], recorded)
    if live_t == recorded_t:
        status = "ok"
    elif live_t > recorded_t:
        status = "stale"
    else:
        status = "anomaly"

    return {"standard": standard, "recorded": recorded, "live": live, "status": status}


def check_all(http_get: HttpGet = default_http_get, token: str | None = None) -> list[dict]:
    token = token if token is not None else os.environ.get("GITHUB_TOKEN")
    results = []
    for standard in STANDARDS:
        try:
            results.append(check_standard(standard, http_get=http_get, token=token))
        except FreshnessCheckError as e:
            results.append({"standard": standard, "status": "unknown", "error": str(e)})
    return results


def main(results: list[dict] | None = None) -> int:
    """Prints the report and returns the process exit code. Takes
    `results` as an optional parameter (rather than always calling
    `check_all()` itself) so tests can exercise the print/exit-code
    logic without a real or mocked network round-trip."""
    if results is None:
        results = check_all()
    problems = 0
    for r in results:
        if r["status"] == "ok":
            print(f"OK: {r['standard']} is current ({r['recorded']})")
        elif r["status"] == "stale":
            print(
                f"STALE: {r['standard']} recorded={r['recorded']} live={r['live']} "
                f"— re-verify and update knowledge/{STANDARDS[r['standard']]['file']}",
                file=sys.stderr,
            )
            problems += 1
        elif r["status"] == "anomaly":
            print(
                f"ANOMALY: {r['standard']} recorded={r['recorded']} but live max "
                f"found was {r['live']} (lower) — likely a fetch/parsing issue, check manually",
                file=sys.stderr,
            )
            problems += 1
        else:
            print(f"UNKNOWN: {r['error']}", file=sys.stderr)
            problems += 1
    return 1 if problems else 0


if __name__ == "__main__":
    # Reconfigured here, not inside main(), so tests that redirect
    # stdout/stderr to an io.StringIO (which has no .reconfigure()) can
    # still call main() directly. See plans/022-cross-platform-compatibility.md.
    sys.stdout.reconfigure(encoding="utf-8", newline="\n")
    sys.stderr.reconfigure(encoding="utf-8", newline="\n")
    sys.exit(main())
