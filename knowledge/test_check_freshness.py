"""Tests for check_freshness.py.

All tests here inject a fake `http_get` — none hit the real network,
per plan 021's requirement (mockable HTTP layer, no flaky live calls in
the default suite). The one test that does call the real GitHub API is
explicitly opt-in via the RUN_LIVE_TESTS env var — see LiveSmokeTest.

Run with: python3 -m unittest test_check_freshness -v (from inside
knowledge/).
"""

from __future__ import annotations

import io
import json
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import MagicMock, patch

import check_freshness as cf


def _dirs(*names: str) -> list[dict]:
    return [{"name": n, "type": "dir"} for n in names]


def _fake_http_get(response: list[dict], captured: dict | None = None):
    def _get(url: str, token: str | None = None):
        if captured is not None:
            captured["url"] = url
            captured["token"] = token
        return response

    return _get


class YearParsingTests(unittest.TestCase):
    def test_picks_highest_year_and_ignores_non_year_names(self) -> None:
        names = ["2003", "2004", "2007", "2010", "2013", "2017", "2021", "2025", "2021-2003_Comparison"]
        self.assertEqual(cf._year_max(names), "2025")

    def test_returns_none_when_no_year_folders(self) -> None:
        self.assertIsNone(cf._year_max(["README.md", "assets"]))


class SemverParsingTests(unittest.TestCase):
    def test_picks_highest_semver(self) -> None:
        names = ["1.0", "2.0", "3.0", "3.0.1", "4.0", "5.0"]
        self.assertEqual(cf._semver_max(names), "5.0")

    def test_three_part_beats_two_part_correctly(self) -> None:
        # 3.0.1 must be treated as greater than 3.0, not string-sorted
        # (which would also happen to get this right, but the tuple
        # comparison must be the actual mechanism, not an accident).
        self.assertEqual(cf._semver_max(["3.0", "3.0.1"]), "3.0.1")

    def test_double_digit_minor_is_not_broken_by_string_sort(self) -> None:
        # A naive string-max would say "5.9" > "5.10" (wrong). Confirms
        # this is genuinely tuple-based, not lexicographic.
        self.assertEqual(cf._semver_max(["5.9", "5.10"]), "5.10")

    def test_returns_none_when_no_semver_folders(self) -> None:
        self.assertIsNone(cf._semver_max(["docs", "images"]))


class CheckStandardTests(unittest.TestCase):
    def test_ok_when_live_matches_recorded(self) -> None:
        # owasp-top10.json's recorded _edition is "2025".
        http_get = _fake_http_get(_dirs("2021", "2025", "2021-2003_Comparison"))
        result = cf.check_standard("OWASP-Top10", http_get=http_get)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["live"], "2025")

    def test_stale_when_live_is_newer(self) -> None:
        http_get = _fake_http_get(_dirs("2021", "2025", "2029"))
        result = cf.check_standard("OWASP-Top10", http_get=http_get)
        self.assertEqual(result["status"], "stale")
        self.assertEqual(result["live"], "2029")

    def test_anomaly_when_recorded_is_newer_than_live(self) -> None:
        # Simulates a truncated/bad fetch that misses the real max.
        http_get = _fake_http_get(_dirs("2017", "2021"))
        result = cf.check_standard("OWASP-Top10", http_get=http_get)
        self.assertEqual(result["status"], "anomaly")

    def test_semver_standard_ok_when_matches(self) -> None:
        # owasp-asvs.json's recorded _edition is "5.0.0"; live folder is
        # "5.0" — must compare equal via tuple normalization, not string.
        http_get = _fake_http_get(_dirs("1.0", "2.0", "3.0", "3.0.1", "4.0", "5.0"))
        result = cf.check_standard("OWASP-ASVS", http_get=http_get)
        self.assertEqual(result["status"], "ok")

    def test_raises_when_no_edition_folders_found(self) -> None:
        http_get = _fake_http_get([{"name": "README.md", "type": "file"}])
        with self.assertRaises(cf.FreshnessCheckError):
            cf.check_standard("OWASP-Top10", http_get=http_get)

    def test_raises_when_http_get_raises(self) -> None:
        def _boom(url, token=None):
            raise ConnectionError("network unreachable")

        with self.assertRaises(cf.FreshnessCheckError):
            cf.check_standard("OWASP-Top10", http_get=_boom)

    def test_file_entries_are_excluded_not_just_dirs(self) -> None:
        # A same-named file (not a dir) must not be mistaken for an
        # edition folder.
        http_get = _fake_http_get(
            [{"name": "2025", "type": "file"}, {"name": "2021", "type": "dir"}]
        )
        result = cf.check_standard("OWASP-Top10", http_get=http_get)
        self.assertEqual(result["live"], "2021")

    def test_token_is_passed_through_to_http_get(self) -> None:
        captured: dict = {}
        http_get = _fake_http_get(_dirs("2025"), captured=captured)
        cf.check_standard("OWASP-Top10", http_get=http_get, token="secret-token")
        self.assertEqual(captured["token"], "secret-token")

    def test_url_targets_correct_repo_and_path(self) -> None:
        captured: dict = {}
        http_get = _fake_http_get(_dirs("2019", "2023"), captured=captured)
        cf.check_standard("OWASP-API-Top10", http_get=http_get)
        self.assertEqual(
            captured["url"], "https://api.github.com/repos/OWASP/API-Security/contents/editions"
        )

    def test_raises_for_semver_standard_too_when_no_folders_match(self) -> None:
        # The earlier "raises when no edition folders found" test only
        # exercised the year-shaped path (OWASP-Top10); ASVS's
        # semver-shaped path goes through a different parser
        # (_semver_max) and needs its own coverage.
        http_get = _fake_http_get([{"name": "docs", "type": "dir"}, {"name": "images", "type": "dir"}])
        with self.assertRaises(cf.FreshnessCheckError):
            cf.check_standard("OWASP-ASVS", http_get=http_get)


class ConfigConsistencyTests(unittest.TestCase):
    """STANDARDS in check_freshness.py must stay in sync with the actual
    knowledge/*.json files and with plan 002's `_edition` convention —
    nothing else would catch these silently drifting apart."""

    def test_every_standards_file_exists_on_disk(self) -> None:
        for config in cf.STANDARDS.values():
            path = cf.KNOWLEDGE_DIR / config["file"]
            self.assertTrue(path.exists(), f"{path} does not exist")

    def test_get_recorded_edition_reads_the_right_file_for_each_standard(self) -> None:
        for standard, config in cf.STANDARDS.items():
            expected = json.loads((cf.KNOWLEDGE_DIR / config["file"]).read_text())["_edition"]
            self.assertEqual(cf.get_recorded_edition(standard), expected)

    def test_every_configured_standard_is_a_valid_finding_schema_enum_value(self) -> None:
        # Mirrors plan 002's CrossRepoConsistencyTests: a standard named
        # here that isn't a real `standard` enum value in
        # finding.schema.json would be a silent typo.
        finding_schema = json.loads(
            (cf.KNOWLEDGE_DIR.parent / "schema" / "finding.schema.json").read_text()
        )
        schema_enum = set(
            finding_schema["$defs"]["standardReference"]["properties"]["standard"]["enum"]
        )
        self.assertTrue(set(cf.STANDARDS).issubset(schema_enum))


class DefaultHttpGetTests(unittest.TestCase):
    """Unit-tests request construction in isolation from the network, so
    a flaky/offline connection can't be confused with a real code bug —
    distinct from LiveSmokeTest, which needs the real network."""

    @patch("check_freshness.urllib.request.urlopen")
    def test_builds_request_with_expected_headers_and_no_auth_by_default(self, mock_urlopen) -> None:
        mock_response = MagicMock()
        mock_response.read.return_value = b"[]"
        mock_urlopen.return_value.__enter__.return_value = mock_response

        cf.default_http_get("https://api.github.com/repos/OWASP/Top10/contents")

        sent_request = mock_urlopen.call_args[0][0]
        self.assertEqual(sent_request.full_url, "https://api.github.com/repos/OWASP/Top10/contents")
        self.assertEqual(sent_request.get_header("Accept"), "application/vnd.github+json")
        self.assertIsNone(sent_request.get_header("Authorization"))

    @patch("check_freshness.urllib.request.urlopen")
    def test_includes_bearer_token_when_provided(self, mock_urlopen) -> None:
        mock_response = MagicMock()
        mock_response.read.return_value = b"[]"
        mock_urlopen.return_value.__enter__.return_value = mock_response

        cf.default_http_get("https://api.github.com/repos/OWASP/Top10/contents", token="secret-token")

        sent_request = mock_urlopen.call_args[0][0]
        self.assertEqual(sent_request.get_header("Authorization"), "Bearer secret-token")

    @patch("check_freshness.urllib.request.urlopen")
    def test_parses_json_response_body(self, mock_urlopen) -> None:
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(_dirs("2025")).encode()
        mock_urlopen.return_value.__enter__.return_value = mock_response

        result = cf.default_http_get("https://api.github.com/repos/OWASP/Top10/contents")
        self.assertEqual(result, _dirs("2025"))


class MainCliTests(unittest.TestCase):
    """Tests check_freshness.main()'s print/exit-code logic directly,
    bypassing check_all() (and therefore the network) entirely."""

    def _run_main(self, results: list[dict]) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cf.main(results)
        return code, out.getvalue(), err.getvalue()

    def test_returns_0_and_prints_ok_when_everything_current(self) -> None:
        results = [
            {"standard": "OWASP-Top10", "recorded": "2025", "live": "2025", "status": "ok"},
        ]
        code, out, err = self._run_main(results)
        self.assertEqual(code, 0)
        self.assertIn("OK: OWASP-Top10 is current (2025)", out)
        self.assertEqual(err, "")

    def test_returns_1_when_stale(self) -> None:
        results = [
            {"standard": "OWASP-Top10", "recorded": "2021", "live": "2025", "status": "stale"},
        ]
        code, out, err = self._run_main(results)
        self.assertEqual(code, 1)
        self.assertIn("STALE", err)
        self.assertIn("2021", err)
        self.assertIn("2025", err)

    def test_returns_1_when_anomaly(self) -> None:
        results = [
            {"standard": "OWASP-ASVS", "recorded": "5.0.0", "live": "4.0", "status": "anomaly"},
        ]
        code, out, err = self._run_main(results)
        self.assertEqual(code, 1)
        self.assertIn("ANOMALY", err)

    def test_returns_1_when_unknown(self) -> None:
        results = [{"standard": "OWASP-Top10", "status": "unknown", "error": "network unreachable"}]
        code, out, err = self._run_main(results)
        self.assertEqual(code, 1)
        self.assertIn("UNKNOWN", err)
        self.assertIn("network unreachable", err)

    def test_one_bad_standard_still_reports_the_others(self) -> None:
        results = [
            {"standard": "OWASP-Top10", "recorded": "2025", "live": "2025", "status": "ok"},
            {"standard": "OWASP-ASVS", "recorded": "4.0.0", "live": "5.0", "status": "stale"},
        ]
        code, out, err = self._run_main(results)
        self.assertEqual(code, 1)
        self.assertIn("OK: OWASP-Top10", out)
        self.assertIn("STALE: OWASP-ASVS", err)


class CheckAllTests(unittest.TestCase):
    def test_checks_all_three_standards(self) -> None:
        def http_get(url: str, token: str | None = None):
            if "Top10" in url:
                return _dirs("2021", "2025")
            if "ASVS" in url:
                return _dirs("4.0", "5.0")
            if "API-Security" in url:
                return _dirs("2019", "2023")
            raise AssertionError(f"unexpected url {url}")

        results = cf.check_all(http_get=http_get)
        self.assertEqual({r["standard"] for r in results}, set(cf.STANDARDS))
        self.assertTrue(all(r["status"] == "ok" for r in results))

    def test_mixed_results_dont_stop_other_checks(self) -> None:
        def http_get(url: str, token: str | None = None):
            if "Top10" in url:
                raise ConnectionError("boom")
            if "ASVS" in url:
                return _dirs("4.0", "5.0")
            return _dirs("2019", "2023")

        results = cf.check_all(http_get=http_get)
        statuses = {r["standard"]: r["status"] for r in results}
        self.assertEqual(statuses["OWASP-Top10"], "unknown")
        self.assertEqual(statuses["OWASP-ASVS"], "ok")
        self.assertEqual(statuses["OWASP-API-Top10"], "ok")

    def test_github_token_env_var_is_picked_up_when_not_passed_explicitly(self) -> None:
        captured: dict = {}
        http_get = _fake_http_get(_dirs("2025"), captured=captured)
        old = os.environ.get("GITHUB_TOKEN")
        os.environ["GITHUB_TOKEN"] = "env-token"
        try:
            cf.check_all(http_get=http_get)
        finally:
            if old is None:
                del os.environ["GITHUB_TOKEN"]
            else:
                os.environ["GITHUB_TOKEN"] = old
        self.assertEqual(captured["token"], "env-token")


@unittest.skipUnless(
    os.environ.get("RUN_LIVE_TESTS"),
    "opt-in only (hits the real GitHub API) — set RUN_LIVE_TESTS=1 to run",
)
class LiveSmokeTest(unittest.TestCase):
    """Not part of the default suite — network-dependent and subject to
    GitHub's rate limits. Exists to sanity-check the real endpoint shape
    still matches what the mocked tests assume."""

    def test_real_github_api_is_reachable_and_shaped_as_expected(self) -> None:
        result = cf.check_standard("OWASP-Top10")
        self.assertIn(result["status"], {"ok", "stale", "anomaly"})


if __name__ == "__main__":
    unittest.main()
