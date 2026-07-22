# detectors/docker/

Dockerfile hardening: unpinned base image, root user, missing
`HEALTHCHECK`, `apt-get upgrade`, `curl | bash`, `ADD` vs `COPY`. See
`plans/009-docker-skill.md` and
`meetings/2026-07-22-1900-plan-009-kickoff.md` in the
security-skill-workspace repo for design rationale.

## Why Trivy, not Hadolint

Both were verified for real at kickoff. **Hadolint** (the best-known
Dockerfile linter) is **GPL-3.0** and its missing-`HEALTHCHECK` rule is
disabled by default. **Trivy** (Aqua Security) is **Apache-2.0** and its
equivalent check (`DS-0026`) fires by default. Chose Trivy to avoid
GPL-3.0 entirely — a from-scratch, hand-written pattern rule for `ADD`
vs `COPY` (which Trivy doesn't have) was simpler than mixing license
models across two overlapping tools.

## What's Trivy-sourced vs. custom

| ruleId | Source | Trivy check ID |
|---|---|---|
| `docker.unpinned-base-image` | Trivy `config` scan | DS-0001 |
| `docker.root-user` | Trivy `config` scan | DS-0002 |
| `docker.missing-healthcheck` | Trivy `config` scan | DS-0026 |
| `docker.apt-upgrade` | Custom pattern rule | — |
| `docker.curl-pipe-shell` | Custom pattern rule | — |
| `docker.add-instead-of-copy` | Custom pattern rule | — |

Trivy's own metadata for its Dockerfile checks has no CWE mapping, so
`problem`/`impact`/`recommendation`/`references` for the three
Trivy-sourced checks are hand-authored in `rules.py` (`TRIVY_RULES`),
the same shape as 006's own catalog — a small, curated set of checks,
unlike 007/008's per-result rich-metadata mapping (which made sense
there because those tools' output had far more distinct check types).
`severity` for these three still comes from Trivy's own scan (it
already matches our `Critical`/`High`/`Medium`/`Low` scale directly).

**`docker.apt-upgrade`** and **`docker.curl-pipe-shell`** (piping a
downloaded script directly into a shell) and **`docker.add-instead-of-copy`**
are hand-written regex rules — verified at kickoff that neither Trivy
nor Hadolint has a security-specific check for any of these three.

**Trivy's own `DS-0031`** (secrets in `ENV`/build-args, found
unexpectedly while verifying this plan) is excluded via a temporary
`--ignorefile` passed to every invocation — 006 (Secret Detection) owns
hardcoded-secret detection exclusively across every artifact type, not
just source code. Verified this exclusion actually works from within
the test suite (`test_trivys_own_secret_check_is_excluded_not_supplemented`),
not just interactively.

## Two real bugs found during implementation, not by inspection

1. **Trivy rejects more than one scan target per invocation**
   (`trivy config` errors with "multiple targets cannot be specified"
   if given two paths at once) — unlike 007's Semgrep or 008's
   osv-scanner, which both accept a path list. `scan_paths()` invokes
   Trivy once per path and aggregates results, rather than trying to
   pass the whole list through in one call. Regression-tested with two
   *distinctly* vulnerable fixtures (not one vulnerable + one clean —
   an earlier version of this test didn't actually distinguish
   "scanned but clean" from "never scanned," caught via mutation
   testing).
2. **Trivy's own `Target` field is always relative to whatever root it
   scanned** (e.g. `"Dockerfile"`), never an absolute or CWD-relative
   path — reading it directly silently failed to find the file
   whenever the scanned path differed from the process's current
   working directory (which it always will, for any real caller).
   Fixed by resolving `Target` against the top-level `ArtifactName`
   field (the actual resolved root Trivy scanned — a directory, or the
   file itself if a single file was scanned directly). See
   `_resolve_target_path()`.

## Error handling — verified against real Trivy behavior, not assumed

Unlike 008's osv-scanner, Trivy's exit code **is** a reliable
success/failure signal on its own: `0` regardless of findings, nonzero
(confirmed `rc=1`) only for a genuine invocation failure (bad path,
etc.), with `FATAL`-prefixed stderr and empty stdout in that case — no
need for the "accept both 0 and 1" workaround 008 needed.

A mutation-testing round caught the same test-quality gap 008 hit:
`test_bad_path_raises_scanner_error` alone would pass even without the
return-code check (a bad path also produces empty stdout, which
independently fails JSON parsing) — added
`test_returncode_nonzero_raises_even_with_valid_json_stdout`, which
mocks `subprocess.run` to isolate the check specifically.

## A third real bug found during "test plan 009" testing: comments were scanned as code

The three custom regex rules matched text inside **Dockerfile
comments** — a line like `# Do NOT do this: curl ... | bash` (a
realistic thing to write, explaining what to avoid) was flagged as if
the anti-pattern were actually present in a real instruction.
`docker.add-instead-of-copy` was already safe (its pattern is anchored
to the start of the line, so `# ADD foo bar` never matched), but
`docker.apt-upgrade` and `docker.curl-pipe-shell` use unanchored
`.search()` and matched anywhere in the text. **Fixed** by blanking out
comment lines (`_blank_out_comment_lines()`, preserving line count so
line-number math stays correct) before any custom-rule pattern
matching. Mutation-tested by removing the call — the new regression
tests correctly failed (found the exact anti-patterns inside what
should have been inert comments).

Also verified in the same round, both already correct (no fix needed):
multi-stage Dockerfiles only flag the *final* stage for
unpinned-base-image/root-user, not an intermediate builder stage that
happens to be pinned (`test_multistage_dockerfile_only_flags_the_final_stage`);
and the `DS-0031` secrets exclusion covers `ARG` (build-args), not just
`ENV` (`test_trivys_own_secret_check_is_excluded_for_build_args_too`).

## Usage

```python
from scanner import scan_file, scan_paths

findings = scan_paths(["path/to/repo"])   # invokes trivy once per path given
findings = scan_file(Path("Dockerfile"))
```

```
python3 scanner.py path/to/project [--artifact-type dockerfile]
```

Requires the real `trivy` CLI on `PATH` (`brew install trivy`, a
prebuilt binary, or Scoop/WinGet on Windows) and network access for its
checks bundle on first run (cached locally after that, per this
environment's own cache directory).
`test_scanner.py`'s subprocess-driving tests skip themselves (not
fail) if it isn't installed, but are never mocked when it is (same
discipline as every prior external-tool wrapper here).

## Not this module's job

- File selection/exclusion — orchestration concern, same boundary as
  every other detector here.
- Secrets in `ENV`/build-args — 006's job exclusively (Trivy's own
  overlapping check is excluded, not supplemented).
- What happens once the image runs in a cluster — 010 (Kubernetes).
- Whether Trivy's `config` scan can run fully offline after the first
  checks-bundle download — observed cached locally in this
  environment, not independently verified fresh.

## Cross-platform

Every file read/write here specifies `encoding="utf-8"` explicitly.
Verify with:
`LC_ALL=en_US.US-ASCII LANG=en_US.US-ASCII python3 -m unittest test_scanner -v`
(macOS/Linux; see the top-level `security-skill/README.md`). Trivy has
full native Windows support (Scoop/WinGet), no beta caveat.
