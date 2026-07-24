#!/usr/bin/env bash
# Setup script for security-skill (macOS/Linux) — see docs/usage-guide.md.
#
# Creates a venv at this repo's root, installs every real requirements.txt
# in the repo (discovered dynamically, not a hardcoded list — a static
# list has already gone stale twice in this project's own history, see
# docs/testing-standards.md), runs `npm install` for detectors/api/ if
# Node.js is available, and reports which optional external tools
# (semgrep/trivy/checkov/osv-scanner/scorecard/helm) are and aren't on
# PATH, with the install command each detector's own error message would
# give you. Never installs those external tools itself — only the ones
# you actually need for the artifact types you scan.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ ! -f "schema/finding.schema.json" ]]; then
  echo "error: this doesn't look like the security-skill repo root (schema/finding.schema.json not found)" >&2
  exit 1
fi

PYTHON_BIN="${PYTHON_BIN:-python3}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "error: $PYTHON_BIN not found on PATH — install Python 3 first" >&2
  exit 1
fi

echo "== Python venv =="
if [[ ! -d ".venv" ]]; then
  "$PYTHON_BIN" -m venv .venv
  echo "created .venv"
else
  echo ".venv already exists, reusing it"
fi

VENV_PY=".venv/bin/python3"
[[ -x "$VENV_PY" ]] || VENV_PY=".venv/bin/python"

"$VENV_PY" -m pip install --upgrade pip --quiet

echo
echo "== Python dependencies =="
# Discover every real requirements.txt in the repo — excludes fixture
# data under */testdata/ (e.g. detectors/dependency/testdata/pypi-vulnerable/),
# which are deliberately-vulnerable test inputs, not install targets.
while IFS= read -r -d '' req; do
  echo "-- $req"
  "$VENV_PY" -m pip install -r "$req" --quiet
done < <(find . -name "requirements.txt" -not -path "*/testdata/*" -not -path "*/.venv/*" -print0 | sort -z)

echo
echo "== Node.js (detectors/api/ — Spectral spec-lint) =="
if command -v npm >/dev/null 2>&1; then
  (cd detectors/api && npm install --silent)
  echo "npm install done in detectors/api/"
else
  echo "npm not found on PATH — skipped. Install Node.js, then run: cd detectors/api && npm install"
fi

echo
echo "== Optional external tools =="
check_tool() {
  local name="$1" hint="$2"
  if command -v "$name" >/dev/null 2>&1; then
    printf "  [x] %-12s found\n" "$name"
  else
    printf "  [ ] %-12s not found — %s\n" "$name" "$hint"
  fi
}
check_tool semgrep      "pip install semgrep (needed by code-review, auth JWT half, api open_redirect)"
check_tool trivy        "brew install trivy, or a prebuilt binary (needed by docker, kubernetes)"
check_tool checkov      "pip install checkov (needed by iac, cicd)"
check_tool osv-scanner  "brew install osv-scanner, or a prebuilt binary (needed by dependency)"
check_tool scorecard    "brew install scorecard (needed by one of supply-chain's three checks)"
check_tool helm         "see Helm's own install docs (only for kubernetes' Helm-chart-specific checks)"

echo
echo "== Done =="
echo "Verify everything: $VENV_PY run_all_tests.py"
echo "Full walkthrough:   docs/usage-guide.md (English) / docs/usage-guide.th.md (ภาษาไทย)"
