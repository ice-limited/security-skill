#!/usr/bin/env pwsh
# Setup script for security-skill (Windows PowerShell / PowerShell Core)
# — see docs/usage-guide.md.
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

$ErrorActionPreference = "Stop"

# Force UTF-8 console output so the Thai text below (docs/usage-guide.th.md
# pointer) renders correctly instead of depending on the host's default
# console encoding — same "never rely on locale defaults" discipline this
# project's own Python CLIs already follow.
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

if (-not (Test-Path "schema/finding.schema.json")) {
    Write-Error "this doesn't look like the security-skill repo root (schema/finding.schema.json not found)"
    exit 1
}

$PythonBin = if ($env:PYTHON_BIN) { $env:PYTHON_BIN } else { "python" }
if (-not (Get-Command $PythonBin -ErrorAction SilentlyContinue)) {
    Write-Error "$PythonBin not found on PATH — install Python 3 first"
    exit 1
}

Write-Host "== Python venv =="
if (-not (Test-Path ".venv")) {
    & $PythonBin -m venv .venv
    Write-Host "created .venv"
} else {
    Write-Host ".venv already exists, reusing it"
}

$VenvPy = ".venv\Scripts\python.exe"
if (-not (Test-Path $VenvPy)) {
    # PowerShell Core also runs on macOS/Linux, where a venv's layout is
    # .venv/bin/python3, not .venv/Scripts/python.exe — fall back so this
    # script still works there, not just on Windows PowerShell.
    $VenvPy = ".venv/bin/python3"
}
& $VenvPy -m pip install --upgrade pip --quiet

Write-Host ""
Write-Host "== Python dependencies =="
# Discover every real requirements.txt in the repo — excludes fixture
# data under */testdata/ (e.g. detectors/dependency/testdata/pypi-vulnerable/),
# which are deliberately-vulnerable test inputs, not install targets.
$reqFiles = Get-ChildItem -Path . -Filter "requirements.txt" -Recurse |
    Where-Object { $_.FullName -notmatch '[\\/]testdata[\\/]' -and $_.FullName -notmatch '[\\/]\.venv[\\/]' } |
    Sort-Object FullName

foreach ($req in $reqFiles) {
    $rel = Resolve-Path -Relative $req.FullName
    Write-Host "-- $rel"
    & $VenvPy -m pip install -r $req.FullName --quiet
}

Write-Host ""
Write-Host "== Node.js (detectors/api/ - Spectral spec-lint) =="
if (Get-Command npm -ErrorAction SilentlyContinue) {
    Push-Location detectors/api
    npm install --silent
    Pop-Location
    Write-Host "npm install done in detectors/api/"
} else {
    Write-Host "npm not found on PATH - skipped. Install Node.js, then run: cd detectors/api; npm install"
}

Write-Host ""
Write-Host "== Optional external tools =="
function Test-Tool {
    param([string]$Name, [string]$Hint)
    if (Get-Command $Name -ErrorAction SilentlyContinue) {
        Write-Host ("  [x] {0,-12} found" -f $Name)
    } else {
        Write-Host ("  [ ] {0,-12} not found - {1}" -f $Name, $Hint)
    }
}
Test-Tool "semgrep"     "pip install semgrep (needed by code-review, auth JWT half, api open_redirect)"
Test-Tool "trivy"       "prebuilt binary from trivy's own release page (needed by docker, kubernetes)"
Test-Tool "checkov"     "pip install checkov (needed by iac, cicd)"
Test-Tool "osv-scanner" "prebuilt binary, or Scoop/WinGet (needed by dependency)"
Test-Tool "scorecard"   "see OpenSSF Scorecard's own install docs (needed by one of supply-chain's three checks)"
Test-Tool "helm"        "see Helm's own install docs (only for kubernetes' Helm-chart-specific checks)"

Write-Host ""
Write-Host "== Done =="
Write-Host "Verify everything: $VenvPy run_all_tests.py"
Write-Host "Full walkthrough:   docs/usage-guide.md (English) / docs/usage-guide.th.md (ภาษาไทย)"
