@echo off
setlocal enabledelayedexpansion
rem Force UTF-8 console output so the Thai text below (docs/usage-guide.th.md
rem pointer) renders correctly instead of depending on the system's default
rem codepage (often not UTF-8) — same "never rely on locale defaults"
rem discipline this project's own Python CLIs already follow.
chcp 65001 >nul
rem Setup script for security-skill (Windows cmd.exe) — see docs/usage-guide.md.
rem
rem Creates a venv at this repo's root, installs every real requirements.txt
rem in the repo (discovered dynamically, not a hardcoded list — a static
rem list has already gone stale twice in this project's own history, see
rem docs/testing-standards.md), runs `npm install` for detectors/api/ if
rem Node.js is available, and reports which optional external tools
rem (semgrep/trivy/checkov/osv-scanner/scorecard/helm) are and aren't on
rem PATH, with the install command each detector's own error message would
rem give you. Never installs those external tools itself — only the ones
rem you actually need for the artifact types you scan.

cd /d "%~dp0"

if not exist "schema\finding.schema.json" (
    echo error: this doesn't look like the security-skill repo root ^(schema\finding.schema.json not found^)
    exit /b 1
)

if "%PYTHON_BIN%"=="" set "PYTHON_BIN=python"
where %PYTHON_BIN% >nul 2>&1
if errorlevel 1 (
    echo error: %PYTHON_BIN% not found on PATH — install Python 3 first
    exit /b 1
)

echo == Python venv ==
if not exist ".venv" (
    %PYTHON_BIN% -m venv .venv
    echo created .venv
) else (
    echo .venv already exists, reusing it
)

set "VENV_PY=.venv\Scripts\python.exe"
"%VENV_PY%" -m pip install --upgrade pip --quiet

echo.
echo == Python dependencies ==
rem Discover every real requirements.txt in the repo — excludes fixture
rem data under \testdata\ (e.g. detectors\dependency\testdata\pypi-vulnerable\),
rem which are deliberately-vulnerable test inputs, not install targets.
for /r %%F in (requirements.txt) do (
    set "REQPATH=%%F"
    echo !REQPATH! | findstr /i "\\testdata\\" >nul
    if errorlevel 1 (
        echo -- %%F
        "%VENV_PY%" -m pip install -r "%%F" --quiet
    )
)

echo.
echo == Node.js ^(detectors\api\ - Spectral spec-lint^) ==
where npm >nul 2>&1
if errorlevel 1 (
    echo npm not found on PATH - skipped. Install Node.js, then run: cd detectors\api ^&^& npm install
) else (
    pushd detectors\api
    call npm install --silent
    popd
    echo npm install done in detectors\api\
)

echo.
echo == Optional external tools ==
call :checktool semgrep     "pip install semgrep (needed by code-review, auth JWT half, api open_redirect)"
call :checktool trivy       "prebuilt binary from trivy's own release page (needed by docker, kubernetes)"
call :checktool checkov     "pip install checkov (needed by iac, cicd)"
call :checktool osv-scanner "prebuilt binary, or Scoop/WinGet (needed by dependency)"
call :checktool scorecard   "see OpenSSF Scorecard's own install docs (needed by one of supply-chain's three checks)"
call :checktool helm        "see Helm's own install docs (only for kubernetes' Helm-chart-specific checks)"

echo.
echo == Done ==
echo Verify everything: %VENV_PY% run_all_tests.py
echo Full walkthrough:   docs\usage-guide.md (English) / docs\usage-guide.th.md (ภาษาไทย)
exit /b 0

:checktool
where %~1 >nul 2>&1
if errorlevel 1 (
    echo   [ ] %~1 not found - %~2
) else (
    echo   [x] %~1 found
)
exit /b 0
