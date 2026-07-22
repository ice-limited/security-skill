# API — reference

AuthN/authz, mass assignment, rate limiting, JWT handling, CORS, open
redirect, + related, for OpenAPI/other API specs and the source code
implementing them.

## Commands

Three separate mechanisms — run whichever apply to what's in scope:

```
python3 detectors/api/scanner.py openapi.yaml       # Spectral OWASP-ruleset spec-lint
python3 detectors/api/open_redirect.py src/          # Semgrep, CWE-601 open redirect in source
python3 detectors/api/crossref.py openapi.yaml       # spec-aware auth cross-reference (deterministic-extraction + playbook hybrid)
```

## Prerequisite — this sub-skill is not pip-install-only

Unlike every other detector, `detectors/api/` also needs **Node.js/npm**
(for Spectral + its OWASP ruleset), in addition to the shared Python
venv:

```
cd detectors/api && npm install    # installs Spectral + OWASP ruleset locally
pip install -r requirements.txt    # PyYAML + ruamel.yaml
```

`open_redirect.py` additionally requires the real `semgrep` CLI on
`PATH` (`pip install semgrep`). If any prerequisite is missing, relay
the error verbatim per `SKILL.md`'s hard rule — don't skip straight to
manual review just because one of the three mechanisms is unavailable;
run whichever of the three actually can run.

## Output

Each prints a JSON array of `Finding` objects on stdout (`ruleId` prefix
`api.*`). Report each one per `SKILL.md`'s Step 2.
