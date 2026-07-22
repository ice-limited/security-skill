# Security Review — cpmatch/devops/example-service

branch `feature/payments` · commit `a1b2c3d4`

| Severity | Count |
|---|---|
| Critical | 1 |
| High | 1 |
| Medium | 1 |
| Low | 1 |
| Info | 0 |
| **Total** | **4** |

## Critical

### Hardcoded AWS access key

- **Location:** `config/deploy.env:4`
- **Rule:** `secret.aws-access-key`
- **Confidence:** 98%
- **Reference:** [CWE CWE-798](https://cwe.mitre.org/data/definitions/798.html)

**Problem:** An AWS access key ID and matching secret key are committed in plaintext.

**Impact:** Anyone with read access to this repository can assume the associated AWS identity and access any resource it's permitted to reach.

**Recommendation:** Revoke the key immediately, move credentials to a secrets manager (e.g. AWS Secrets Manager, SSM Parameter Store), and use short-lived role assumption in CI instead of static keys.

## High

### SQL query built via string concatenation

- **Location:** `src/handlers/orders.py:41`
- **Rule:** `code-review.sqli.string-concat`
- **Confidence:** 87%
- **Reference:** [CWE CWE-89](https://cwe.mitre.org/data/definitions/89.html), OWASP-Top10 A03:2021

**Problem:** User-supplied `request.params.id` is concatenated directly into a SQL query string.

**Impact:** An attacker can inject arbitrary SQL, potentially reading or modifying any data the database user can access.

**Recommendation:** Use parameterized queries / prepared statements instead of string concatenation.

## Medium

### Known vulnerability in requests 2.6.0

- **Location:** `requirements.lock:12`
- **Rule:** `dependency.cve`
- **Confidence:** 90%
- **Reference:** CWE CWE-200

**Problem:** The pinned version of `requests` is affected by a disclosed CVE.

**Impact:** Depending on usage, this can allow credential leakage via redirected requests.

**Recommendation:** Upgrade `requests` to a patched version.

## Low

### hostPath volume mounted in non-privileged workload _(suppressed)_

- **Location:** `deploy/statefulset.yaml:23-27`
- **Rule:** `kubernetes.hostpath-mount`
- **Confidence:** 70%
- **Reference:** CWE CWE-668

**Problem:** A `hostPath` volume is mounted, giving the pod access to the node's filesystem.

**Impact:** If the container is compromised, an attacker can read/write files on the underlying node.

**Recommendation:** Remove the hostPath mount or replace it with a scoped volume type (e.g. ConfigMap, PVC).

> Suppressed: Intentional — used only in the local-dev overlay, excluded from prod overlay.
