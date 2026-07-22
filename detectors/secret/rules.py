"""Secret detection rule catalog.

Pattern-matching rules are adapted from gitleaks
(https://github.com/gitleaks/gitleaks, config/gitleaks.toml, MIT
License, Copyright (c) 2019 Zachary Rice) — battle-tested against years
of real-world secret leaks rather than reinvented from scratch. Each
rule below cites its source gitleaks rule id. gitleaks itself has no
dedicated AWS *secret* key or database-connection-string rule (the
secret value has no distinctive format of its own) — this catalog
follows the same fallback to `generic-api-key` for those, rather than
inventing unproven patterns.

See plans/006-secret-detection-skill.md and
meetings/2026-07-22-1359-plan-006-kickoff.md in the
security-skill-workspace repo for design rationale.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    pattern: re.Pattern
    confidence: int
    problem: str
    impact: str
    recommendation: str
    references: list[dict] = field(default_factory=lambda: [{"standard": "CWE", "id": "CWE-798"}])
    requires_entropy_check: bool = False


_HARDCODED_CRED_REFS = [
    {"standard": "CWE", "id": "CWE-798"},
    {"standard": "OWASP-Top10", "id": "A07:2025"},
]

RULES: list[Rule] = [
    Rule(
        rule_id="secret.aws-access-key",
        title="Hardcoded AWS access key",
        # gitleaks rule id: aws-access-token
        pattern=re.compile(r"\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b"),
        confidence=95,
        problem="An AWS access key ID is hardcoded in this file.",
        impact=(
            "Anyone with read access to this repository can use this key to authenticate "
            "as the associated AWS identity and access any resource it's permitted to reach."
        ),
        recommendation=(
            "Revoke this key immediately via the AWS IAM console, then move credentials to a "
            "secrets manager (e.g. AWS Secrets Manager, SSM Parameter Store) or use short-lived "
            "role assumption in CI instead of static keys."
        ),
        references=_HARDCODED_CRED_REFS,
    ),
    Rule(
        rule_id="secret.github-pat",
        title="Hardcoded GitHub personal access token",
        # gitleaks rule id: github-pat
        pattern=re.compile(r"ghp_[0-9a-zA-Z]{36}"),
        confidence=95,
        problem="A GitHub personal access token is hardcoded in this file.",
        impact=(
            "Anyone with read access to this repository can use this token to act as the "
            "associated GitHub user, scoped to whatever permissions the token was granted."
        ),
        recommendation=(
            "Revoke this token immediately in GitHub Settings > Developer settings > Personal "
            "access tokens, then store credentials in a secrets manager or CI secret store "
            "instead of committing them."
        ),
        references=_HARDCODED_CRED_REFS,
    ),
    Rule(
        rule_id="secret.gitlab-pat",
        title="Hardcoded GitLab personal access token",
        # gitleaks rule id: gitlab-pat
        pattern=re.compile(r"glpat-[\w-]{20}"),
        confidence=95,
        problem="A GitLab personal access token is hardcoded in this file.",
        impact=(
            "Anyone with read access to this repository can use this token to act as the "
            "associated GitLab user, scoped to whatever permissions the token was granted."
        ),
        recommendation=(
            "Revoke this token immediately in GitLab User Settings > Access Tokens, then store "
            "credentials in a secrets manager or CI secret store instead of committing them."
        ),
        references=_HARDCODED_CRED_REFS,
    ),
    Rule(
        rule_id="secret.jwt",
        title="Hardcoded JSON Web Token (JWT)",
        # gitleaks rule id: jwt
        pattern=re.compile(r"\b(ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9/\\_-]{17,}\.(?:[a-zA-Z0-9/\\_-]{10,}={0,2})?)"),
        confidence=80,
        problem="A JSON Web Token (JWT) is hardcoded in this file.",
        impact=(
            "If this token is a live session/auth token (not a non-sensitive example), anyone "
            "with read access to this repository can use it to impersonate whatever identity or "
            "session it represents until it expires or is revoked."
        ),
        recommendation=(
            "If this is a real token, revoke/invalidate the underlying session immediately. "
            "Don't hardcode tokens — issue them at runtime and store them in memory or a secrets "
            "manager, not in source."
        ),
        references=_HARDCODED_CRED_REFS,
    ),
    Rule(
        rule_id="secret.private-key",
        title="Hardcoded RSA/SSH private key",
        # gitleaks rule id: private-key
        pattern=re.compile(r"-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S-]{64,}?KEY(?: BLOCK)?-----", re.IGNORECASE),
        confidence=98,
        problem="A PEM-formatted private key (RSA/SSH/etc.) is hardcoded in this file.",
        impact=(
            "Anyone with read access to this repository can use this key to authenticate to "
            "any system that trusts the matching public key (SSH access, TLS client auth, etc.)."
        ),
        recommendation=(
            "Rotate the key pair immediately (revoke the compromised public key everywhere it's "
            "trusted), then store private keys in a secrets manager or the CI/CD platform's "
            "encrypted secret store, never in source."
        ),
        references=[{"standard": "CWE", "id": "CWE-798"}],
    ),
    Rule(
        rule_id="secret.gcp-api-key",
        title="Hardcoded GCP API key",
        # gitleaks rule id: gcp-api-key
        pattern=re.compile(r"\b(AIza[\w-]{35})\b"),
        confidence=95,
        problem="A Google Cloud Platform API key is hardcoded in this file.",
        impact=(
            "Anyone with read access to this repository can use this key to call any GCP API "
            "it's authorized for, potentially incurring cost or accessing data on your behalf."
        ),
        recommendation=(
            "Regenerate this key in the GCP Console (APIs & Services > Credentials), restrict "
            "replacement keys by API/referrer/IP, and load them from a secrets manager or "
            "environment configuration instead of hardcoding them."
        ),
        references=_HARDCODED_CRED_REFS,
    ),
    Rule(
        rule_id="secret.azure-ad-client-secret",
        title="Hardcoded Azure AD client secret",
        # gitleaks rule id: azure-ad-client-secret
        pattern=re.compile(r"(?:^|[\\'\"`\s>=:(,)])([a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34})(?:$|[\\'\"`\s<),])"),
        confidence=85,
        problem="An Azure AD application client secret is hardcoded in this file.",
        impact=(
            "Anyone with read access to this repository can use this secret to authenticate as "
            "the associated Azure AD application, scoped to whatever permissions it's been granted."
        ),
        recommendation=(
            "Revoke this client secret in the Azure Portal (App registrations > Certificates & "
            "secrets), issue a replacement, and load it from Azure Key Vault or a CI secret "
            "store instead of hardcoding it."
        ),
        references=_HARDCODED_CRED_REFS,
    ),
    Rule(
        rule_id="secret.generic-api-key",
        title="Hardcoded credential (generic pattern)",
        # gitleaks rule id: generic-api-key (simplified: dropped the
        # scoped case-insensitive `(?-i:...)` toggle from the original,
        # which needs Python 3.11+ — a deliberate, minor simplification,
        # not a faithful byte-for-byte port).
        pattern=re.compile(
            r"[\w.-]{0,50}?(?:access|auth|api|credential|creds|key|passw(?:or)?d|secret|token)"
            r"(?:[ \t\w.-]{0,20})[\s'\"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'\"\s=]{0,5}"
            r"([\w.=-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3})",
            re.IGNORECASE,
        ),
        confidence=60,
        problem=(
            "A high-entropy value is assigned to a variable/key whose name suggests it's a "
            "credential (password, secret, token, api key, etc.), with no more specific pattern "
            "matching a known key format — most often database passwords or custom API keys."
        ),
        impact=(
            "If this value is a real credential, anyone with read access to this repository can "
            "use it to authenticate to whatever system it belongs to."
        ),
        recommendation=(
            "If this is a real credential, rotate it immediately and load it from a secrets "
            "manager, environment variable, or CI secret store instead of hardcoding it. If it's "
            "a placeholder/example value, consider using an obviously-fake value "
            "(e.g. 'changeme') to avoid tripping secret scanners."
        ),
        references=_HARDCODED_CRED_REFS,
        requires_entropy_check=True,
    ),
]
