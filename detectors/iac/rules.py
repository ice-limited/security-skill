"""IaC misconfiguration rule catalog: curated IAM + public-exposure
checks across AWS/Azure/GCP (Terraform + CloudFormation) plus Ansible
playbook hardening, via Checkov (github.com/bridgecrewio/checkov,
Apache-2.0).

Decided at kickoff: Checkov, not Trivy (already wrapped for 009/010) —
verified for real that Trivy's AWS IAM-wildcard check is deprecated and
doesn't fire, GCP has no project-level IAM check at all, and Ansible
has zero shipped checks despite being a listed scanner mode, while
Checkov covers all three. See plans/011-iac-skill.md and
meetings/2026-07-22-2100-plan-011-kickoff.md in the
security-skill-workspace repo for the full empirical trail.

Curated to a focused IAM + public-exposure checklist per cloud (not
Checkov's full multi-thousand-check catalog) — matches ROLES.md's own
framing of each cloud expert's focus (IAM policy findings, S3/SG
misconfig rules for AWS; Azure AD/RBAC for Azure; GCP IAM for GCP), and
010's own "curate now, expand later" precedent. Checkov's own check
metadata has no CWE/OWASP mapping (checked its check source directly at
kickoff), so problem/impact/recommendation/references are hand-authored
here, same situation as 009/010's TRIVY_RULES.

**Framework-specific check IDs**: unlike Trivy's unified "cloud" schema
(identical check IDs regardless of source format), Checkov's IDs are
often framework-specific for the same logical concern — verified for
real at kickoff by running an identical fixture through both Terraform
and an equivalent CloudFormation template and diffing the resulting
check IDs (e.g. IAM privilege escalation is `CKV_AWS_286` in Terraform
but `CKV_AWS_110` in CloudFormation). Each CheckovRule below therefore
maps to a `check_ids` dict of `{framework: checkov_check_id}`, not a
single ID — the reverse of TRIVY_RULES' flat 1:1 shape.

Ansible: exposes all of Checkov's built-in task checks except
`CKV_AWS_135` ("EC2 is EBS optimized"), which is a cost/performance
concern (Checkov tags it GENERAL_SECURITY, but it has no confidentiality/
integrity/availability implication for an attacker) — excluded as a
judgment call, not part of the "curate a focused checklist" scope
decision, which was about breadth of *coverage*, not about including a
check with no real security relevance.
"""

from __future__ import annotations

import sys
from pathlib import Path

_common_dir = next(p for p in Path(__file__).resolve().parents if (p / "common").is_dir()) / "common"
sys.path.insert(0, str(_common_dir))
from checkov_wrapper import CheckovRule  # noqa: E402

# CheckovRule moved to common/checkov_wrapper.py at plan 013's
# implementation — 013 is Checkov's second consumer (011 is the
# first), the trigger plan 005 already established for extracting
# shared tool-wrapper logic (see common/checkov_wrapper.py's own
# docstring).


_IAM_PRIVILEGE_REFS = [{"standard": "CWE", "id": "CWE-269"}, {"standard": "OWASP-Top10", "id": "A06:2025"}]
_PUBLIC_EXPOSURE_REFS = [{"standard": "CWE", "id": "CWE-668"}, {"standard": "OWASP-Top10", "id": "A01:2025"}]
_CERT_VALIDATION_REFS = [{"standard": "CWE", "id": "CWE-295"}]
_UNTRUSTED_CODE_REFS = [{"standard": "CWE", "id": "CWE-494"}, {"standard": "OWASP-Top10", "id": "A08:2025"}]

CHECKOV_RULES: list[CheckovRule] = [
    # --- AWS ---
    CheckovRule(
        rule_id="iac.aws-iam-wildcard-actions",
        title="IAM policy grants wildcard (\"*\") actions",
        problem="An IAM policy statement's Action is set to \"*\", granting every possible action rather than the specific ones the principal actually needs.",
        impact="A principal with this policy can perform any AWS API action — including creating new IAM users/roles, exfiltrating data, or destroying infrastructure — far beyond whatever the policy was actually written to permit.",
        recommendation="Enumerate the specific actions the principal needs (e.g. `s3:GetObject`, `s3:PutObject`) instead of \"*\"; use IAM Access Analyzer's policy generation to derive a least-privilege starting point from actual usage.",
        references=_IAM_PRIVILEGE_REFS,
        severity="High",
        confidence=90,
        check_ids={"terraform": "CKV_AWS_63", "cloudformation": "CKV_AWS_63"},
    ),
    CheckovRule(
        rule_id="iac.aws-iam-full-admin-privileges",
        title="IAM policy grants full \"*-*\" administrative privileges",
        problem="An IAM policy statement grants both Action \"*\" and Resource \"*\" together — unrestricted administrative access to the entire AWS account.",
        impact="Equivalent to attaching the AWS-managed AdministratorAccess policy: a principal with this policy can do anything in the account, including modifying IAM itself to grant further access or cover its tracks.",
        recommendation="Replace with a scoped policy naming specific actions and resource ARNs; reserve full-admin policies (if ever needed) for a tightly-controlled break-glass role, not routine workload identities.",
        references=_IAM_PRIVILEGE_REFS,
        severity="Critical",
        confidence=90,
        check_ids={"terraform": "CKV_AWS_62", "cloudformation": "CKV_AWS_62"},
    ),
    CheckovRule(
        rule_id="iac.aws-iam-wildcard-resource",
        title="IAM policy allows wildcard (\"*\") resource for a restrictable action",
        problem="A policy statement uses Resource \"*\" for an action that AWS supports restricting to specific resource ARNs (e.g. a specific bucket or role), granting the action against every matching resource in the account instead of the intended one(s).",
        impact="The principal can act on resources it was never meant to touch — e.g. reading every S3 bucket in the account rather than the one application bucket it needed.",
        recommendation="Scope Resource to the specific ARN(s) the principal actually needs; use ARN wildcards narrowly (e.g. `arn:aws:s3:::my-app-*`) only when a genuinely dynamic set of resources is involved.",
        references=_IAM_PRIVILEGE_REFS,
        severity="High",
        confidence=80,
        check_ids={"terraform": "CKV_AWS_355"},
    ),
    CheckovRule(
        rule_id="iac.aws-iam-privilege-escalation",
        title="IAM policy allows a known privilege-escalation path",
        problem="The policy grants a combination of permissions (e.g. `iam:PassRole` plus `lambda:CreateFunction`, or `iam:CreatePolicyVersion`) that is a documented AWS privilege-escalation technique, letting the principal grant itself more access than the policy author intended.",
        impact="A principal that should have narrowly-scoped access can escalate to broader (potentially full-admin) privileges without any additional external action, bypassing the policy's own intended limits.",
        recommendation="Remove the specific escalation-enabling permission combination; if `iam:PassRole` is required, scope it to specific role ARNs via a Condition, not account-wide.",
        references=_IAM_PRIVILEGE_REFS,
        severity="High",
        confidence=80,
        check_ids={"terraform": "CKV_AWS_286", "cloudformation": "CKV_AWS_110"},
    ),
    CheckovRule(
        rule_id="iac.aws-s3-public-read-acl",
        title="S3 bucket ACL allows public READ access",
        problem="The bucket's ACL grants read access to \"AllUsers\" or \"AuthenticatedUsers\" (any AWS account), making every object in it readable by anyone on the internet.",
        impact="Any data stored in the bucket — which may include application data, backups, or logs — is exposed to public read, a common source of real-world data breaches.",
        recommendation="Remove the public-read ACL grant; use a bucket policy scoped to specific principals if external access is genuinely required, and enable S3 Block Public Access at the bucket or account level.",
        references=_PUBLIC_EXPOSURE_REFS,
        severity="High",
        confidence=90,
        check_ids={"terraform": "CKV_AWS_20", "cloudformation": "CKV_AWS_20"},
    ),
    CheckovRule(
        rule_id="iac.aws-s3-missing-public-access-block",
        title="S3 bucket is missing a Public Access Block configuration",
        problem="The bucket has no `aws_s3_bucket_public_access_block` (Terraform) or equivalent `PublicAccessBlockConfiguration` (CloudFormation) resource restricting public ACLs/policies — the account-level default alone is not guaranteed to cover it.",
        impact="Without this explicit guard, a future ACL or bucket-policy change (accidental or malicious) can make the bucket public with nothing to block it — this check catches the *absence* of a safety net, not necessarily current public exposure.",
        recommendation="Add a Public Access Block configuration blocking public ACLs, public policies, and restricting public buckets, even if the bucket isn't public today.",
        references=_PUBLIC_EXPOSURE_REFS,
        severity="Medium",
        confidence=80,
        check_ids={"terraform": "CKV2_AWS_6", "cloudformation": "CKV_AWS_56"},
    ),
    CheckovRule(
        rule_id="iac.aws-open-ssh-ingress",
        title="Security group allows unrestricted SSH ingress",
        problem="A security group ingress rule allows TCP port 22 from `0.0.0.0/0` — any host on the internet.",
        impact="Any host with an SSH-reachable target behind this security group is exposed to internet-wide brute-force and credential-stuffing attempts against SSH.",
        recommendation="Restrict the source CIDR to specific known ranges (office VPN, bastion host, etc.), or remove direct SSH exposure entirely in favor of SSM Session Manager / a bastion.",
        references=_PUBLIC_EXPOSURE_REFS,
        severity="High",
        confidence=90,
        check_ids={"terraform": "CKV_AWS_24", "cloudformation": "CKV_AWS_24"},
    ),
    # --- Azure ---
    CheckovRule(
        rule_id="iac.azure-custom-owner-role",
        title="Custom role definition grants wildcard actions at subscription/root scope",
        problem="A custom `azurerm_role_definition` grants wildcard (\"*\") actions with an assignable scope of \"/\" (the tenant root or subscription level) — equivalent to a custom Owner role.",
        impact="Any principal assigned this role has unrestricted control over every resource within the assignable scope, the Azure equivalent of AWS's full-admin IAM policy.",
        recommendation="Scope the role's actions to only what's needed, and its assignable_scopes to the specific resource group(s) that actually need it, not the subscription/tenant root.",
        references=_IAM_PRIVILEGE_REFS,
        severity="Critical",
        confidence=85,
        check_ids={"terraform": "CKV_AZURE_39"},
    ),
    CheckovRule(
        rule_id="iac.azure-storage-public-access",
        title="Storage account allows public network access",
        problem="The storage account does not disallow public network access (`allow_nested_items_to_be_public`/network rules default action is not set to deny), leaving it reachable over the public internet.",
        impact="Blob containers, queues, or tables in the account can be exposed publicly if any container-level access setting also permits it — public storage account access is a common source of data exposure incidents.",
        recommendation="Set the storage account's public network access to disabled (or restrict via private endpoints/network rules), and disallow public blob access at the account level.",
        references=_PUBLIC_EXPOSURE_REFS,
        severity="High",
        confidence=85,
        check_ids={"terraform": "CKV_AZURE_59"},
    ),
    CheckovRule(
        rule_id="iac.azure-storage-blob-public-access",
        title="Storage account allows anonymous blob public access",
        problem="The storage account permits anonymous (unauthenticated) public access to blob containers, rather than requiring authenticated access.",
        impact="Any blob in a container configured for public access is readable by anyone with the URL, without any Azure AD credential — a direct data-exposure risk.",
        recommendation="Set `allow_nested_items_to_be_public = false` on the storage account so no container can be configured for anonymous public access, regardless of its own container-level setting.",
        references=_PUBLIC_EXPOSURE_REFS,
        severity="High",
        confidence=85,
        check_ids={"terraform": "CKV_AZURE_190"},
    ),
    CheckovRule(
        rule_id="iac.azure-open-ssh-nsg",
        title="Network Security Group rule allows unrestricted SSH ingress",
        problem="An NSG rule allows inbound TCP port 22 from any source address (`*` or `0.0.0.0/0`).",
        impact="Any VM behind this NSG is exposed to internet-wide brute-force and credential-stuffing attempts against SSH.",
        recommendation="Restrict the source address prefix to specific known ranges, or remove direct SSH exposure in favor of Azure Bastion / just-in-time VM access.",
        references=_PUBLIC_EXPOSURE_REFS,
        severity="High",
        confidence=90,
        check_ids={"terraform": "CKV_AZURE_10"},
    ),
    # --- GCP ---
    CheckovRule(
        rule_id="iac.gcp-project-basic-role",
        title="Basic role (Owner/Editor/Viewer) granted at the project level",
        problem="A project-level IAM binding grants one of GCP's coarse-grained \"basic\" roles (`roles/owner`, `roles/editor`, or `roles/viewer`) rather than a predefined or custom role scoped to what the principal actually needs.",
        impact="Basic roles grant sweeping, cross-service permissions — `roles/owner` in particular includes the ability to modify IAM itself — far beyond what almost any real workload or user needs, and are Google's own explicitly-discouraged legacy role tier.",
        recommendation="Replace with predefined roles scoped to the specific services/actions needed (e.g. `roles/storage.objectViewer` instead of `roles/viewer`), or a custom role for a precise fit.",
        references=_IAM_PRIVILEGE_REFS,
        severity="High",
        confidence=85,
        check_ids={"terraform": "CKV_GCP_117"},
    ),
    CheckovRule(
        rule_id="iac.gcp-project-iam-service-account-impersonation",
        title="Project-level IAM role allows impersonating or managing service accounts",
        problem="A project-level IAM binding grants a role that can create service account keys or impersonate service accounts (e.g. `roles/iam.serviceAccountTokenCreator`, `roles/iam.serviceAccountKeyAdmin`) at the project level rather than scoped to specific service accounts.",
        impact="The principal can obtain the identity of any service account in the project, including ones with far broader permissions than the principal itself was granted — a project-wide privilege-escalation path.",
        recommendation="Scope service-account-impersonation roles to specific service account resources (`google_service_account_iam_member` on the individual SA), not project-wide.",
        references=_IAM_PRIVILEGE_REFS,
        severity="High",
        confidence=80,
        check_ids={"terraform": "CKV_GCP_49"},
    ),
    CheckovRule(
        rule_id="iac.gcp-storage-public-access",
        title="Cloud Storage bucket is publicly or anonymously accessible",
        problem="A bucket IAM binding/member grants access to `allUsers` or `allAuthenticatedUsers`, making the bucket's contents accessible without any Google-account-specific authorization.",
        impact="Any data in the bucket is exposed to the public internet (or to any Google account holder, for `allAuthenticatedUsers`) — a direct data-exposure risk, and the exact GCP misconfiguration this plan's kickoff found completely undetected by Trivy.",
        recommendation="Remove `allUsers`/`allAuthenticatedUsers` bindings; grant access to specific principals (users, groups, or service accounts) instead.",
        references=_PUBLIC_EXPOSURE_REFS,
        severity="Critical",
        confidence=90,
        check_ids={"terraform": "CKV_GCP_28"},
    ),
    CheckovRule(
        rule_id="iac.gcp-storage-missing-public-access-prevention",
        title="Cloud Storage bucket does not enforce public access prevention",
        problem="The bucket does not set `public_access_prevention = \"enforced\"`, so a future IAM binding change (accidental or malicious) could make it public with nothing to block it.",
        impact="Like the AWS S3 Public Access Block absence, this check catches the *absence* of a safety net, not necessarily current public exposure — but leaves the bucket one misconfigured binding away from public exposure.",
        recommendation="Set `public_access_prevention = \"enforced\"` on the bucket even if it isn't public today.",
        references=_PUBLIC_EXPOSURE_REFS,
        severity="Medium",
        confidence=80,
        check_ids={"terraform": "CKV_GCP_114"},
    ),
    CheckovRule(
        rule_id="iac.gcp-open-ssh-firewall",
        title="Firewall rule allows unrestricted SSH ingress",
        problem="A `google_compute_firewall` allow rule permits TCP port 22 from `0.0.0.0/0` — any host on the internet.",
        impact="Any instance matching this firewall rule's target is exposed to internet-wide brute-force and credential-stuffing attempts against SSH.",
        recommendation="Restrict `source_ranges` to specific known ranges (Identity-Aware Proxy range, office VPN, etc.), or use IAP TCP forwarding instead of direct SSH exposure.",
        references=_PUBLIC_EXPOSURE_REFS,
        severity="High",
        confidence=90,
        check_ids={"terraform": "CKV_GCP_2"},
    ),
    # --- Ansible ---
    CheckovRule(
        rule_id="iac.ansible-uri-cert-validation-disabled",
        title="Ansible `uri` task disables certificate validation",
        problem="A `uri` task sets `validate_certs: false`, disabling TLS certificate validation for the HTTP(S) request it makes.",
        impact="A machine-in-the-middle can intercept and tamper with the request/response undetected, since the playbook will trust any certificate (or none) presented.",
        recommendation="Remove `validate_certs: false` (the module defaults to validating); if a genuinely internal self-signed CA is in play, add its CA cert to the trust store instead of disabling validation entirely.",
        references=_CERT_VALIDATION_REFS,
        severity="Medium",
        confidence=90,
        check_ids={"ansible": "CKV_ANSIBLE_1"},
    ),
    CheckovRule(
        rule_id="iac.ansible-get-url-cert-validation-disabled",
        title="Ansible `get_url` task disables certificate validation",
        problem="A `get_url` task sets `validate_certs: false`, disabling TLS certificate validation for the file it downloads.",
        impact="A machine-in-the-middle can substitute the downloaded file with a malicious one undetected, since the playbook will trust any certificate (or none) presented.",
        recommendation="Remove `validate_certs: false`; add an internal CA to the trust store instead of disabling validation if needed.",
        references=_CERT_VALIDATION_REFS,
        severity="Medium",
        confidence=90,
        check_ids={"ansible": "CKV_ANSIBLE_2"},
    ),
    CheckovRule(
        rule_id="iac.ansible-yum-cert-validation-disabled",
        title="Ansible `yum` task disables certificate validation",
        problem="A `yum` task sets `validate_certs: false` (or equivalent), disabling TLS certificate validation for the repository it fetches packages from.",
        impact="A machine-in-the-middle on the package-repository connection can substitute malicious packages undetected.",
        recommendation="Remove the certificate-validation override; configure the internal repository's CA in the system trust store instead.",
        references=_CERT_VALIDATION_REFS,
        severity="Medium",
        confidence=85,
        check_ids={"ansible": "CKV_ANSIBLE_3"},
    ),
    CheckovRule(
        rule_id="iac.ansible-yum-ssl-validation-disabled",
        title="Ansible `yum` task disables SSL validation",
        problem="A `yum` task sets `sslverify: false` (or equivalent), disabling SSL/TLS validation for the repository connection.",
        impact="A machine-in-the-middle on the package-repository connection can substitute malicious packages undetected.",
        recommendation="Remove the SSL-verification override; configure the internal repository's CA in the system trust store instead.",
        references=_CERT_VALIDATION_REFS,
        severity="Medium",
        confidence=85,
        check_ids={"ansible": "CKV_ANSIBLE_4"},
    ),
    CheckovRule(
        rule_id="iac.ansible-apt-unauthenticated-packages",
        title="Ansible `apt` task allows unauthenticated packages",
        problem="An `apt` task sets `allow_unauthenticated: true`, permitting installation of packages whose GPG signature couldn't be verified.",
        impact="A compromised or spoofed package mirror can serve tampered packages that will be installed and executed without any signature check catching it — a direct supply-chain compromise path.",
        recommendation="Remove `allow_unauthenticated: true`; ensure the package repository's signing key is properly configured instead of bypassing verification.",
        references=_UNTRUSTED_CODE_REFS,
        severity="High",
        confidence=90,
        check_ids={"ansible": "CKV_ANSIBLE_5"},
    ),
    CheckovRule(
        rule_id="iac.ansible-apt-force-downgrade",
        title="Ansible `apt` task uses `force`, bypassing signature validation",
        problem="An `apt` task sets `force: true`, which (per Ansible's own documentation) disables signature validation and permits package downgrades that can leave the system in a broken or inconsistent state.",
        impact="Combines the same signature-bypass risk as `allow_unauthenticated` with the added risk of silently downgrading packages to older, potentially vulnerable versions.",
        recommendation="Remove `force: true`; resolve the underlying dependency conflict explicitly (e.g. pin specific versions) instead of forcing past it.",
        references=_UNTRUSTED_CODE_REFS,
        severity="Medium",
        confidence=85,
        check_ids={"ansible": "CKV_ANSIBLE_6"},
    ),
    CheckovRule(
        rule_id="iac.ansible-ec2-public-ip",
        title="Ansible-provisioned EC2 instance is assigned a public IP",
        problem="An `ec2_instance` task does not disable public IP assignment, so the instance will receive a public IP address on creation.",
        impact="The instance becomes directly reachable from the internet on whatever ports its security groups permit, widening the attack surface compared to a private-subnet-only instance behind a load balancer or bastion.",
        recommendation="Set the network interface's public-IP assignment to disabled for instances that don't need direct internet exposure; use a NAT gateway/load balancer for outbound/inbound needs instead.",
        references=_PUBLIC_EXPOSURE_REFS,
        severity="Medium",
        confidence=75,
        check_ids={"ansible": "CKV_AWS_88"},
    ),
]
