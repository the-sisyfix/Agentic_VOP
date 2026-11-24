"""Finding -> Remediation Family classifier.

Deterministic rule-based mapping of an issue row to one of the 5 families in
the Phase-1 Remediation Pattern Library (migration 0036). Sub-Agent 3 calls
this BEFORE the LLM to look up the right pattern template.

Rules are intentionally simple and ordered so the most specific signal wins
first. For findings outside the Phase-1 scope, returns 'unknown' — the caller
should either skip or fall back to a generic prompt.

Families (keys in remediation_patterns):
  public_exposure        — Cloud data stores, IAM, audit (S3, RDS, DynamoDB, IAM, KMS, ...)
  network_exposure       — Network primitives (Security Groups, LBs, VPCs, Route53, ...)
  injection              — SAST/DAST + code-execution surfaces (Lambda, API Gateway, ECS, ...)
  vulnerable_dependency  — SCA findings (Snyk, Dependabot, OSV, Trivy, Grype app pkgs)
  os_vulnerability       — Host scanners + Grype OS packages (apk/deb/rpm) + EC2/EBS hardening

Classification signals (in priority order):
  1. Checkov + raw.resource prefix (deterministic AWS resource → family map)
  2. Source slug (snyk, qualys, sonarqube, etc. — already unambiguous)
  3. Grype purl ecosystem
  4. CWE id for injection
  5. Title keyword fallback
"""

from __future__ import annotations


Family = str  # one of the 5 above + 'unknown'


# =============================================================================
# Checkov (and other IaC scanners) resource-prefix → family map.
#
# Matches by longest-prefix. Reads raw_findings.raw["resource"] which Checkov
# emits as an unambiguous Terraform resource address like "aws_s3_bucket.foo"
# or "aws_security_group.bar". Add new prefixes as new AWS resources appear
# in Checkov findings — one-line change per resource.
#
# Rationale for each bucketing:
#   public_exposure   → data stores, IAM/access control, audit trails, secrets
#   network_exposure  → anything that shapes reachability at network layer
#   injection         → serverless / container compute (code execution surfaces)
#   os_vulnerability  → EC2 hardening, EBS/AMI/launch config
# =============================================================================
_CHECKOV_RESOURCE_FAMILY: dict[str, Family] = {
    # ---- public_exposure ----
    "aws_s3_bucket": "public_exposure",
    "aws_s3_object": "public_exposure",
    "aws_rds_": "public_exposure",
    "aws_db_instance": "public_exposure",
    "aws_db_cluster": "public_exposure",
    "aws_dynamodb_": "public_exposure",
    "aws_iam_": "public_exposure",
    "aws_cloudtrail": "public_exposure",
    "aws_config_": "public_exposure",
    "aws_kms_": "public_exposure",
    "aws_secretsmanager_": "public_exposure",
    "aws_efs_": "public_exposure",
    "aws_elasticsearch_": "public_exposure",
    "aws_opensearch_": "public_exposure",
    "aws_redshift_": "public_exposure",
    "aws_kinesis_": "public_exposure",
    "aws_sns_": "public_exposure",
    "aws_sqs_": "public_exposure",
    "aws_glacier_": "public_exposure",
    "aws_backup_": "public_exposure",
    # ---- network_exposure ----
    "aws_security_group": "network_exposure",
    "aws_default_security_group": "network_exposure",
    "aws_lb": "network_exposure",
    "aws_alb": "network_exposure",
    "aws_elb": "network_exposure",
    "aws_lb_listener": "network_exposure",
    "aws_route53_": "network_exposure",
    "aws_vpc": "network_exposure",
    "aws_network_acl": "network_exposure",
    "aws_network_interface": "network_exposure",
    "aws_subnet": "network_exposure",
    "aws_route_table": "network_exposure",
    "aws_route": "network_exposure",
    "aws_internet_gateway": "network_exposure",
    "aws_nat_gateway": "network_exposure",
    "aws_vpn_": "network_exposure",
    "aws_cloudfront_": "network_exposure",
    "aws_apigatewayv2_stage": "network_exposure",
    # ---- injection (code execution surfaces) ----
    "aws_lambda_": "injection",
    "aws_api_gateway_": "injection",
    "aws_apigatewayv2_api": "injection",
    "aws_ecs_": "injection",
    "aws_eks_": "injection",
    "aws_ecr_": "injection",
    "aws_codebuild_": "injection",
    # ---- os_vulnerability (compute hardening) ----
    "aws_instance": "os_vulnerability",
    "aws_ebs_": "os_vulnerability",
    "aws_ami": "os_vulnerability",
    "aws_launch_": "os_vulnerability",
    "aws_autoscaling_": "os_vulnerability",
    "aws_ssm_": "os_vulnerability",
}


def _classify_by_checkov_resource(resource: str | None) -> Family:
    """Longest-prefix match against `_CHECKOV_RESOURCE_FAMILY`. Returns 'unknown'
    on no match (caller decides the fallback)."""
    if not resource:
        return "unknown"
    r = resource.lower()
    # Strip Terraform resource address suffix ".name" so we match the type.
    r_type = r.split(".", 1)[0] if "." in r else r
    # Try longest prefix first so `aws_security_group_rule` matches
    # 'aws_security_group' before 'aws_'.
    for prefix in sorted(_CHECKOV_RESOURCE_FAMILY, key=len, reverse=True):
        if r_type.startswith(prefix):
            return _CHECKOV_RESOURCE_FAMILY[prefix]
    return "unknown"


# =============================================================================
# Deployment-tier suffixes stripped before source matching. Lets one rule
# handle both `snyk-appsec` and `snyk-appsec-ec2`, both `trivy-fs` and
# `trivy-fs-ec2`, etc. Add new suffixes here (never new rules elsewhere).
# =============================================================================
_SOURCE_SUFFIXES = ("-ec2", "-on-prem", "-onprem", "-cloud", "-cspm", "-saas")


def _canonical_source(source: str) -> str:
    """Strip deployment-tier suffixes so the classifier is oblivious to how
    the scanner was deployed. `trivy-fs-ec2` and `trivy-fs` both canonicalize
    to `trivy-fs`, hitting the same rule."""
    s = source.lower()
    for suffix in _SOURCE_SUFFIXES:
        if s.endswith(suffix):
            return s[: -len(suffix)]
    return s


# Purl ecosystems that indicate OS-level packages (base image / host).
_OS_PURL_PREFIXES = ("pkg:apk", "pkg:deb", "pkg:rpm")
# Purl ecosystems that indicate application-level packages.
_APP_PURL_PREFIXES = (
    "pkg:npm",
    "pkg:pypi",
    "pkg:maven",
    "pkg:gem",
    "pkg:cargo",
    "pkg:nuget",
    "pkg:golang",
    "pkg:go",
    "pkg:composer",
)


def _classify_by_purl(purl: str, default: Family) -> Family:
    """Split a hybrid scanner's finding by purl ecosystem. `default` used when
    purl is empty or unrecognized (e.g. Grype's fallback = os_vulnerability)."""
    if purl.startswith(_OS_PURL_PREFIXES):
        return "os_vulnerability"
    if purl.startswith(_APP_PURL_PREFIXES):
        return "vulnerable_dependency"
    return default


# =============================================================================
# CWE → family maps. These are authoritative vulnerability-type categorizations
# (MITRE), independent of any scanner. When a finding's cwe_id is in one of
# these sets, the family is decided.
# =============================================================================
_INJECTION_CWES = {
    "CWE-89",  # SQL Injection
    "CWE-78",  # OS Command Injection
    "CWE-94",  # Code Injection
    "CWE-95",  # eval Injection
    "CWE-77",  # Generic Command Injection
    "CWE-90",  # LDAP Injection
    "CWE-91",  # XML Injection
    "CWE-79",  # XSS
    "CWE-74",  # Generic Injection
    "CWE-98",  # PHP Remote File Inclusion
    "CWE-611",  # XML External Entity
}
_ACCESS_CONTROL_CWES = {
    "CWE-284",  # Improper Access Control
    "CWE-287",  # Improper Authentication
    "CWE-732",  # Incorrect Permission Assignment
    "CWE-306",  # Missing Auth for Critical Function
    "CWE-522",  # Insufficiently Protected Credentials
    "CWE-798",  # Hard-coded Credentials
    "CWE-269",  # Improper Privilege Management
    "CWE-863",  # Incorrect Authorization
    "CWE-359",  # PII Exposure
    "CWE-200",  # Info Exposure
    "CWE-201",  # Info Exposure Through Send Data
    "CWE-311",  # Missing Encryption of Sensitive Data
    "CWE-312",  # Cleartext Storage of Sensitive Info
    "CWE-319",  # Cleartext Transmission
    "CWE-326",  # Inadequate Encryption Strength
}
_NETWORK_EXPOSURE_CWES = {
    "CWE-1188",  # Insecure Default Init of Resource
    "CWE-16",  # Configuration
    "CWE-923",  # Improper Restriction of Communication Channel
    "CWE-940",  # Improper Verification of Source of Message
}


def _classify_by_cwe(cwe: str) -> Family:
    """Return family for CWE-based classification, or 'unknown' if no match."""
    if cwe in _INJECTION_CWES:
        return "injection"
    if cwe in _ACCESS_CONTROL_CWES:
        return "public_exposure"
    if cwe in _NETWORK_EXPOSURE_CWES:
        return "network_exposure"
    return "unknown"


# =============================================================================
# Source hint map — used ONLY as fallback when no data signal fires.
# Not a rule table. Just: "if we can't tell from the data, what does this
# scanner USUALLY find?". Add entries; they only kick in for ambiguous rows.
# =============================================================================
_SOURCE_HINT: dict[str, Family] = {
    # SCA scanners typically emit package findings — hint = vulnerable_dependency
    "snyk-appsec": "vulnerable_dependency",
    "snyk": "vulnerable_dependency",
    "dependabot": "vulnerable_dependency",
    "osv": "vulnerable_dependency",
    "trivy-fs": "vulnerable_dependency",
    # trivy-image findings are OS packages inside a container image. Fix
    # shape is "rebuild image with updated base pkgs", which aligns with
    # os_vulnerability strategy per SA-4 design doc (not manifest-edit).
    "trivy-image": "os_vulnerability",
    "trivy-cloud": "vulnerable_dependency",
    "trivy-config": "vulnerable_dependency",
    # Host/VM scanners — hint = os_vulnerability
    "tenable-nessus-vuln": "os_vulnerability",
    "tenable": "os_vulnerability",
    "qualys-vmdr-vuln": "os_vulnerability",
    "qualys": "os_vulnerability",
    "rapid7": "os_vulnerability",
    "grype": "os_vulnerability",
    "trivy-os": "os_vulnerability",
    # SAST/DAST — hint = injection
    "sonarqube-appsec": "injection",
    "sonarqube": "injection",
    "semgrep-appsec": "injection",
    "semgrep": "injection",
    "serverless": "injection",  # Semgrep-run rules over Lambda source; -ec2 suffix stripped by _canonical_source
    "burp-suite": "injection",
    "burp": "injection",
    "zap": "injection",
    "owasp-zap": "injection",
    # IaC / CSPM — hint = public_exposure (most misconfigs are access-control)
    "checkov": "public_exposure",
    "wiz": "public_exposure",
    "prisma-cloud": "public_exposure",
}


def classify_finding(issue: dict, raw: dict | None = None) -> Family:
    """Map an issue row to its remediation family. Pure function, no I/O.

    Classification is **data-first** — we look at what's actually inside the
    finding (purl, raw.resource, cwe, asset_identity) rather than the scanner
    name. Source name is only a fallback hint for rows where no data signal
    fires. This makes the classifier robust to new scanners + naming variants
    (`-ec2`, `-cspm`, `-cloud`, etc.) without adding rules.

    Priority (most authoritative first):
      1. Purl ecosystem (definitive for package findings)
      2. Raw cloud resource type (definitive for IaC/CSPM findings)
      3. CWE category (authoritative MITRE mapping)
      4. Data-shape signals (has package? has hostname+cve? etc.)
      5. Title keywords (last-resort semantic hint)
      6. Source hint (fallback when data is insufficient)
    """
    source = _canonical_source((issue.get("source") or "").lower())
    title = (issue.get("title") or "").lower()
    cwe = (issue.get("cwe_id") or "").upper()
    purl = (issue.get("runtime_purl") or "").lower()
    identity = issue.get("asset_identity") or {}
    package = issue.get("package")
    cve_id = issue.get("cve_id")

    # =========================================================================
    # 0. Source-hint override for OS-package scanners
    # =========================================================================
    # OS-level scanners (Trivy Image/OS, host scanners) emit findings with a
    # `package` field. Without this override, data-shape rule 4a below would
    # see the package field and misroute them to vulnerable_dependency (which
    # points at the wrong SA-4 strategy — dependency-manifest edits, not
    # apt/docker rebuild). The fix shape for these is always os_vulnerability:
    #   - trivy-image → rebuild container with updated base pkgs
    #   - trivy-os / trivy-os-al2 / tenable / qualys → apt/yum upgrade on host
    if source in (
        "trivy-image",
        "trivy-image-php",
        "trivy-os",
        "trivy-os-al2",
        "snyk-container",
        "grype-image",
        "tenable-nessus-vuln",
        "qualys-vmdr-vuln",
        "rapid7",
    ) or source.startswith("trivy-os"):
        return "os_vulnerability"

    # =========================================================================
    # 1. Purl ecosystem — deterministic when present
    # =========================================================================
    if purl.startswith(_OS_PURL_PREFIXES):
        return "os_vulnerability"
    if purl.startswith(_APP_PURL_PREFIXES):
        return "vulnerable_dependency"

    # =========================================================================
    # 2. Raw cloud resource — deterministic for IaC/CSPM findings
    # =========================================================================
    if raw:
        resource = (
            raw.get("resource")
            or raw.get("Resource")
            or raw.get("resourceType")
            or raw.get("resource_type")
        )
        if resource:
            fam = _classify_by_checkov_resource(resource)
            if fam != "unknown":
                return fam

    # =========================================================================
    # 3. CWE category — authoritative MITRE classification
    # =========================================================================
    if cwe:
        fam = _classify_by_cwe(cwe)
        if fam != "unknown":
            return fam

    # =========================================================================
    # 4. Data-shape signals — infer family from what fields the issue has
    # =========================================================================
    # 4a. Package finding with no purl (Trivy sometimes normalizes without purl):
    #     if the row carries a package object, it's a dependency finding.
    if package or identity.get("package") or identity.get("package_name"):
        return "vulnerable_dependency"

    # 4b. Host-level finding (hostname/ip + CVE) → OS vulnerability
    has_host = bool(identity.get("hostname") or identity.get("ipv4") or identity.get("host"))
    if has_host and cve_id:
        return "os_vulnerability"

    # 4c. Network primitive without a CVE → network config exposure
    #     (open port on a host without a specific CVE is a config issue)
    if has_host and identity.get("port"):
        return "network_exposure"

    # 4d. File-based finding (SAST) → injection (default for code-scan findings)
    if identity.get("file") or identity.get("file_path") or identity.get("path"):
        # Only classify as injection here if we don't hit source hint later
        # for something better — but a code file finding is most likely injection.
        # We'll fall through to hint if it exists.
        pass

    # =========================================================================
    # 5. Title keywords — semantic last resort
    # =========================================================================
    if any(
        kw in title
        for kw in (
            "sql injection",
            "command injection",
            "code injection",
            "ldap injection",
            "xml injection",
            "template injection",
            "xss",
            "cross-site scripting",
            "cross site scripting",
        )
    ):
        return "injection"

    if ("public" in title) and any(
        kw in title for kw in ("s3", "bucket", "storage", "blob", "acl")
    ):
        return "public_exposure"

    if "0.0.0.0/0" in title or "security group" in title or "open port" in title:
        return "network_exposure"

    # =========================================================================
    # 6. Source hint — fallback for genuinely ambiguous rows
    # =========================================================================
    if source in _SOURCE_HINT:
        return _SOURCE_HINT[source]

    # Also try prefix match on source hint (catches "sonarqube-something",
    # "snyk-new-tier", etc.) — pick the longest matching prefix key.
    matching = [k for k in _SOURCE_HINT if source.startswith(k)]
    if matching:
        return _SOURCE_HINT[max(matching, key=len)]

    return "unknown"
