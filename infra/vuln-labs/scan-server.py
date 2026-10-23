"""HTTP server that serves pre-computed scan results.

Architecture:
  - Scans run ONCE at startup (or on POST /trigger-scan)
  - Results are cached to /opt/vuln-labs/results/
  - GET /scan/* endpoints return cached results instantly
  - VOP fetches pre-computed results, never triggers a scan

Endpoints:
  GET  /health                  — liveness check
  GET  /scan/checkov            — returns cached Checkov CSPM results
  GET  /scan/semgrep            — returns cached Semgrep SAST results
  GET  /scan/trivy-fs           — returns cached Trivy FS SCA results
  GET  /scan/trivy-image/infra  — returns cached Trivy image results (Ubuntu/OpenSSL)
  GET  /scan/trivy-image/java   — returns cached Trivy image results (Tomcat/JDK)
  GET  /scan/trivy-image/python — returns cached Trivy image results (Python/pip)
  GET  /scan/trivy-image/php    — returns cached Trivy image results (Debian php8.2 OS pkgs)
  GET  /scan/trivy-os           — returns cached Trivy OS results (host rootfs)
  GET  /scan/serverless         — returns cached Semgrep serverless results (Lambda IaC + code)
  POST /trigger-scan            — re-runs all scanners and updates cache
  GET  /scan-status             — shows when each scan was last run
"""

import json
import os
import subprocess
import time
import threading
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

CSPM_PATH = os.environ.get("VULN_LABS_CSPM_PATH", "/opt/vuln-labs/cspm-lab/")
SAST_PATH = os.environ.get("VULN_LABS_SAST_PATH", "/opt/vuln-labs/appsec-lab/")
SCA_PATH = os.environ.get("VULN_LABS_SCA_PATH", "/opt/vuln-labs/appsec-lab/")
SERVERLESS_PATH = os.environ.get(
    "VULN_LABS_SERVERLESS_PATH", "/opt/vuln-labs/serverless-lab/"
)
INFRA_IMAGE = os.environ.get("VULN_LABS_INFRA_IMAGE", "vuln-lab-image:latest")
JAVA_IMAGE = os.environ.get("VULN_LABS_JAVA_IMAGE", "vuln-java-image:latest")
PYTHON_IMAGE = os.environ.get("VULN_LABS_PYTHON_IMAGE", "vuln-python-image:latest")
PHP_IMAGE = os.environ.get("VULN_LABS_PHP_IMAGE", "vuln-php-image:latest")
RESULTS_DIR = os.environ.get("VULN_LABS_RESULTS_DIR", "/opt/vuln-labs/results/")

# Track when each scan was last run
scan_timestamps = {}
scan_lock = threading.Lock()


def ensure_results_dir():
    os.makedirs(RESULTS_DIR, exist_ok=True)


def run_checkov():
    """Run Checkov and cache only the 3 key findings (1 per resource type)."""
    TARGET_CHECKS = {
        "CKV_AWS_24",  # Security Group: SSH open to 0.0.0.0/0
        "CKV_AWS_145",  # S3 Bucket: No KMS encryption
        "CKV_AWS_63",  # IAM: Policy allows * actions
    }
    try:
        result = subprocess.run(
            ["checkov", "-d", CSPM_PATH, "--output", "json", "--quiet", "--compact"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        output = result.stdout or result.stderr
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            data = {"raw_output": output[:5000]}

        findings = []
        checks = data if isinstance(data, list) else [data]
        for check_group in checks:
            if not isinstance(check_group, dict):
                continue
            results = check_group.get("results", {})
            failed = results.get("failed_checks", [])
            for f in failed:
                findings.append(
                    {
                        "check_id": f.get("check_id"),
                        "check_name": f.get("check_name") or f.get("check_id"),
                        "severity": f.get("severity") or "MEDIUM",
                        "resource": f.get("resource"),
                        "file_path": f.get("file_path"),
                        "file_line_range": f.get("file_line_range"),
                        "guideline": f.get("guideline"),
                        "check_type": check_group.get("check_type", "terraform"),
                    }
                )

        result_data = {
            "findings": findings,
            "total": len(findings),
            "scanned_at": datetime.utcnow().isoformat(),
        }
        with open(os.path.join(RESULTS_DIR, "checkov.json"), "w") as f:
            json.dump(result_data, f)
        scan_timestamps["checkov"] = datetime.utcnow().isoformat()
        print(f"[scan] Checkov complete: {len(findings)} findings")
    except Exception as e:
        print(f"[scan] Checkov failed: {e}")


def run_semgrep():
    """Run Semgrep against the SAST lab and cache results."""
    if not os.path.isdir(SAST_PATH):
        print(f"[scan] Semgrep SKIPPED — SAST lab path does not exist: {SAST_PATH}")
        error_data = {
            "findings": [],
            "total": 0,
            "error": f"SAST path missing: {SAST_PATH}",
            "scanned_at": datetime.utcnow().isoformat(),
        }
        with open(os.path.join(RESULTS_DIR, "semgrep.json"), "w") as f:
            json.dump(error_data, f)
        scan_timestamps["semgrep"] = datetime.utcnow().isoformat()
        return

    # Log what files exist in the SAST path for debugging
    try:
        sast_files = os.listdir(SAST_PATH)
        print(f"[scan] SAST lab contents: {sast_files}")
    except Exception as e:
        print(f"[scan] Cannot list SAST path: {e}")

    try:
        # Write a local rules file to avoid dependency on Semgrep registry
        rules_file = os.path.join(RESULTS_DIR, "semgrep-rules.yaml")
        with open(rules_file, "w") as rf:
            rf.write("""rules:
  # --- SQL Injection (CWE-89) ---
  - id: sql-injection-format-string
    patterns:
      - pattern-either:
          - pattern: $CONN.execute(f"...{$VAR}...")
          - pattern: $CONN.execute("..." + $VAR + "...")
    message: >
      SQL injection via string formatting. Use parameterized queries instead.
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ["CWE-89"]
      owasp: ["A03:2021 - Injection"]
      confidence: HIGH

  - id: sql-injection-fstring-variable
    patterns:
      - pattern-either:
          - pattern: |
              $QUERY = f"...{$VAR}..."
              ...
              $CURSOR = $CONN.execute($QUERY)
          - pattern: |
              $QUERY = "..." + $VAR + "..."
              ...
              $CURSOR = $CONN.execute($QUERY)
    message: >
      SQL injection via string formatting in variable. Use parameterized queries.
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ["CWE-89"]
      owasp: ["A03:2021 - Injection"]
      confidence: HIGH

  # --- XSS / Reflected Input (CWE-79) ---
  - id: xss-render-template-string
    patterns:
      - pattern-either:
          - pattern: render_template_string("..." + $VAR + "...")
          - pattern: render_template_string(f"...{$VAR}...")
    message: >
      XSS via unsanitized user input in render_template_string. Escape user input.
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ["CWE-79"]
      owasp: ["A03:2021 - Injection"]
      confidence: HIGH

  - id: xss-formatted-html-response
    pattern: |
      $HTML = f"...{$VAR}..."
      ...
      return render_template_string($HTML)
    message: >
      XSS via user input embedded in HTML string passed to render_template_string.
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ["CWE-79"]
      owasp: ["A03:2021 - Injection"]
      confidence: HIGH

  # --- Flask Debug Mode (CWE-489) ---
  - id: flask-debug-enabled
    pattern: $APP.run(..., debug=True, ...)
    message: Flask debug mode enabled in production.
    languages: [python]
    severity: WARNING
    metadata:
      cwe: ["CWE-489"]
      owasp: ["A05:2021 - Security Misconfiguration"]

  # --- Hardcoded Secrets (CWE-798) ---
  - id: hardcoded-secret-key
    patterns:
      - pattern-either:
          - pattern: SECRET_KEY = "..."
          - pattern: API_TOKEN = "..."
          - pattern: DB_PASSWORD = "..."
          - pattern: AWS_ACCESS_KEY_ID = "..."
          - pattern: AWS_SECRET_ACCESS_KEY = "..."
    message: >
      Hardcoded credential or secret in source code. Use environment variables.
    languages: [python]
    severity: WARNING
    metadata:
      cwe: ["CWE-798"]
      owasp: ["A07:2021 - Identification and Authentication Failures"]

  # --- Weak Hashing (CWE-328) ---
  - id: weak-hash-md5
    pattern: hashlib.md5(...)
    message: >
      Weak hash algorithm MD5 used. Use SHA-256 or bcrypt for password hashing.
    languages: [python]
    severity: WARNING
    metadata:
      cwe: ["CWE-328"]
      owasp: ["A02:2021 - Cryptographic Failures"]

  - id: weak-hash-sha1
    pattern: hashlib.sha1(...)
    message: >
      Weak hash algorithm SHA1 used. Use SHA-256 or stronger for security tokens.
    languages: [python]
    severity: WARNING
    metadata:
      cwe: ["CWE-328"]
      owasp: ["A02:2021 - Cryptographic Failures"]

  # --- Path Traversal (CWE-22) ---
  - id: path-traversal-open
    patterns:
      - pattern-either:
          - pattern: open(os.path.join($DIR, $USERINPUT), ...)
          - pattern: send_file(open(os.path.join($DIR, $USERINPUT), ...), ...)
    message: >
      Path traversal — user-controlled filename passed to os.path.join + open.
      Validate that the resolved path stays within the intended directory.
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ["CWE-22"]
      owasp: ["A01:2021 - Broken Access Control"]

  # --- Unrestricted File Upload (CWE-434) ---
  - id: unrestricted-file-upload
    pattern: $FILE.save(os.path.join($DIR, $FILE.filename))
    message: >
      Unrestricted file upload — file saved with user-supplied filename without
      extension or content-type validation.
    languages: [python]
    severity: WARNING
    metadata:
      cwe: ["CWE-434"]
      owasp: ["A04:2021 - Insecure Design"]

  # --- SSRF (CWE-918) ---
  - id: ssrf-requests-get
    pattern: requests.get($URL)
    message: >
      SSRF — user-controlled URL passed to requests.get. Validate against an allowlist.
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ["CWE-918"]
      owasp: ["A10:2021 - Server-Side Request Forgery"]

  - id: ssrf-urllib-urlopen
    pattern: urllib.request.urlopen($URL)
    message: >
      SSRF — user-controlled URL passed to urllib.request.urlopen.
      Validate against an allowlist.
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ["CWE-918"]
      owasp: ["A10:2021 - Server-Side Request Forgery"]

  # --- Command Injection (CWE-78) ---
  - id: command-injection-os-system
    pattern: os.system("..." + $VAR)
    message: >
      Command injection via os.system with concatenated user input.
      Use subprocess with a list of arguments instead.
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ["CWE-78"]
      owasp: ["A03:2021 - Injection"]
      confidence: HIGH

  - id: command-injection-subprocess-shell
    pattern: subprocess.run($CMD, shell=True, ...)
    message: >
      Command injection risk — subprocess.run with shell=True.
      Use shell=False and pass arguments as a list.
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ["CWE-78"]
      owasp: ["A03:2021 - Injection"]

  # --- Insecure Deserialization (CWE-502) ---
  - id: insecure-deserialization-pickle
    pattern: pickle.loads(...)
    message: >
      Insecure deserialization — pickle.loads on potentially untrusted data.
      Use json.loads or a safe serialization format.
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ["CWE-502"]
      owasp: ["A08:2021 - Software and Data Integrity Failures"]

  # --- Weak Random (CWE-330) ---
  - id: weak-random-token
    pattern: random.randint(...)
    message: >
      Weak randomness — random.randint used for security-sensitive token.
      Use secrets.token_hex() or secrets.randbelow() instead.
    languages: [python]
    severity: WARNING
    metadata:
      cwe: ["CWE-330"]
      owasp: ["A02:2021 - Cryptographic Failures"]

  # --- Dangerous Eval (CWE-95) ---
  - id: dangerous-eval
    pattern: eval($EXPR)
    message: >
      Dangerous eval() on potentially untrusted input. Use ast.literal_eval()
      for safe expression evaluation.
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ["CWE-95"]
      owasp: ["A03:2021 - Injection"]
""")

        # Use local rules + memory limits for small EC2 instances
        result = subprocess.run(
            [
                "semgrep",
                "scan",
                "--config",
                rules_file,
                SAST_PATH,
                "--json",
                "--no-git-ignore",
                "--timeout",
                "60",
                "--max-memory",
                "256",
                "-j",
                "1",
                "--optimizations",
                "none",
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )
        if result.stderr:
            print(f"[scan] Semgrep stderr: {result.stderr[:500]}")

        if not result.stdout:
            error_data = {
                "findings": [],
                "total": 0,
                "error": f"No stdout. returncode={result.returncode}. stderr={result.stderr[:500]}",
                "scanned_at": datetime.utcnow().isoformat(),
            }
            with open(os.path.join(RESULTS_DIR, "semgrep.json"), "w") as f:
                json.dump(error_data, f)
            scan_timestamps["semgrep"] = datetime.utcnow().isoformat()
            print(f"[scan] Semgrep produced no output. stderr: {result.stderr[:200]}")
            return

        data = json.loads(result.stdout)
        results = data.get("results", [])
        errors = data.get("errors", [])
        findings = []
        for r in results:
            findings.append(
                {
                    "rule_id": r.get("check_id"),
                    "message": r.get("extra", {}).get("message"),
                    "severity": r.get("extra", {}).get("severity", "WARNING"),
                    "path": r.get("path"),
                    "start_line": r.get("start", {}).get("line"),
                    "end_line": r.get("end", {}).get("line"),
                    "metadata": r.get("extra", {}).get("metadata", {}),
                }
            )

        result_data = {
            "findings": findings,
            "total": len(findings),
            "scanned_at": datetime.utcnow().isoformat(),
        }
        # Include errors from semgrep if any (e.g. invalid path, rule download failure)
        if errors:
            result_data["errors"] = errors[:5]
        with open(os.path.join(RESULTS_DIR, "semgrep.json"), "w") as f:
            json.dump(result_data, f)
        scan_timestamps["semgrep"] = datetime.utcnow().isoformat()
        print(
            f"[scan] Semgrep complete: {len(findings)} findings, {len(errors)} errors"
        )
    except Exception as e:
        print(f"[scan] Semgrep failed: {e}")
        error_data = {
            "findings": [],
            "total": 0,
            "error": str(e),
            "scanned_at": datetime.utcnow().isoformat(),
        }
        with open(os.path.join(RESULTS_DIR, "semgrep.json"), "w") as f:
            json.dump(error_data, f)
        scan_timestamps["semgrep"] = datetime.utcnow().isoformat()


def run_trivy_fs():
    """Run Trivy FS and cache results."""
    try:
        result = subprocess.run(
            ["trivy", "fs", SCA_PATH, "--format", "json", "--scanners", "vuln"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        data = json.loads(result.stdout) if result.stdout else {}
        findings = []
        for target_result in data.get("Results", []):
            for vuln in target_result.get("Vulnerabilities", []):
                findings.append(
                    {
                        "vuln_id": vuln.get("VulnerabilityID"),
                        "pkg_name": vuln.get("PkgName"),
                        "installed_version": vuln.get("InstalledVersion"),
                        "fixed_version": vuln.get("FixedVersion"),
                        "severity": vuln.get("Severity"),
                        "title": vuln.get("Title"),
                        "description": vuln.get("Description"),
                        "target": target_result.get("Target"),
                        "type": target_result.get("Type"),
                    }
                )

        result_data = {
            "findings": findings,
            "total": len(findings),
            "scanned_at": datetime.utcnow().isoformat(),
        }
        with open(os.path.join(RESULTS_DIR, "trivy-fs.json"), "w") as f:
            json.dump(result_data, f)
        scan_timestamps["trivy-fs"] = datetime.utcnow().isoformat()
        print(f"[scan] Trivy FS complete: {len(findings)} findings")
    except Exception as e:
        print(f"[scan] Trivy FS failed: {e}")


def run_trivy_image():
    """Run Trivy image scan on vulnerable app image and cache results."""
    try:
        result = subprocess.run(
            ["trivy", "image", INFRA_IMAGE, "--format", "json", "--scanners", "vuln"],
            capture_output=True,
            text=True,
            timeout=180,
        )
        data = json.loads(result.stdout) if result.stdout else {}
        findings = []
        for target_result in data.get("Results", []):
            for vuln in target_result.get("Vulnerabilities", []):
                findings.append(
                    {
                        "vuln_id": vuln.get("VulnerabilityID"),
                        "pkg_name": vuln.get("PkgName"),
                        "installed_version": vuln.get("InstalledVersion"),
                        "fixed_version": vuln.get("FixedVersion"),
                        "severity": vuln.get("Severity"),
                        "title": vuln.get("Title"),
                        "description": vuln.get("Description"),
                        "target": target_result.get("Target"),
                        "type": target_result.get("Type"),
                    }
                )

        result_data = {
            "findings": findings,
            "total": len(findings),
            "scanned_at": datetime.utcnow().isoformat(),
        }
        with open(os.path.join(RESULTS_DIR, "trivy-image.json"), "w") as f:
            json.dump(result_data, f)
        scan_timestamps["trivy-image"] = datetime.utcnow().isoformat()
        print(f"[scan] Trivy Image complete: {len(findings)} findings")
    except Exception as e:
        print(f"[scan] Trivy Image failed: {e}")


def run_trivy_image_java():
    """Run Trivy image scan on the Java/Tomcat image and cache results."""
    try:
        result = subprocess.run(
            ["trivy", "image", JAVA_IMAGE, "--format", "json", "--scanners", "vuln"],
            capture_output=True,
            text=True,
            timeout=180,
        )
        data = json.loads(result.stdout) if result.stdout else {}
        findings = []
        for target_result in data.get("Results", []):
            for vuln in target_result.get("Vulnerabilities", []):
                findings.append(
                    {
                        "vuln_id": vuln.get("VulnerabilityID"),
                        "pkg_name": vuln.get("PkgName"),
                        "installed_version": vuln.get("InstalledVersion"),
                        "fixed_version": vuln.get("FixedVersion"),
                        "severity": vuln.get("Severity"),
                        "title": vuln.get("Title"),
                        "description": vuln.get("Description"),
                        "target": target_result.get("Target"),
                        "type": target_result.get("Type"),
                    }
                )

        result_data = {
            "findings": findings,
            "total": len(findings),
            "scanned_at": datetime.utcnow().isoformat(),
        }
        with open(os.path.join(RESULTS_DIR, "trivy-image-java.json"), "w") as f:
            json.dump(result_data, f)
        scan_timestamps["trivy-image-java"] = datetime.utcnow().isoformat()
        print(f"[scan] Trivy Image Java complete: {len(findings)} findings")
    except Exception as e:
        print(f"[scan] Trivy Image Java failed: {e}")


def run_trivy_image_python():
    """Run Trivy image scan on the Python image and cache results.

    Only includes python-pkg (pip) findings — OS-level Debian packages from the
    base image are excluded because they're unfixable (Debian Buster is EOL,
    repos are dead, apt-get update fails). The pip packages are explicitly pinned
    in the Dockerfile and fixable by removing the version pin + rebuild.
    """
    try:
        result = subprocess.run(
            ["trivy", "image", PYTHON_IMAGE, "--format", "json", "--scanners", "vuln"],
            capture_output=True,
            text=True,
            timeout=180,
        )
        data = json.loads(result.stdout) if result.stdout else {}
        findings = []
        for target_result in data.get("Results", []):
            # Only include python-pkg (pip) findings — skip OS-level debian packages
            result_type = (target_result.get("Type") or "").lower()
            if result_type in (
                "debian",
                "ubuntu",
                "alpine",
                "redhat",
                "oracle",
                "amazon",
            ):
                continue
            for vuln in target_result.get("Vulnerabilities", []):
                findings.append(
                    {
                        "vuln_id": vuln.get("VulnerabilityID"),
                        "pkg_name": vuln.get("PkgName"),
                        "installed_version": vuln.get("InstalledVersion"),
                        "fixed_version": vuln.get("FixedVersion"),
                        "severity": vuln.get("Severity"),
                        "title": vuln.get("Title"),
                        "description": vuln.get("Description"),
                        "target": target_result.get("Target"),
                        "type": target_result.get("Type"),
                    }
                )

        result_data = {
            "findings": findings,
            "total": len(findings),
            "scanned_at": datetime.utcnow().isoformat(),
        }
        with open(os.path.join(RESULTS_DIR, "trivy-image-python.json"), "w") as f:
            json.dump(result_data, f)
        scan_timestamps["trivy-image-python"] = datetime.utcnow().isoformat()
        print(f"[scan] Trivy Image Python complete: {len(findings)} findings")
    except Exception as e:
        print(f"[scan] Trivy Image Python failed: {e}")


def run_trivy_image_php():
    """Run Trivy image scan on the PHP image and cache results.

    Reports ALL packages (OS + language) — same behavior as the Java image,
    NOT filtered like the Python image. The PHP2Shell CVEs (CVE-2026-109618 /
    CVE-2026-109619) live in the Debian php8.2-* OS packages, so filtering out
    OS-level packages would discard exactly the findings this lab exists to
    produce.
    """
    try:
        result = subprocess.run(
            ["trivy", "image", PHP_IMAGE, "--format", "json", "--scanners", "vuln"],
            capture_output=True,
            text=True,
            timeout=180,
        )
        data = json.loads(result.stdout) if result.stdout else {}
        findings = []
        for target_result in data.get("Results", []):
            for vuln in target_result.get("Vulnerabilities", []):
                findings.append(
                    {
                        "vuln_id": vuln.get("VulnerabilityID"),
                        "pkg_name": vuln.get("PkgName"),
                        "installed_version": vuln.get("InstalledVersion"),
                        "fixed_version": vuln.get("FixedVersion"),
                        "severity": vuln.get("Severity"),
                        "title": vuln.get("Title"),
                        "description": vuln.get("Description"),
                        "target": target_result.get("Target"),
                        "type": target_result.get("Type"),
                    }
                )

        result_data = {
            "findings": findings,
            "total": len(findings),
            "scanned_at": datetime.utcnow().isoformat(),
        }
        with open(os.path.join(RESULTS_DIR, "trivy-image-php.json"), "w") as f:
            json.dump(result_data, f)
        scan_timestamps["trivy-image-php"] = datetime.utcnow().isoformat()
        print(f"[scan] Trivy Image PHP complete: {len(findings)} findings")
    except Exception as e:
        print(f"[scan] Trivy Image PHP failed: {e}")


def run_trivy_os():
    """Scan the host OS (Ubuntu 20.04) for OS-level CVEs using trivy rootfs."""
    try:
        result = subprocess.run(
            ["trivy", "rootfs", "/", "--format", "json", "--scanners", "vuln"],
            capture_output=True,
            text=True,
            timeout=300,
        )

        if not result.stdout:
            error_msg = f"trivy produced no output (rc={result.returncode}): {result.stderr[:300]}"
            print(f"[scan] {error_msg}")
            error_data = {
                "findings": [],
                "total": 0,
                "error": error_msg,
                "scanned_at": datetime.utcnow().isoformat(),
            }
            with open(os.path.join(RESULTS_DIR, "trivy-os.json"), "w") as f:
                json.dump(error_data, f)
            scan_timestamps["trivy-os"] = datetime.utcnow().isoformat()
            return

        data = json.loads(result.stdout)
        findings = []
        for target_result in data.get("Results", []):
            for vuln in target_result.get("Vulnerabilities", []):
                findings.append(
                    {
                        "vuln_id": vuln.get("VulnerabilityID"),
                        "pkg_name": vuln.get("PkgName"),
                        "installed_version": vuln.get("InstalledVersion"),
                        "fixed_version": vuln.get("FixedVersion"),
                        "severity": vuln.get("Severity"),
                        "title": vuln.get("Title"),
                        "description": vuln.get("Description"),
                        "target": target_result.get("Target"),
                        "type": target_result.get("Type"),
                        "os": "ubuntu 20.04 (host)",
                    }
                )

        result_data = {
            "findings": findings,
            "total": len(findings),
            "scanned_at": datetime.utcnow().isoformat(),
        }
        with open(os.path.join(RESULTS_DIR, "trivy-os.json"), "w") as f:
            json.dump(result_data, f)
        scan_timestamps["trivy-os"] = datetime.utcnow().isoformat()
        print(f"[scan] Trivy OS (host rootfs) complete: {len(findings)} findings")
    except Exception as e:
        print(f"[scan] Trivy OS failed: {e}")
        error_data = {
            "findings": [],
            "total": 0,
            "error": str(e),
            "scanned_at": datetime.utcnow().isoformat(),
        }
        with open(os.path.join(RESULTS_DIR, "trivy-os.json"), "w") as f:
            json.dump(error_data, f)
        scan_timestamps["trivy-os"] = datetime.utcnow().isoformat()


def run_serverless_semgrep():
    """Run Semgrep against the serverless lab (Lambda code + Terraform IaC) and cache results."""
    if not os.path.isdir(SERVERLESS_PATH):
        print(
            f"[scan] Serverless Semgrep SKIPPED — path does not exist: {SERVERLESS_PATH}"
        )
        error_data = {
            "findings": [],
            "total": 0,
            "error": f"Serverless path missing: {SERVERLESS_PATH}",
            "scanned_at": datetime.utcnow().isoformat(),
        }
        with open(os.path.join(RESULTS_DIR, "serverless.json"), "w") as f:
            json.dump(error_data, f)
        scan_timestamps["serverless"] = datetime.utcnow().isoformat()
        return

    try:
        # Write serverless-specific rules (HCL for IaC + Python for Lambda code)
        rules_file = os.path.join(RESULTS_DIR, "serverless-rules.yaml")
        with open(rules_file, "w") as rf:
            rf.write("""rules:
  # =========================================================================
  # HCL Rules — Terraform Lambda misconfigurations
  # =========================================================================

  # FINDING 1: Lambda with no VPC configuration
  - id: lambda-no-vpc-config
    patterns:
      - pattern: |
          resource "aws_lambda_function" $NAME {
            ...
          }
      - pattern-not: |
          resource "aws_lambda_function" $NAME {
            ...
            vpc_config {
              ...
            }
            ...
          }
    message: >
      Lambda function has no VPC configuration. Attach to a VPC for network isolation.
    languages: [hcl]
    severity: WARNING
    metadata:
      cwe: ["CWE-284"]
      owasp: ["A01:2021 - Broken Access Control"]

  # FINDING 2: Lambda with no dead letter queue
  - id: lambda-no-dlq
    patterns:
      - pattern: |
          resource "aws_lambda_function" $NAME {
            ...
          }
      - pattern-not: |
          resource "aws_lambda_function" $NAME {
            ...
            dead_letter_config {
              ...
            }
            ...
          }
    message: >
      Lambda function has no dead letter queue configured. Failed events will be lost.
    languages: [hcl]
    severity: WARNING
    metadata:
      cwe: ["CWE-392"]
      owasp: ["A05:2021 - Security Misconfiguration"]

  # FINDING 3: Hardcoded secrets in Lambda environment variables
  - id: lambda-hardcoded-env-secret
    patterns:
      - pattern-either:
          - pattern: |
              environment {
                variables = {
                  ...
                  DB_PASSWORD = "..."
                  ...
                }
              }
          - pattern: |
              environment {
                variables = {
                  ...
                  API_KEY = "..."
                  ...
                }
              }
    message: >
      Hardcoded secret in Lambda environment variables. Use AWS Secrets Manager or SSM Parameter Store.
    languages: [hcl]
    severity: ERROR
    metadata:
      cwe: ["CWE-798"]
      owasp: ["A07:2021 - Identification and Authentication Failures"]

  # FINDING 4: Lambda with no X-Ray tracing
  - id: lambda-no-tracing
    patterns:
      - pattern: |
          resource "aws_lambda_function" $NAME {
            ...
          }
      - pattern-not: |
          resource "aws_lambda_function" $NAME {
            ...
            tracing_config {
              ...
            }
            ...
          }
    message: >
      Lambda function has no X-Ray tracing enabled. Enable tracing for observability.
    languages: [hcl]
    severity: WARNING
    metadata:
      cwe: ["CWE-778"]
      owasp: ["A09:2021 - Security Logging and Monitoring Failures"]

  # FINDING 5: Lambda with excessive timeout
  - id: lambda-excessive-timeout
    pattern: |
      resource "aws_lambda_function" $NAME {
        ...
        timeout = 900
        ...
      }
    message: >
      Lambda function has maximum timeout (900s). Use a reasonable timeout value.
    languages: [hcl]
    severity: WARNING
    metadata:
      cwe: ["CWE-400"]
      owasp: ["A05:2021 - Security Misconfiguration"]

  # FINDING 6: Lambda with no reserved concurrency limit
  - id: lambda-no-concurrency-limit
    patterns:
      - pattern: |
          resource "aws_lambda_function" $NAME {
            ...
          }
      - pattern-not: |
          resource "aws_lambda_function" $NAME {
            ...
            reserved_concurrent_executions = $VAL
            ...
          }
    message: >
      Lambda function has no reserved concurrency limit. Set a limit to prevent runaway invocations.
    languages: [hcl]
    severity: WARNING
    metadata:
      cwe: ["CWE-770"]
      owasp: ["A05:2021 - Security Misconfiguration"]

  # FINDING 7: IAM role with overly permissive assume role (Principal: *)
  - id: lambda-role-wildcard-assume
    pattern: |
      Principal = { AWS = "*" }
    message: >
      IAM role allows any AWS principal to assume it. Restrict to lambda.amazonaws.com service.
    languages: [hcl]
    severity: ERROR
    metadata:
      cwe: ["CWE-269"]
      owasp: ["A01:2021 - Broken Access Control"]

  # FINDINGS 8 & 9: IAM policy with wildcard Action and Resource
  - id: lambda-policy-wildcard
    pattern-either:
      - pattern: Action = "*"
      - pattern: Resource = "*"
    message: >
      IAM policy uses wildcard Action or Resource. Scope to least-privilege permissions.
    languages: [hcl]
    severity: ERROR
    metadata:
      cwe: ["CWE-269"]
      owasp: ["A01:2021 - Broken Access Control"]

  # FINDING 10: Lambda Function URL with no authentication
  - id: lambda-public-url-no-auth
    pattern: |
      resource "aws_lambda_function_url" $NAME {
        ...
        authorization_type = "NONE"
        ...
      }
    message: >
      Lambda Function URL has no authentication. Set authorization_type to AWS_IAM.
    languages: [hcl]
    severity: ERROR
    metadata:
      cwe: ["CWE-306"]
      owasp: ["A07:2021 - Identification and Authentication Failures"]

  # FINDING 11: CloudWatch Log Group with no KMS encryption
  - id: lambda-logs-no-encryption
    patterns:
      - pattern: |
          resource "aws_cloudwatch_log_group" $NAME {
            ...
          }
      - pattern-not: |
          resource "aws_cloudwatch_log_group" $NAME {
            ...
            kms_key_id = $VAL
            ...
          }
    message: >
      CloudWatch Log Group has no KMS encryption. Add kms_key_id for encryption at rest.
    languages: [hcl]
    severity: WARNING
    metadata:
      cwe: ["CWE-311"]
      owasp: ["A02:2021 - Cryptographic Failures"]

  # FINDING 12: CloudWatch Log Group with no retention period
  - id: lambda-logs-no-retention
    patterns:
      - pattern: |
          resource "aws_cloudwatch_log_group" $NAME {
            ...
          }
      - pattern-not: |
          resource "aws_cloudwatch_log_group" $NAME {
            ...
            retention_in_days = $VAL
            ...
          }
    message: >
      CloudWatch Log Group has no retention period. Set retention_in_days to avoid unbounded storage.
    languages: [hcl]
    severity: WARNING
    metadata:
      cwe: ["CWE-779"]
      owasp: ["A09:2021 - Security Logging and Monitoring Failures"]

  # =========================================================================
  # Python Rules — Lambda code vulnerabilities
  # =========================================================================

  # Lambda hardcoded credentials
  - id: serverless-hardcoded-secret
    patterns:
      - pattern-either:
          - pattern: AWS_ACCESS_KEY = "..."
          - pattern: AWS_SECRET_KEY = "..."
          - pattern: THIRD_PARTY_API_KEY = "..."
    message: >
      Hardcoded credential in Lambda source code. Use environment variables or Secrets Manager.
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ["CWE-798"]
      owasp: ["A07:2021 - Identification and Authentication Failures"]

  # Lambda logging sensitive event data
  - id: serverless-log-sensitive-data
    pattern: logger.info(f"...{json.dumps($EVENT)}...")
    message: >
      Logging full event payload which may contain sensitive data. Redact PII before logging.
    languages: [python]
    severity: WARNING
    metadata:
      cwe: ["CWE-532"]
      owasp: ["A09:2021 - Security Logging and Monitoring Failures"]

  # Lambda bare except
  - id: serverless-broad-exception
    pattern: |
      except:
        ...
    message: >
      Bare except clause catches all exceptions including SystemExit and KeyboardInterrupt.
      Catch specific exceptions instead.
    languages: [python]
    severity: WARNING
    metadata:
      cwe: ["CWE-396"]
      owasp: ["A05:2021 - Security Misconfiguration"]

  # Lambda PartiQL injection
  - id: serverless-sql-injection
    patterns:
      - pattern-either:
          - pattern: $CLIENT.execute_statement(Statement=f"...{$VAR}...")
          - pattern: |
              $QUERY = f"...{$VAR}..."
              ...
              $CLIENT.execute_statement(Statement=$QUERY)
    message: >
      PartiQL injection via f-string. Use parameterized queries with Parameters argument.
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ["CWE-89"]
      owasp: ["A03:2021 - Injection"]

  # Lambda SSRF
  - id: serverless-ssrf
    pattern: requests.get($URL)
    message: >
      SSRF — user-controlled URL passed to requests.get in Lambda handler.
      Validate against an allowlist of permitted URLs.
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ["CWE-918"]
      owasp: ["A10:2021 - Server-Side Request Forgery"]

  # Lambda insecure deserialization
  - id: serverless-insecure-deserialization
    pattern: pickle.loads(...)
    message: >
      Insecure deserialization via pickle.loads on user-supplied Lambda event data.
      Use json.loads or a safe format.
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ["CWE-502"]
      owasp: ["A08:2021 - Software and Data Integrity Failures"]

  # Lambda command injection
  - id: serverless-command-injection
    pattern: os.system("..." + $VAR)
    message: >
      Command injection via os.system with concatenated user input in Lambda handler.
      Use subprocess with a list of arguments.
    languages: [python]
    severity: ERROR
    metadata:
      cwe: ["CWE-78"]
      owasp: ["A03:2021 - Injection"]

  # Lambda weak random
  - id: serverless-weak-random
    pattern: random.randint(...)
    message: >
      Weak randomness in Lambda handler. Use secrets module for security tokens.
    languages: [python]
    severity: WARNING
    metadata:
      cwe: ["CWE-330"]
      owasp: ["A02:2021 - Cryptographic Failures"]
""")

        # Scan both .tf and .py files in the serverless lab directory
        result = subprocess.run(
            [
                "semgrep",
                "scan",
                "--config",
                rules_file,
                SERVERLESS_PATH,
                "--json",
                "--no-git-ignore",
                "--timeout",
                "60",
                "--max-memory",
                "256",
                "-j",
                "1",
                "--optimizations",
                "none",
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )
        if result.stderr:
            print(f"[scan] Serverless Semgrep stderr: {result.stderr[:500]}")

        if not result.stdout:
            error_data = {
                "findings": [],
                "total": 0,
                "error": f"No stdout. returncode={result.returncode}. stderr={result.stderr[:500]}",
                "scanned_at": datetime.utcnow().isoformat(),
            }
            with open(os.path.join(RESULTS_DIR, "serverless.json"), "w") as f:
                json.dump(error_data, f)
            scan_timestamps["serverless"] = datetime.utcnow().isoformat()
            print(
                f"[scan] Serverless Semgrep produced no output. stderr: {result.stderr[:200]}"
            )
            return

        data = json.loads(result.stdout)
        results = data.get("results", [])
        errors = data.get("errors", [])
        findings = []
        for r in results:
            findings.append(
                {
                    "rule_id": r.get("check_id"),
                    "message": r.get("extra", {}).get("message"),
                    "severity": r.get("extra", {}).get("severity", "WARNING"),
                    "path": r.get("path"),
                    "start_line": r.get("start", {}).get("line"),
                    "end_line": r.get("end", {}).get("line"),
                    "metadata": r.get("extra", {}).get("metadata", {}),
                }
            )

        result_data = {
            "findings": findings,
            "total": len(findings),
            "scanned_at": datetime.utcnow().isoformat(),
        }
        if errors:
            result_data["errors"] = errors[:5]
        with open(os.path.join(RESULTS_DIR, "serverless.json"), "w") as f:
            json.dump(result_data, f)
        scan_timestamps["serverless"] = datetime.utcnow().isoformat()
        print(
            f"[scan] Serverless Semgrep complete: {len(findings)} findings, {len(errors)} errors"
        )
    except Exception as e:
        print(f"[scan] Serverless Semgrep failed: {e}")
        error_data = {
            "findings": [],
            "total": 0,
            "error": str(e),
            "scanned_at": datetime.utcnow().isoformat(),
        }
        with open(os.path.join(RESULTS_DIR, "serverless.json"), "w") as f:
            json.dump(error_data, f)
        scan_timestamps["serverless"] = datetime.utcnow().isoformat()


def run_all_scans():
    """Run all scanners sequentially and cache results."""
    print("[scan] Running all scanners...")
    run_checkov()
    run_semgrep()
    run_trivy_fs()
    run_serverless_semgrep()
    run_trivy_image()
    run_trivy_image_java()
    run_trivy_image_python()
    run_trivy_image_php()
    run_trivy_os()
    print("[scan] All scans complete.")


class ScanHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self._respond(200, {"status": "ok"})
        elif self.path == "/scan/checkov":
            self._serve_cached("checkov.json")
        elif self.path == "/scan/semgrep":
            self._serve_cached("semgrep.json")
        elif self.path == "/scan/trivy-fs":
            self._serve_cached("trivy-fs.json")
        elif self.path == "/scan/trivy-image/infra":
            self._serve_cached("trivy-image.json")
        elif self.path == "/scan/trivy-image/java":
            self._serve_cached("trivy-image-java.json")
        elif self.path == "/scan/trivy-image/python":
            self._serve_cached("trivy-image-python.json")
        elif self.path == "/scan/trivy-image/php":
            self._serve_cached("trivy-image-php.json")
        elif self.path == "/scan/trivy-image":
            # Backward compatible — serves infra image results
            self._serve_cached("trivy-image.json")
        elif self.path == "/scan/trivy-os":
            self._serve_cached("trivy-os.json")
        elif self.path == "/scan/serverless":
            self._serve_cached("serverless.json")
        elif self.path == "/scan-status":
            self._respond(200, {"timestamps": scan_timestamps})
        else:
            self._respond(
                404,
                {
                    "error": "unknown endpoint",
                    "available": [
                        "/health",
                        "/scan/checkov",
                        "/scan/semgrep",
                        "/scan/trivy-fs",
                        "/scan/trivy-image/infra",
                        "/scan/trivy-image/java",
                        "/scan/trivy-image/python",
                        "/scan/trivy-image/php",
                        "/scan/trivy-os",
                        "/scan/serverless",
                        "/scan-status",
                        "POST /trigger-scan",
                    ],
                },
            )

    def do_POST(self):
        if self.path == "/trigger-scan":
            thread = threading.Thread(target=run_all_scans, daemon=True)
            thread.start()
            self._respond(
                202,
                {
                    "status": "scan triggered",
                    "message": "Scans running in background. Check /scan-status for completion.",
                },
            )
        elif self.path == "/trigger-scan/semgrep":
            thread = threading.Thread(target=run_semgrep, daemon=True)
            thread.start()
            self._respond(202, {"status": "semgrep scan triggered"})
        elif self.path == "/trigger-scan/trivy-os":
            thread = threading.Thread(target=run_trivy_os, daemon=True)
            thread.start()
            self._respond(202, {"status": "trivy-os scan triggered"})
        elif self.path == "/trigger-scan/checkov":
            thread = threading.Thread(target=run_checkov, daemon=True)
            thread.start()
            self._respond(202, {"status": "checkov scan triggered"})
        elif self.path == "/trigger-scan/trivy-fs":
            thread = threading.Thread(target=run_trivy_fs, daemon=True)
            thread.start()
            self._respond(202, {"status": "trivy-fs scan triggered"})
        elif self.path == "/trigger-scan/trivy-image":
            thread = threading.Thread(target=run_trivy_image, daemon=True)
            thread.start()
            self._respond(202, {"status": "trivy-image (infra) scan triggered"})
        elif self.path == "/trigger-scan/trivy-image-java":
            thread = threading.Thread(target=run_trivy_image_java, daemon=True)
            thread.start()
            self._respond(202, {"status": "trivy-image-java scan triggered"})
        elif self.path == "/trigger-scan/trivy-image-python":
            thread = threading.Thread(target=run_trivy_image_python, daemon=True)
            thread.start()
            self._respond(202, {"status": "trivy-image-python scan triggered"})
        elif self.path == "/trigger-scan/trivy-image-php":
            thread = threading.Thread(target=run_trivy_image_php, daemon=True)
            thread.start()
            self._respond(202, {"status": "trivy-image-php scan triggered"})
        elif self.path == "/trigger-scan/serverless":
            thread = threading.Thread(target=run_serverless_semgrep, daemon=True)
            thread.start()
            self._respond(202, {"status": "serverless scan triggered"})
        else:
            self._respond(404, {"error": "unknown endpoint"})

    def _serve_cached(self, filename):
        """Return cached scan results from disk."""
        filepath = os.path.join(RESULTS_DIR, filename)
        if not os.path.exists(filepath):
            self._respond(
                404,
                {
                    "error": f"No cached results for {filename}. POST /trigger-scan first or wait for startup scan to complete."
                },
            )
            return
        with open(filepath) as f:
            data = json.load(f)
        self._respond(200, data)

    def _respond(self, code, data):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def log_message(self, fmt, *args):
        print(f"[server] {args[0]}")


if __name__ == "__main__":
    ensure_results_dir()

    # Wait for lab setup to complete before scanning.
    # The user-data script writes this marker file as its very last step.
    SETUP_MARKER = "/opt/vuln-labs/SETUP_COMPLETE"
    MAX_WAIT = 300  # 5 minutes max
    waited = 0
    while not os.path.exists(SETUP_MARKER) and waited < MAX_WAIT:
        print(f"[startup] Waiting for lab setup to complete ({waited}s)...")
        time.sleep(10)
        waited += 10

    if not os.path.exists(SETUP_MARKER):
        print(
            f"[startup] WARNING: {SETUP_MARKER} not found after {MAX_WAIT}s. Running scans anyway."
        )
    else:
        print(f"[startup] Lab setup complete. Starting scans.")

    # Run all scans once at startup
    print("Running initial scans at startup...")
    run_all_scans()

    print("Scan server starting on port 8090...")
    server = HTTPServer(("0.0.0.0", 8090), ScanHandler)
    print("Ready. GET endpoints serve cached results. POST /trigger-scan to re-scan.")
    server.serve_forever()
