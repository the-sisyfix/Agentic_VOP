#!/bin/bash
# =============================================================================
# Vulnerable Lab Setup Script
# Role: ${role}
# Provisions intentionally vulnerable applications for scanner demos.
# Scanner installation is conditional based on instance role.
# =============================================================================
set -e

export DEBIAN_FRONTEND=noninteractive

# Update system packages (retry up to 3 times on transient mirror failures)
for i in 1 2 3; do
  apt-get update -y && break
  echo "apt-get update failed (attempt $i/3), retrying in 10s..."
  sleep 10
done
for i in 1 2 3; do
  apt-get install -y --fix-missing git curl unzip python3 python3-pip python3-venv nodejs npm docker.io && break
  echo "apt-get install failed (attempt $i/3), retrying in 10s..."
  apt-get update -y
  sleep 10
done

# Enable and start Docker
systemctl enable docker
systemctl start docker
usermod -aG docker ubuntu

# Vuln baseline parity (env1==env2): the focal AMI already ships vulnerable
# apport/accountsservice; we only FREEZE them by disabling auto-upgrade so the
# host doesn't self-patch and drift from env1. SA-4 fixes via apt-get
# --only-upgrade (moves e.g. apport 27.8 -> 27.31, which the archive serves).
systemctl disable --now unattended-upgrades apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true

# =============================================================================
# 0a. Install AWS CLI v2 (self-contained, no system Python dependency conflicts)
# =============================================================================
curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip
unzip -o /tmp/awscliv2.zip -d /tmp/
/tmp/aws/install --update 2>/dev/null || /tmp/aws/install
rm -rf /tmp/awscliv2.zip /tmp/aws
aws --version

# =============================================================================
# 0b. Install Terraform (needed to apply CSPM lab resources)
# =============================================================================
curl -fsSL https://releases.hashicorp.com/terraform/1.7.5/terraform_1.7.5_linux_amd64.zip -o /tmp/terraform.zip
unzip -o /tmp/terraform.zip -d /usr/local/bin/
rm -f /tmp/terraform.zip
terraform version

# =============================================================================
# 1. AppSec Lab — Vulnerable Python Flask app (for Semgrep SAST + Trivy SCA)
#    Single application scanned by both tools:
#    - Semgrep scans .py files for code-level vulnerabilities
#    - Trivy FS scans requirements.txt for vulnerable dependencies
#    Files downloaded from GitHub to keep user-data under 16KB limit.
# =============================================================================
mkdir -p /opt/vuln-labs/appsec-lab/uploads
mkdir -p /opt/vuln-labs/appsec-lab/data
echo "sensitive internal data" > /opt/vuln-labs/appsec-lab/data/secrets.txt

APPSEC_BASE="https://raw.githubusercontent.com/the-sisyfix/Agentic_VOP/main/infra/vuln-labs/appsec-lab"
curl -fsSL "$APPSEC_BASE/app.py" -o /opt/vuln-labs/appsec-lab/app.py
curl -fsSL "$APPSEC_BASE/auth.py" -o /opt/vuln-labs/appsec-lab/auth.py
curl -fsSL "$APPSEC_BASE/file_handler.py" -o /opt/vuln-labs/appsec-lab/file_handler.py
curl -fsSL "$APPSEC_BASE/api_client.py" -o /opt/vuln-labs/appsec-lab/api_client.py
curl -fsSL "$APPSEC_BASE/utils.py" -o /opt/vuln-labs/appsec-lab/utils.py
curl -fsSL "$APPSEC_BASE/config.py" -o /opt/vuln-labs/appsec-lab/config.py
curl -fsSL "$APPSEC_BASE/requirements.txt" -o /opt/vuln-labs/appsec-lab/requirements.txt

# =============================================================================
# 3. Infra Lab — Dockerfile with outdated base image (for Trivy Image)
# =============================================================================
mkdir -p /opt/vuln-labs/infra-lab
cat > /opt/vuln-labs/infra-lab/Dockerfile << 'DKREOF'
# Intentionally outdated base image with known CVEs
FROM ubuntu:20.04

RUN apt-get update && apt-get install -y \
    openssl=1.1.1f-1ubuntu2 \
    curl \
    wget \
    nginx \
    && rm -rf /var/lib/apt/lists/*

# VULN: Running as root (no USER instruction)
# VULN: No HEALTHCHECK defined
# VULN: Using ADD instead of COPY for local files
ADD app.py /app/app.py

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
DKREOF

cat > /opt/vuln-labs/infra-lab/app.py << 'PYEOF'
print("placeholder app")
PYEOF

# Build the vulnerable image (timeout after 5 minutes)
cd /opt/vuln-labs/infra-lab
timeout 300 docker build -t vuln-lab-image:latest . || echo "WARNING: infra-lab docker build timed out or failed"

# =============================================================================
# 3b. Java Lab — Old Tomcat + JDK 8 on Debian (for Trivy Image)
#     Produces JDK CVEs, Tomcat CVEs, and OS-level Debian CVEs.
#     These do NOT overlap with the SCA lab (which scans pom.xml manifests).
# =============================================================================
mkdir -p /opt/vuln-labs/java-image-lab
cat > /opt/vuln-labs/java-image-lab/Dockerfile << 'JDKREOF'
# Intentionally outdated Java runtime environment
# Tomcat 9.0.30 + OpenJDK 8 on Debian Buster — has JDK CVEs, Tomcat CVEs,
# and Debian OS-level CVEs baked into the base image layers.
# No apt-get needed — Debian Buster repos are EOL and unavailable.
FROM tomcat:9.0.30-jdk8-openjdk

# Deploy a placeholder webapp
RUN mkdir -p /usr/local/tomcat/webapps/ROOT
RUN echo '<html><body><h1>Vulnerable Java App</h1></body></html>' > /usr/local/tomcat/webapps/ROOT/index.html

# VULN: Running as root (no USER instruction)
# VULN: No HEALTHCHECK defined
EXPOSE 8080
CMD ["catalina.sh", "run"]
JDKREOF

cd /opt/vuln-labs/java-image-lab
timeout 300 docker build -t vuln-java-image:latest . || echo "WARNING: java-image-lab docker build timed out or failed"

# =============================================================================
# 3c. Python Lab — Old Python 3.8 with vulnerable pip packages (for Trivy Image)
#     Produces OS CVEs (Debian buster) + installed pip package CVEs.
#     Remediation: update base image or pin newer package versions in Dockerfile.
# =============================================================================
mkdir -p /opt/vuln-labs/python-image-lab
cat > /opt/vuln-labs/python-image-lab/Dockerfile << 'PYDKREOF'
# Intentionally outdated Python runtime with vulnerable dependencies
FROM python:3.8-slim-buster

# Install vulnerable pip packages directly into the image
RUN pip install --no-cache-dir \
    flask==2.0.0 \
    jinja2==3.0.0 \
    requests==2.25.0 \
    cryptography==3.3.2 \
    pyyaml==5.3.1 \
    urllib3==1.26.4 \
    werkzeug==2.0.0 \
    setuptools==58.0.0 \
    pillow==8.1.0 \
    certifi==2020.12.5

# Add a placeholder app
RUN mkdir -p /app
RUN echo 'from flask import Flask; app = Flask(__name__)' > /app/main.py

# VULN: Running as root (no USER instruction)
# VULN: No HEALTHCHECK defined
WORKDIR /app
EXPOSE 5000
CMD ["python", "main.py"]
PYDKREOF

cd /opt/vuln-labs/python-image-lab
timeout 300 docker build -t vuln-python-image:latest . || echo "WARNING: python-image-lab docker build timed out or failed"

# =============================================================================
# 3d. PHP Lab — Debian 12 + apt-pinned php8.2 (for Trivy Image)
#     Produces the PHP2Shell OS-package CVEs (CVE-2026-109618/109619) plus
#     other Debian CVEs. Dockerfile fetched from GitHub to keep user-data
#     under the 16KB limit (same pattern as scan-server.py / cspm template).
# =============================================================================
mkdir -p /opt/vuln-labs/php-image-lab
curl -fsSL "https://raw.githubusercontent.com/the-sisyfix/Agentic_VOP/main/infra/vuln-labs/php-image-lab/Dockerfile" \
  -o /opt/vuln-labs/php-image-lab/Dockerfile
cd /opt/vuln-labs/php-image-lab
timeout 300 docker build -t vuln-php-image:latest . || echo "WARNING: php-image-lab docker build timed out or failed"

# =============================================================================
# 4. CSPM Lab — Vulnerable Terraform (applied as real AWS resources)
#    Creates intentionally misconfigured S3 bucket + Security Group + more.
#    SA4 will later fix these by editing the .tf and re-applying.
#    Template downloaded from GitHub to keep user-data under 16KB limit.
# =============================================================================
mkdir -p /opt/vuln-labs/cspm-lab

# Download CSPM lab template and substitute placeholders
curl -fsSL "https://raw.githubusercontent.com/the-sisyfix/Agentic_VOP/main/infra/vuln-labs/cspm-lab-template.tf" \
  -o /opt/vuln-labs/cspm-lab/main.tf
sed -i "s/NAME_PLACEHOLDER/${name_prefix}/g" /opt/vuln-labs/cspm-lab/main.tf
sed -i "s/REGION_PLACEHOLDER/${aws_region}/g" /opt/vuln-labs/cspm-lab/main.tf

# Create backend config for CSPM lab Terraform state
cat > /opt/vuln-labs/cspm-lab/backend.hcl << 'BKEOF'
bucket         = "${terraform_state_bucket}"
key            = "vuln-labs/cspm-lab/${name_prefix}/terraform.tfstate"
region         = "${aws_region}"
encrypt        = true
dynamodb_table = "${terraform_lock_table}"
BKEOF

# Initialize and apply the CSPM lab Terraform to create real resources
cd /opt/vuln-labs/cspm-lab
terraform init -backend-config=backend.hcl -input=false
terraform apply -auto-approve -input=false || echo "WARNING: CSPM lab terraform apply failed. Resources may not exist."

# =============================================================================
# 4b. Serverless Lab — Vulnerable Lambda (applied as real AWS resources)
#     Creates intentionally misconfigured Lambda + IAM + Function URL.
#     Semgrep scans both the .tf (IaC misconfigs) and .py (code vulns).
#     SA4 will later fix these by editing the files and re-applying.
#     Files downloaded from GitHub to keep user-data under 16KB limit.
# =============================================================================
mkdir -p /opt/vuln-labs/serverless-lab

SERVERLESS_BASE="https://raw.githubusercontent.com/the-sisyfix/Agentic_VOP/main/infra/vuln-labs"
curl -fsSL "$SERVERLESS_BASE/serverless-lab-template.tf" \
  -o /opt/vuln-labs/serverless-lab/main.tf
curl -fsSL "$SERVERLESS_BASE/serverless-lab/lambda_function.py" \
  -o /opt/vuln-labs/serverless-lab/lambda_function.py

# Substitute placeholders in the Terraform template
sed -i "s/NAME_PLACEHOLDER/${name_prefix}/g" /opt/vuln-labs/serverless-lab/main.tf
sed -i "s/REGION_PLACEHOLDER/${aws_region}/g" /opt/vuln-labs/serverless-lab/main.tf

# Create backend config for Serverless lab Terraform state
cat > /opt/vuln-labs/serverless-lab/backend.hcl << 'BKEOF'
bucket         = "${terraform_state_bucket}"
key            = "vuln-labs/serverless-lab/${name_prefix}/terraform.tfstate"
region         = "${aws_region}"
encrypt        = true
dynamodb_table = "${terraform_lock_table}"
BKEOF

# Initialize and apply the Serverless lab Terraform to create real resources
# First, clean up any orphaned resources from prior failed runs (makes deploy idempotent)
LAMBDA_NAME="serverless-lab-${name_prefix}-vuln-handler"
ROLE_NAME="serverless-lab-${name_prefix}-role"
POLICY_NAME="serverless-lab-${name_prefix}-policy"
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | python3 -c "import json,sys;print(json.load(sys.stdin)['accountId'])" 2>/dev/null || echo "unknown")
POLICY_ARN="arn:aws:iam::$AWS_ACCOUNT_ID:policy/$POLICY_NAME"
LOG_GROUP="/aws/lambda/$LAMBDA_NAME"

if [ "$AWS_ACCOUNT_ID" != "unknown" ]; then
  echo "[serverless-lab] Cleaning up any orphaned resources from prior failed runs..."
  # Delete function URL config (if exists)
  aws lambda delete-function-url-config --function-name "$LAMBDA_NAME" 2>/dev/null || true
  # Delete Lambda function (if exists)
  aws lambda delete-function --function-name "$LAMBDA_NAME" 2>/dev/null || true
  # Detach policy from role (if attached)
  aws iam detach-role-policy --role-name "$ROLE_NAME" --policy-arn "$POLICY_ARN" 2>/dev/null || true
  # Delete IAM policy (delete all non-default versions first)
  for v in $(aws iam list-policy-versions --policy-arn "$POLICY_ARN" --query 'Versions[?!IsDefaultVersion].VersionId' --output text 2>/dev/null); do
    aws iam delete-policy-version --policy-arn "$POLICY_ARN" --version-id "$v" 2>/dev/null || true
  done
  aws iam delete-policy --policy-arn "$POLICY_ARN" 2>/dev/null || true
  # Delete IAM role (if exists)
  aws iam delete-role --role-name "$ROLE_NAME" 2>/dev/null || true
  # Delete CloudWatch log group (if exists)
  aws logs delete-log-group --log-group-name "$LOG_GROUP" 2>/dev/null || true
  echo "[serverless-lab] Cleanup complete."
else
  echo "[serverless-lab] Skipping cleanup (could not determine AWS account ID)."
fi
echo "[serverless-lab] Proceeding with terraform apply..."

cd /opt/vuln-labs/serverless-lab
terraform init -backend-config=backend.hcl -input=false
terraform apply -auto-approve -input=false || echo "WARNING: Serverless lab terraform apply failed. Resources may not exist."

%{ if install_scanners ~}
# =============================================================================
# 5. Install Scanners
# =============================================================================

# Install Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install Semgrep
pip3 install semgrep --break-system-packages 2>/dev/null || pip3 install semgrep

# Install Checkov
# Pin argcomplete<3.6 to avoid Python 3.8 incompatibility with argcomplete 3.7+
# Remove stale system botocore/boto3 that conflict with checkov's requirements
rm -rf /usr/lib/python3/dist-packages/botocore /usr/lib/python3/dist-packages/boto3 /usr/lib/python3/dist-packages/s3transfer 2>/dev/null || true
pip3 install "argcomplete<3.6" --break-system-packages 2>/dev/null || pip3 install "argcomplete<3.6"
pip3 install checkov --break-system-packages 2>/dev/null || pip3 install checkov
%{ endif ~}

%{ if install_scan_server ~}
# =============================================================================
# 6. Install and Start Scan Server (scan-source role only)
# Download from GitHub to keep user-data under the 16KB limit.
# =============================================================================
curl -fsSL "https://raw.githubusercontent.com/the-sisyfix/Agentic_VOP/main/infra/vuln-labs/scan-server.py" \
  -o /opt/vuln-labs/scan-server.py

# Replace port placeholder if needed
sed -i 's/8090/${scan_server_port}/g' /opt/vuln-labs/scan-server.py

# Start the scan server as a systemd service for reliability
cat > /etc/systemd/system/scan-server.service << 'SVCEOF'
[Unit]
Description=VOP Vulnerability Lab Scan Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/vuln-labs/scan-server.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable scan-server
systemctl start scan-server
%{ endif ~}

# =============================================================================
# Done — write a marker file
# =============================================================================
echo "Lab setup complete (role: ${role}) at $(date)" > /opt/vuln-labs/SETUP_COMPLETE
chown -R ubuntu:ubuntu /opt/vuln-labs
