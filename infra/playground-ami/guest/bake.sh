#!/bin/bash
# =============================================================================
# Playground golden image: bake script.
#
# Runs ON the builder instance, as root, sent over SSM by build_ami.py.
# Starts from the same frozen Ubuntu 20.04 base AMI that env1/env2/env3 use and
# installs the "ubuntu2004-labs" profile: appsec lab, CSPM lab template, four
# image labs, scanners, and the re-scan rule files.
#
# Differences from modules/lab-instance/user-data.sh.tpl (on purpose):
#   - Every lab file is fetched from GitHub at a PINNED commit ($COMMIT).
#   - Tool versions are pinned (see the block below).
#   - The CSPM lab is NOT applied. The template ships with placeholders and is
#     rendered per lease by /opt/playground/activate.sh with a unique prefix.
#   - The serverless lab is NOT included (see docs/known-gaps.md, KG-1).
#   - Any failure aborts the build (user-data only warned and carried on).
#
# Inputs (environment): COMMIT (required), ACTIVATE_B64 (required),
#                       MIN_FREE_GB (optional, default 4)
# =============================================================================
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

: "${COMMIT:?COMMIT is required}"
: "${ACTIVATE_B64:?ACTIVATE_B64 is required}"
MIN_FREE_GB="${MIN_FREE_GB:-4}"

REPO_RAW="https://raw.githubusercontent.com/the-sisyfix/Agentic_VOP/${COMMIT}"
LABS_RAW="${REPO_RAW}/infra/vuln-labs"

# ---- pinned tool versions (match what env3 runs today) ----
TERRAFORM_VERSION="1.7.5"
TRIVY_VERSION="v0.76.2"
SEMGREP_VERSION="1.99.0"
CHECKOV_VERSION="3.2.477"

log() { echo "[bake $(date -u +%H:%M:%S)] $*"; }
retry() { local n=$1; shift; local i; for i in $(seq 1 "$n"); do "$@" && return 0; log "retry $i/$n failed: $*"; sleep 10; done; return 1; }
fetch() { retry 3 curl -fsSL "$1" -o "$2"; }

log "commit=${COMMIT}"
log "host: $(. /etc/os-release && echo "$PRETTY_NAME") $(uname -m)"

# ---- 1. OS packages -------------------------------------------------------
log "apt packages"
retry 3 apt-get update -y
retry 3 apt-get install -y --fix-missing git curl unzip python3 python3-pip python3-venv nodejs npm docker.io

# SSM agent must already be present (it is how we got here).
log "ssm agent: $(systemctl is-active snap.amazon-ssm-agent.amazon-ssm-agent.service 2>/dev/null || systemctl is-active amazon-ssm-agent 2>/dev/null || echo unknown)"

systemctl enable docker
systemctl start docker
usermod -aG docker ubuntu || true

# Keep the host frozen so it does not drift from the scan source (same as user-data).
systemctl disable --now unattended-upgrades apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true

# ---- 2. AWS CLI v2 + Terraform -------------------------------------------
log "aws cli v2"
fetch "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" /tmp/awscliv2.zip
unzip -q -o /tmp/awscliv2.zip -d /tmp/
/tmp/aws/install --update || /tmp/aws/install
rm -rf /tmp/awscliv2.zip /tmp/aws
aws --version

log "terraform ${TERRAFORM_VERSION}"
fetch "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip" /tmp/terraform.zip
unzip -q -o /tmp/terraform.zip -d /usr/local/bin/
rm -f /tmp/terraform.zip
terraform version | head -1

# ---- 3. Scanners ----------------------------------------------------------
log "trivy ${TRIVY_VERSION}"
retry 3 sh -c "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin ${TRIVY_VERSION}"
trivy --version | head -1

log "semgrep ${SEMGREP_VERSION}"
retry 2 pip3 install --quiet "semgrep==${SEMGREP_VERSION}"
log "checkov ${CHECKOV_VERSION}"
rm -rf /usr/lib/python3/dist-packages/botocore /usr/lib/python3/dist-packages/boto3 /usr/lib/python3/dist-packages/s3transfer 2>/dev/null || true
pip3 install --quiet "argcomplete<3.6"
retry 2 pip3 install --quiet "checkov==${CHECKOV_VERSION}"
semgrep --version | tail -1
checkov --version | tail -1

# ---- 4. Labs --------------------------------------------------------------
log "appsec lab"
mkdir -p /opt/vuln-labs/appsec-lab/uploads /opt/vuln-labs/appsec-lab/data
echo "sensitive internal data" > /opt/vuln-labs/appsec-lab/data/secrets.txt
for f in app.py auth.py file_handler.py api_client.py utils.py config.py requirements.txt; do
  fetch "${LABS_RAW}/appsec-lab/${f}" "/opt/vuln-labs/appsec-lab/${f}"
done

build_image() {  # <lab-dir> <image-tag>
  local dir="/opt/vuln-labs/$1" tag="$2"
  local logf="/var/log/bake-build-${tag%%:*}.log"
  log "docker build ${tag}"
  cd "$dir"
  _attempt() { timeout 900 docker build -t "$tag" . >"$logf" 2>&1; }
  if ! retry 2 _attempt; then
    log "ERROR: docker build ${tag} failed. Last lines:"
    tail -40 "$logf"
    return 1
  fi
  log "built ${tag}"
}

log "infra image lab"
mkdir -p /opt/vuln-labs/infra-lab
fetch "${LABS_RAW}/infra-lab/Dockerfile" /opt/vuln-labs/infra-lab/Dockerfile
fetch "${LABS_RAW}/infra-lab/app.py" /opt/vuln-labs/infra-lab/app.py
build_image infra-lab vuln-lab-image:latest

log "java image lab"
mkdir -p /opt/vuln-labs/java-image-lab
fetch "${LABS_RAW}/java-image-lab/Dockerfile" /opt/vuln-labs/java-image-lab/Dockerfile
build_image java-image-lab vuln-java-image:latest

log "python image lab"
mkdir -p /opt/vuln-labs/python-image-lab
fetch "${LABS_RAW}/python-image-lab/Dockerfile" /opt/vuln-labs/python-image-lab/Dockerfile
build_image python-image-lab vuln-python-image:latest

log "php image lab"
mkdir -p /opt/vuln-labs/php-image-lab
fetch "${LABS_RAW}/php-image-lab/Dockerfile" /opt/vuln-labs/php-image-lab/Dockerfile
build_image php-image-lab vuln-php-image:latest

# CSPM lab: template only. Rendered per lease by activate.sh.
log "cspm lab template + terraform provider cache"
mkdir -p /opt/vuln-labs/cspm-lab
fetch "${LABS_RAW}/cspm-lab-template.tf" /opt/vuln-labs/cspm-lab/main.tf.template
TMP_TF="$(mktemp -d)"
sed -e "s/NAME_PLACEHOLDER/bake/g" -e "s/REGION_PLACEHOLDER/us-east-1/g" /opt/vuln-labs/cspm-lab/main.tf.template > "${TMP_TF}/main.tf"
( cd "$TMP_TF" && terraform init -backend=false -input=false -no-color >/dev/null )
cp -r "${TMP_TF}/.terraform" /opt/vuln-labs/cspm-lab/.terraform
cp "${TMP_TF}/.terraform.lock.hcl" /opt/vuln-labs/cspm-lab/.terraform.lock.hcl
rm -rf "$TMP_TF"

# Re-scan rule files. On the scan source these are written at runtime by
# scan-server.py into /opt/vuln-labs/results/. Extract them from that same file
# (pinned commit) so a playground has the same rule files, with no copy to drift.
log "semgrep rule files (extracted from scan-server.py)"
mkdir -p /opt/vuln-labs/results
fetch "${LABS_RAW}/scan-server.py" /tmp/scan-server.py
python3 - <<'PY'
import ast
import re
import sys

src = open("/tmp/scan-server.py", encoding="utf-8").read()
tree = ast.parse(src)

names = []   # (lineno, filename) from: rules_file = os.path.join(RESULTS_DIR, "<name>")
writes = []  # (lineno, text)     from: rf.write("<literal>")
for node in ast.walk(tree):
    if isinstance(node, ast.Assign) and len(node.targets) == 1 \
            and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "rules_file":
        call = node.value
        if isinstance(call, ast.Call) and call.args and isinstance(call.args[-1], ast.Constant) \
                and isinstance(call.args[-1].value, str) and call.args[-1].value.endswith("-rules.yaml"):
            names.append((node.lineno, call.args[-1].value))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "write" \
            and isinstance(node.func.value, ast.Name) and node.func.value.id == "rf" \
            and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
        writes.append((node.lineno, node.args[0].value))

names.sort()
writes.sort()
out = {}
for ln, text in writes:
    prior = [n for n in names if n[0] < ln]
    if prior:
        out[prior[-1][1]] = text
expected = {"semgrep-rules.yaml", "serverless-rules.yaml"}
if set(out) != expected:
    sys.exit(f"rule extraction failed: found {sorted(out)} expected {sorted(expected)}")
for name, text in out.items():
    if len(text) < 1000 or not text.lstrip().startswith("rules:"):
        sys.exit(f"rule file {name} looks wrong ({len(text)} bytes)")
    with open(f"/opt/vuln-labs/results/{name}", "w", encoding="utf-8") as fh:
        fh.write(text)
    print(f"wrote /opt/vuln-labs/results/{name} ({len(text)} bytes, {len(re.findall(r'- id:', text))} rules)")
PY
rm -f /tmp/scan-server.py

# ---- 5. Playground activation script (shipped by build_ami.py) -------------
log "activate.sh"
mkdir -p /opt/playground
echo "${ACTIVATE_B64}" | base64 -d > /opt/playground/activate.sh
chmod 755 /opt/playground/activate.sh

# ---- 6. Warm the Trivy DB (a stale DB is refreshed automatically on first use) ----
log "trivy db warm-up"
trivy image --download-db-only >/dev/null 2>&1 || log "WARN: trivy db warm-up returned non-zero (continuing)"

# ---- 7. Clean up so the image carries no builder state --------------------
log "cleanup"
docker image prune -f >/dev/null 2>&1 || true
apt-get clean
rm -rf /var/lib/apt/lists/* /tmp/* /root/.cache /root/.bash_history /home/ubuntu/.bash_history 2>/dev/null || true
journalctl --rotate >/dev/null 2>&1 && journalctl --vacuum-time=1s >/dev/null 2>&1 || true
chown -R ubuntu:ubuntu /opt/vuln-labs

# ---- 8. Space check, manifest, marker -------------------------------------
FREE_GB="$(df --output=avail -B1G / | tail -1 | tr -d ' ')"
USED_GB="$(df --output=used -B1G / | tail -1 | tr -d ' ')"
log "disk: used=${USED_GB}G free=${FREE_GB}G (minimum free required: ${MIN_FREE_GB}G)"
if [ "${FREE_GB}" -lt "${MIN_FREE_GB}" ]; then
  log "ERROR: not enough free space left in the image"
  exit 1
fi

python3 - <<PY
import json, subprocess, datetime
def sh(c): return subprocess.run(c, shell=True, capture_output=True, text=True).stdout.strip()
manifest = {
    "profile": "ubuntu2004-labs",
    "git_commit": "${COMMIT}",
    "built_at": datetime.datetime.utcnow().isoformat() + "Z",
    "labs": ["appsec", "cspm-template", "image-infra", "image-java", "image-python", "image-php"],
    "excluded": ["serverless (KG-1)"],
    "tools": {
        "terraform": sh("terraform version | head -1"),
        "trivy": sh("trivy --version | head -1"),
        "semgrep": sh("semgrep --version | tail -1"),
        "checkov": sh("checkov --version | tail -1"),
        "docker": sh("docker --version"),
        "aws": sh("aws --version"),
    },
    "images": sh("docker images --format '{{.Repository}}:{{.Tag}}' | grep -v none | sort").splitlines(),
    "disk_used_gb": ${USED_GB},
    "disk_free_gb": ${FREE_GB},
}
json.dump(manifest, open("/opt/playground/MANIFEST.json", "w"), indent=2)
print(json.dumps(manifest, indent=2))
PY
echo "Playground image baked (profile: ubuntu2004-labs, commit: ${COMMIT}) at $(date -u)" > /opt/vuln-labs/SETUP_COMPLETE
log "BAKE_OK"
