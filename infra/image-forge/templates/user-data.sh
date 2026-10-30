#!/bin/bash
set -euo pipefail

# ==============================================================================
# image-forge build box bootstrap (user-data)
# Installs the supply-chain toolchain used to build, scan, SBOM, sign and
# attest hardened base images:
#   - Docker Engine + buildx
#   - trivy  (vulnerability scan gate)
#   - syft   (SBOM generation)
#   - cosign (signing + SLSA provenance attestation)
# Template variables: aws_region, cosign_version, syft_version, trivy_version
# Target arch: ARM64 (Graviton / t4g)
# Version: 2026-09-29-v1
# ==============================================================================

LOG_FILE="/var/log/user-data.log"

log() {
  local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $${1}"
  echo "$${msg}" | tee -a "$${LOG_FILE}"
}

fail() {
  local step="$${1}"
  local err="$${2:-unknown error}"
  log "FATAL: Step '$${step}' failed — $${err}"
  exit 1
}

run_step() {
  local step_name="$${1}"
  shift
  log "START: $${step_name}"
  if "$@" >> "$${LOG_FILE}" 2>&1; then
    log "DONE: $${step_name}"
  else
    fail "$${step_name}" "exit code $?"
  fi
}

# ==============================================================================
# Step 1: Base packages + AWS CLI v2 (ARM64)
# ==============================================================================
install_base() {
  apt-get update -y
  apt-get install -y unzip curl ca-certificates gnupg lsb-release jq
  curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip" -o /tmp/awscliv2.zip
  unzip -qo /tmp/awscliv2.zip -d /tmp
  /tmp/aws/install --update
  rm -rf /tmp/awscliv2.zip /tmp/aws
  aws --version
}
run_step "Install base packages + AWS CLI v2" install_base

# ==============================================================================
# Step 2: Docker Engine + buildx + compose plugin
# ==============================================================================
install_docker() {
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
    gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg

  local arch
  arch=$(dpkg --print-architecture)
  local codename
  codename=$(lsb_release -cs)
  echo "deb [arch=$${arch} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $${codename} stable" | \
    tee /etc/apt/sources.list.d/docker.list > /dev/null

  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

  systemctl enable docker
  systemctl start docker
  usermod -aG docker ubuntu
  docker --version
  docker buildx version
}
run_step "Install Docker Engine + buildx" install_docker

# ==============================================================================
# Step 3: trivy (vulnerability scan gate)
# ==============================================================================
# Use the vendor-official install script. It auto-detects OS/arch and resolves
# the correct GitHub release asset, so we don't hand-build (and mis-build) the
# ARM64 filename. Version is pinned via the trailing tag argument (v<version>)
# for reproducibility.
install_trivy() {
  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin "v${trivy_version}"
  trivy --version
}
run_step "Install trivy v${trivy_version}" install_trivy

# ==============================================================================
# Step 4: syft (SBOM generation)
# ==============================================================================
# Vendor-official install script, same rationale as trivy: it resolves the
# right asset for linux/arm64. Version pinned via the trailing tag argument.
install_syft() {
  curl -sfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
    | sh -s -- -b /usr/local/bin "v${syft_version}"
  syft version
}
run_step "Install syft v${syft_version}" install_syft

# ==============================================================================
# Step 5: cosign (signing + SLSA provenance attestation)
# ==============================================================================
# cosign ships a single static arm64 binary per release. Pin the version via
# the release tag. (cosign has no vendor install script; the versioned release
# URL is the documented binary install path.)
install_cosign() {
  local ver="${cosign_version}"
  curl -fsSL "https://github.com/sigstore/cosign/releases/download/v$${ver}/cosign-linux-arm64" -o /tmp/cosign
  install -m 0755 /tmp/cosign /usr/local/bin/cosign
  rm -f /tmp/cosign
  cosign version
}
run_step "Install cosign v${cosign_version}" install_cosign

# ==============================================================================
# Step 6: copa (Copacetic — in-place OS-package patching)
# ==============================================================================
# copa ships a tarball per release/arch: copa_<ver>_linux_arm64.tar.gz.
# It patches an existing image BY REFERENCE using a trivy report + BuildKit.
install_copa() {
  local ver="${copa_version}"
  local tarball="copa_$${ver}_linux_arm64.tar.gz"
  curl -fsSL "https://github.com/project-copacetic/copacetic/releases/download/v$${ver}/$${tarball}" -o /tmp/copa.tar.gz
  tar -xzf /tmp/copa.tar.gz -C /tmp copa
  install -m 0755 /tmp/copa /usr/local/bin/copa
  rm -f /tmp/copa.tar.gz /tmp/copa
  copa --version
}
run_step "Install copa v${copa_version}" install_copa

# ==============================================================================
# Step 7: Pre-pull BuildKit image (copa needs a buildkitd endpoint)
# ==============================================================================
# copa drives BuildKit to apply the patch layer. The hardening strategy starts
# a moby/buildkit container at run time (ensure_buildkit); pre-pulling the image
# here makes the first patch run fast and avoids a mid-run pull failure.
prepull_buildkit() {
  docker pull ${buildkit_image}
}
run_step "Pre-pull BuildKit image ${buildkit_image}" prepull_buildkit

# ==============================================================================
# Step 8: Completion marker
# ==============================================================================
write_marker() {
  cat > /opt/IMAGE_FORGE_READY <<EOF
image-forge build box bootstrap completed at $(date -u '+%Y-%m-%dT%H:%M:%SZ')
region=${aws_region}
docker=$(docker --version 2>/dev/null || echo missing)
trivy=$(trivy --version 2>/dev/null | head -1 || echo missing)
syft=$(syft version 2>/dev/null | head -1 || echo missing)
cosign=$(cosign version 2>/dev/null | head -1 || echo missing)
copa=$(copa --version 2>/dev/null | head -1 || echo missing)
buildkit_image=${buildkit_image}
EOF
  chmod 0644 /opt/IMAGE_FORGE_READY
}
run_step "Write IMAGE_FORGE_READY marker" write_marker

log "=== image-forge build box bootstrap finished successfully ==="
