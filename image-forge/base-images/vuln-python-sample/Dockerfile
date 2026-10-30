# syntax=docker/dockerfile:1.7
# =============================================================================
# DELIBERATELY VULNERABLE Python image — test fixture for the hardening
# pipeline's dependency-bump (rebuild) leg.
#
# Purpose: prove that the pipeline can remediate LANGUAGE/dependency CVEs that
# copa (OS-package patcher) cannot touch. copa handles the Debian base; the
# vulnerable PIP packages in requirements.txt are fixed by the rebuild leg,
# which deterministically pins each to trivy's FixedVersion and rebuilds.
#
# The base is a CURRENT, supported Debian (bookworm) so the OS side is clean/
# patchable and the DEPENDENCY findings are the star of the test. NOT a floating
# tag for the deps — they are pinned-old on purpose (see requirements.txt).
#
# DO NOT run this anywhere real. It exists only to exercise the rebuild leg.
# =============================================================================

FROM python:3.12-slim-bookworm

# OCI labels — provenance-friendly metadata (mirrors the static-hello sample).
ARG SOURCE_REPO="https://github.com/the-sisyfix/Agentic_VOP"
ARG SOURCE_REVISION="dev"
LABEL org.opencontainers.image.title="sisyfix-vuln-python-sample" \
      org.opencontainers.image.description="Deliberately vulnerable Python image for testing the dependency-bump rebuild leg (NOT for production)" \
      org.opencontainers.image.vendor="Sisyfix" \
      org.opencontainers.image.source="${SOURCE_REPO}" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /app

# Install the (deliberately old) declared dependencies so trivy detects them in
# the built image as pip lang-pkgs findings. --no-cache-dir keeps the layer lean.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Trivial payload — the app itself is irrelevant; the dependencies are the point.
COPY app.py .

# Non-root runtime (hardening hygiene; survives a base change).
RUN useradd --create-home --uid 10001 appuser
USER 10001:10001

ENTRYPOINT ["python", "app.py"]
