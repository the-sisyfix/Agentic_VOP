# syntax=docker/dockerfile:1.7
# =============================================================================
# DELIBERATELY VULNERABLE mixed image — test fixture for the hardening
# pipeline's COMBINED remediation path:
#   - OS-level CVEs  → patched in place by copa (Copacetic)
#   - pip dependency → fixed by the dependency-bump rebuild leg
#
# Base: debian:12 (bookworm) — a CURRENT, SUPPORTED release, so (a) the EOL
# fail-fast does NOT trigger and (b) copa's apt mirror still serves packages.
# We deliberately DO NOT run `apt-get upgrade`, so whatever fixable OS CVEs
# exist in this base snapshot remain present for copa to patch. The vulnerable
# pip dependency (requirements.txt) provides the dependency leg.
#
# Base pinned to debian:12.0 (the FIRST bookworm point release, June 2023) —
# a SUPPORTED release (bookworm EOL 2028, so no EOL fail-fast; copa's mirror
# works) that is frozen at release and therefore carries ~2 years of
# subsequently-disclosed, now-FIXABLE OS CVEs for copa to patch. Probe on the
# box confirmed debian:12.0 → 44 fixable OS crit/high (5 CRITICAL, 39 HIGH),
# vs. 0 on the rolling `debian:12` tag (which is fully patched). The rolling
# tag gave copa nothing to do, so we pin the older snapshot on purpose.
#
# DO NOT use this image for anything real — it exists only to prove the leg.
# =============================================================================

FROM debian:12.0

ARG SOURCE_REPO="https://github.com/the-sisyfix/Agentic_VOP"
ARG SOURCE_REVISION="dev"
LABEL org.opencontainers.image.title="sisyfix-vuln-mixed-sample" \
      org.opencontainers.image.description="Deliberately vulnerable image with BOTH OS and pip CVEs for testing the combined copa+rebuild path (NOT for production)" \
      org.opencontainers.image.vendor="Sisyfix" \
      org.opencontainers.image.source="${SOURCE_REPO}" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /app

# Install python + pip (OS packages), then the vulnerable pip dependency.
# --break-system-packages: Debian 12's pip refuses a global install into the
# system interpreter (PEP 668 "externally managed") without it; fine for this
# throwaway fixture. No `apt-get upgrade` — keep the base's OS CVEs present.
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

COPY app.py .

RUN useradd --create-home --uid 10001 appuser
USER 10001:10001

ENTRYPOINT ["python3", "app.py"]
