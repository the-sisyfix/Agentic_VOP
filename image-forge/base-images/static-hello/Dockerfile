# syntax=docker/dockerfile:1.7
# =============================================================================
# Curated minimal/hardened base image — SAMPLE ("static-hello")
# =============================================================================
# This is the "base image we maintain" for the first slice of the hardened
# base-image supply chain. It is deliberately tiny but demonstrates the real
# hardening properties we want every curated image to have:
#
#   1. Multi-stage build — build tooling never reaches the final image.
#   2. Distroless-style final layer — no shell, no package manager, no libc
#      beyond what the binary needs. Pinned by DIGEST, not a floating tag,
#      so the build input is reproducible (matters for SLSA provenance).
#   3. Static binary — no dynamic linker, no OS package surface to patch.
#   4. Non-root runtime user.
#   5. OCI labels carrying source + purpose metadata (feeds provenance).
#
# The payload is intentionally trivial (a tiny static "hello" HTTP server)
# so the whole build -> scan -> SBOM -> sign/attest -> push -> verify pipeline
# can be proven end-to-end quickly. Swap the payload later; the hardening
# shape stays identical.
# =============================================================================

# --- Stage 1: build a fully static binary --------------------------------
# golang:1.25-alpine pinned by DIGEST (linux/arm64/v8), not a floating tag,
# so the build input is reproducible (a supply-chain requirement). Re-resolve
# when bumping the base: docker buildx imagetools inspect golang:1.25-alpine
FROM golang:1.25-alpine@sha256:ac555adf0aa5588ce5c707a2534b7d2d6f9f3938faa3560ab12eedeb6a18541f AS build

WORKDIR /src

# Build a static, position-independent binary with no cgo so the final image
# needs no libc / dynamic linker.
ENV CGO_ENABLED=0 \
    GOOS=linux

COPY server.go .

RUN go build \
      -trimpath \
      -ldflags="-s -w -buildid=" \
      -o /out/static-hello \
      ./server.go

# --- Stage 2: distroless-style final image -------------------------------
# gcr.io/distroless/static carries no shell and no package manager — minimal
# attack surface. Pinned by DIGEST (linux/arm64/v8); `nonroot` variant runs as
# uid 65532. Re-resolve when bumping: docker buildx imagetools inspect gcr.io/distroless/static:nonroot
FROM gcr.io/distroless/static:nonroot@sha256:dd804b6c91a33a478f9a56e5033f463007696c2934a73303eb186767226bc33d

# OCI image labels — provenance-friendly metadata. source/revision are build
# args so CI can stamp the exact commit without editing the Dockerfile.
ARG SOURCE_REPO="https://github.com/the-sisyfix/Agentic_VOP"
ARG SOURCE_REVISION="dev"
LABEL org.opencontainers.image.title="sisyfix-static-hello" \
      org.opencontainers.image.description="Curated minimal/hardened sample base image (distroless, static, non-root)" \
      org.opencontainers.image.vendor="Sisyfix" \
      org.opencontainers.image.source="${SOURCE_REPO}" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=build /out/static-hello /usr/local/bin/static-hello

# Already non-root via the `nonroot` base, but set it explicitly so the
# property survives a base change.
USER 65532:65532

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/static-hello"]
