# Intentionally outdated PHP runtime for the Trivy Image (PHP) scan target.
#
# WHY debian:12 + apt-pinned php8.2: the PHP2Shell CVEs (CVE-2026-109618 /
# CVE-2026-109619) are flaws in the PHP engine, detected by Trivy as Debian
# OS-level packages (php8.2-*). The official `php:*` Docker images compile PHP
# from source, so PHP never appears in dpkg and Trivy cannot match it against
# the Debian security tracker. Installing php via apt makes php8.2-* real
# dpkg packages that Trivy flags.
#
# WHY the snapshot repo + version pins: pinning php8.2 to 8.2.28 (a pre-patch
# release, below the fixed 8.2.35) makes the image deterministically vulnerable
# every rebuild, instead of depending on whatever the live mirror serves today.
# The default sources are removed so a plain rebuild cannot silently pull the
# patched 8.2.35 from bookworm-security.
#
# This mirrors a real stale enterprise PHP container: Debian base + apt PHP that
# has drifted out of date. The fix (discovered by SA-3, not encoded here) is to
# upgrade the php8.2 packages to the Debian-patched version and rebuild.
FROM debian:12

# apt retry logic: snapshot.debian.org can be slow or rate-limited; retry the
# update/install a few times before giving up (matches the user-data apt retry
# pattern used elsewhere in the lab).
RUN set -eux; \
    rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources 2>/dev/null || true; \
    echo 'deb [trusted=yes] http://snapshot.debian.org/archive/debian/20250601T000000Z/ bookworm main' > /etc/apt/sources.list; \
    echo 'deb [trusted=yes] http://snapshot.debian.org/archive/debian-security/20250601T000000Z/ bookworm-security main' >> /etc/apt/sources.list; \
    printf 'Acquire::Check-Valid-Until "false";\nAcquire::Retries "3";\n' > /etc/apt/apt.conf.d/99snapshot; \
    for i in 1 2 3 4 5; do apt-get update && break || { echo "apt-get update retry $i"; sleep 10; }; done; \
    for i in 1 2 3 4 5; do \
      apt-get install -y --allow-downgrades \
        php8.2-cli=8.2.28-1~deb12u1 \
        php8.2-common=8.2.28-1~deb12u1 \
        php8.2-opcache=8.2.28-1~deb12u1 \
        php8.2-readline=8.2.28-1~deb12u1 \
      && break || { echo "apt-get install retry $i"; sleep 10; }; \
    done; \
    rm -rf /var/lib/apt/lists/*

# VULN: Running as root (no USER instruction)
# VULN: No HEALTHCHECK defined
# Keep the container short-lived friendly — print the version and exit. The
# scan target only needs the image to exist for `trivy image` to scan it;
# there is no long-running service to start (avoids a foreground-daemon hang).
CMD ["php", "--version"]
