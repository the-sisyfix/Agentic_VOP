# vuln-mixed-sample — test fixture for the COMBINED hardening path

**This image is deliberately vulnerable. Do not use it for anything real.**

It carries BOTH classes of remediable vulnerability so the hardening pipeline's
full decision path can be proven in one run:

- **OS-level CVEs** (Debian packages) → patched in place by **copa**.
- **pip dependency CVE** (`urllib3==1.26.5`) → fixed by the **dependency-bump
  rebuild** leg (pins forward to the trivy FixedVersion, rebuilds).

## Design notes

- Base is `debian:12` (bookworm) — a **supported** release, so the EOL
  fail-fast does not trigger and copa's apt mirror still serves updates.
- No `apt-get upgrade` in the Dockerfile, so the base snapshot's fixable OS
  CVEs remain present for copa to patch.
- The exact fixable-OS-CVE set depends on the base snapshot + trivy's DB, so
  **probe-scan before a full run**. If a probe shows no fixable OS crit/high,
  bump the base to an older bookworm point release (e.g. `debian:12.4`).

## Expected combined flow

intake (OS fixable > 0 AND dep fixable > 0) → copa patches OS → re-gate → dep
findings remain → rebuild leg bumps pip → final policy-zero gate → publish +
SBOM + residual + VEX → (auto_sign) sign + attest.
