"""End-of-life (EOL) base-image detection — fail-fast, deterministic.

WHY: copa patches a client image by running the base distro's package manager
against the distro's LIVE security mirror. Once a distro release reaches EOL,
the distro stops publishing security updates and PURGES packages from the live
mirror (relocating them to an archive). copa then fails mid-patch with opaque
404s (observed live on debian:11 / bullseye after its 2026-08-31 EOL — the
`busybox-static ... 404 Not Found` wall).

Rather than let that surface as a cryptic mid-run failure, we DETECT an EOL base
up front (from trivy's detected OS) and FAIL FAST with a clear, honest message.

MVP scope (deliberately simple — see docs/image-forge/known-limitations.md):
  - A small, DATED, hardcoded table of known-EOL releases. Deterministic, no
    network call. Conservative: only releases we are CONFIDENT are EOL.
  - Unknown distro / unknown version / no OS detected → NOT flagged (fail-open
    on detection). Blocking a still-supported or unrecognized base would be
    worse than letting it proceed to the honest policy-zero gate; a genuinely
    unpatchable EOL base that we don't yet list will still fail at copa, just
    less cleanly. We expand the table as we learn.

LATER: swap the fail-fast for archive-mirror patching (point the build at
archive.debian.org etc.) so EOL images CAN be hardened. This module is the seam
where that decision is made.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Known-EOL table. Keyed by (normalized trivy OS family, major version string).
# Dates are the official EOL dates (incl. LTS where applicable) as of 2026-10;
# sourced from endoflife.date / distro vendors. Only releases we are confident
# are PAST EOL are listed — this table BLOCKS; a wrong entry would falsely block
# a supported image, so we keep it conservative and dated.
# ---------------------------------------------------------------------------
_EOL_TABLE: dict[tuple[str, str], str] = {
    # Debian — trivy family "debian", Name like "11.0" / "11.7" / "10.13".
    ("debian", "11"): "2026-08-31",  # bullseye (LTS ended)
    ("debian", "10"): "2024-06-30",  # buster
    ("debian", "9"): "2022-06-30",  # stretch
    ("debian", "8"): "2020-06-30",  # jessie
    ("debian", "7"): "2018-05-31",  # wheezy
    # Ubuntu — trivy family "ubuntu", Name like "18.04". Standard-support end
    # (not ESM; ESM is a paid add-on, not the live default mirror).
    ("ubuntu", "18.04"): "2023-05-31",
    ("ubuntu", "16.04"): "2021-04-30",
    ("ubuntu", "14.04"): "2019-04-30",
    # Alpine — trivy family "alpine", Name like "3.16". Alpine supports only
    # the few most-recent minor releases (~2 years each); older are EOL.
    ("alpine", "3.16"): "2024-05-23",
    ("alpine", "3.15"): "2023-11-01",
    ("alpine", "3.14"): "2023-05-01",
    ("alpine", "3.13"): "2022-11-01",
    ("alpine", "3.12"): "2022-05-01",
}


@dataclass(frozen=True)
class EOLVerdict:
    """Result of the EOL check."""

    is_eol: bool
    os_family: str = ""
    os_version: str = ""
    eol_date: str = ""  # the release's EOL date, when known/flagged
    reason: str = ""

    @property
    def message(self) -> str:
        if not self.is_eol:
            return ""
        return (
            f"Base image OS {self.os_family} {self.os_version} reached end-of-life "
            f"on {self.eol_date}. Its security mirror no longer serves package "
            f"updates, so in-place OS patching (copa) cannot complete — packages "
            f"have been purged/archived. Rebuild the image on a supported base, "
            f"or (future) enable archive-mirror hardening."
        )


def _major_version(os_name: str) -> str:
    """Extract the comparable version key from trivy's OS `Name`.

    Debian/Ubuntu/Alpine report names like "11.0", "18.04", "3.16". The EOL
    table is keyed per-distro: Debian by MAJOR only ("11"), Ubuntu/Alpine by
    MAJOR.MINOR ("18.04"/"3.16"). We return both forms and let the lookup try
    the most specific first.
    """
    return (os_name or "").strip()


def check_eol(os_family: str, os_name: str) -> EOLVerdict:
    """Deterministically decide whether a detected base OS is end-of-life.

    Pure function — no I/O. `os_family` / `os_name` come from trivy's
    Metadata.OS (surfaced via the intake scan). Fail-OPEN: anything not clearly
    in the EOL table returns is_eol=False.
    """
    fam = (os_family or "").strip().lower()
    name = _major_version(os_name)
    if not fam or not name:
        # No OS detected (scratch/distroless/unknown) → EOL check doesn't apply.
        return EOLVerdict(is_eol=False, os_family=fam, os_version=name)

    # Try the full name first (Ubuntu/Alpine use major.minor), then the leading
    # major (Debian uses major only). e.g. name "11.0" → try "11.0", then "11".
    candidates = [name]
    m = re.match(r"^(\d+)", name)
    if m and m.group(1) != name:
        candidates.append(m.group(1))

    for key in candidates:
        eol_date = _EOL_TABLE.get((fam, key))
        if eol_date:
            return EOLVerdict(
                is_eol=True,
                os_family=fam,
                os_version=name,
                eol_date=eol_date,
                reason=f"{fam} {key} is in the known-EOL table (EOL {eol_date})",
            )
    return EOLVerdict(is_eol=False, os_family=fam, os_version=name)
