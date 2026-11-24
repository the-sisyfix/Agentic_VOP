"""Generic user-supplied-endpoint connector.

Used when a tool has no purpose-built connector but the user has provided an
HTTP endpoint that returns scanner findings. The shape of the response is
intentionally permissive — Sub-Agent 1's LLM normalizes whatever comes back,
so this connector just has to deliver a `list[dict]` of raw rows.

Configuration (all under `connection_registry.metadata`):

  http_method        : "GET" (default) | "POST"
  headers            : dict[str, str] — sent verbatim; put auth here, e.g.
                          {"Authorization": "Bearer <token>"}
  body               : dict | list — JSON body for POST (ignored for GET)
  response_path      : dotted path to the array inside the response, e.g.
                          "data.findings". Optional — see "Locating the array".
  response_type      : "zip" to force ZIP handling regardless of Content-Type.
                          Optional — auto-detected from Content-Type if absent.
  extract_file_pattern : glob pattern for selecting a file inside a ZIP
                          archive, e.g. "*.sarif" or "report-*.json".
                          Defaults to "*.json".
  max_zip_bytes      : maximum allowed ZIP response size in bytes.
                          Defaults to 104857600 (100 MB).
  pkg_name_filter    : comma-separated package-name substrings; keep only
                          findings whose package name contains one. Optional.
  vuln_id_filter     : comma-separated vulnerability IDs (e.g.
                          "CVE-2026-109618,CVE-2026-109619"); keep only findings
                          whose vuln id matches one exactly (case-insensitive).
                          Optional.
  max_findings       : cap on how many raw findings are returned (head slice).
                          Applied after the filters above. Optional.

Locating the array uses the shared three-tier fallback in `_shape_utils`:
explicit path → common-key auto-detect → LLM inference (cached).

ZIP response support: when the endpoint returns a ZIP archive (detected via
Content-Type or forced via `response_type`), the connector extracts the first
file matching `extract_file_pattern` (alphabetical order), parses it as JSON
or SARIF based on extension, and feeds the result into the standard extraction
pipeline.

Watermark behavior: not enforced here — the user's endpoint typically can't
filter server-side without bespoke logic. Sub-Agent 1 still records its
own watermark for replay accounting; older rows get re-normalized but that's
cheap and idempotent at the issues layer.
"""

from __future__ import annotations

import fnmatch
import io
import json
import zipfile

import httpx

from ._shape_utils import (
    infer_response_path,
    parse_sarif,
    persist_response_path,
    try_simple_extract,
)
from ...crypto import decrypt_sensitive_fields
from ..http_utils import request_with_retry


_ZIP_CONTENT_TYPES = frozenset(
    {
        "application/zip",
        "application/x-zip-compressed",
        "application/octet-stream",
    }
)

_DEFAULT_EXTRACT_PATTERN = "*.json"
_DEFAULT_MAX_ZIP_BYTES = 100 * 1024 * 1024  # 100 MB


def fetch(
    registry_entry: dict,
    last_fetched_at: str | None = None,  # noqa: ARG001
    *,
    run_id: str | None = None,
) -> list[dict]:
    """Hit the user-defined endpoint and return raw rows for Sub-Agent 1."""
    endpoint = registry_entry.get("endpoint")
    if not endpoint:
        raise ValueError("user_endpoint connector: registry row has no endpoint")

    metadata = registry_entry.get("metadata") or {}
    # Decrypt sensitive fields (headers, body, credentials) for runtime use.
    # If encryption is not configured or fields are plaintext, this is a no-op.
    metadata = decrypt_sensitive_fields(metadata)

    method = (metadata.get("http_method") or "GET").upper()
    headers = metadata.get("headers") or {}
    body = metadata.get("body")
    response_path = metadata.get("response_path")
    timeout_sec = int(registry_entry.get("timeout_sec") or 60)

    with httpx.Client(timeout=timeout_sec, follow_redirects=True) as client:
        if method == "POST":
            resp = request_with_retry(
                client,
                "POST",
                endpoint,
                headers=headers,
                json=body,
                timeout=timeout_sec,
                run_id=run_id,
                agent="sub-agent-1",
            )
        else:
            resp = request_with_retry(
                client,
                "GET",
                endpoint,
                headers=headers,
                timeout=timeout_sec,
                run_id=run_id,
                agent="sub-agent-1",
            )

    if _is_zip_response(resp, metadata):
        return _handle_zip_response(resp, metadata, registry_entry, run_id)

    try:
        payload = resp.json()
    except ValueError as e:
        raise ValueError(
            f"user_endpoint connector: response from {endpoint} was not valid JSON"
        ) from e

    rows = _extract_with_fallbacks(payload, response_path, registry_entry, run_id)

    # Optional cap — limits how many raw findings Sub-Agent 1 will normalize.
    # Useful for scanners that produce thousands of rows (trivy rootfs can
    # emit 16K+ on an unpatched host) where only a small sample is needed
    # for the demo pipeline. Set `metadata.max_findings` on the registry row
    # to activate.
    #
    # Optional filter — `metadata.pkg_name_filter` is a comma-separated list
    # of package name substrings. When set, only findings whose PkgName/pkg_name
    # contains one of these substrings are kept. Applied BEFORE the cap so we
    # get the RIGHT findings, not just the first N. Use for image scanners where
    # we only want pip/npm/maven packages (fixable) and NOT OS packages (unfixable).
    pkg_filter_str = metadata.get("pkg_name_filter")
    if pkg_filter_str and isinstance(rows, list):
        filters = [f.strip().lower() for f in pkg_filter_str.split(",") if f.strip()]
        if filters:
            filtered = []
            for row in rows:
                pkg = ""
                if isinstance(row, dict):
                    pkg = (
                        row.get("PkgName") or row.get("pkg_name") or row.get("pkgName") or ""
                    ).lower()
                if any(f in pkg for f in filters):
                    filtered.append(row)
            rows = filtered

    # Optional filter — `metadata.vuln_id_filter` is a comma-separated list of
    # vulnerability IDs (e.g. "CVE-2026-109618,CVE-2026-109619"). When set, only
    # findings whose vuln id matches one of these (exact, case-insensitive) are
    # kept. Applied AFTER pkg_name_filter and BEFORE the cap, so the RIGHT
    # findings survive the max_findings slice. Matching is exact on the full id
    # (not substring) to avoid accidental collisions between CVE numbers. Use
    # for image scanners where only specific CVEs matter for the demo. When the
    # key is absent, this block is a no-op and behavior is unchanged.
    vuln_id_filter_str = metadata.get("vuln_id_filter")
    if vuln_id_filter_str and isinstance(rows, list):
        wanted = {v.strip().lower() for v in vuln_id_filter_str.split(",") if v.strip()}
        if wanted:
            filtered = []
            for row in rows:
                vid = ""
                if isinstance(row, dict):
                    vid = (
                        row.get("vuln_id")
                        or row.get("VulnerabilityID")
                        or row.get("vulnerability_id")
                        or row.get("cve_id")
                        or row.get("rule_id")  # semgrep / serverless
                        or row.get("check_id")  # checkov
                        or ""
                    )
                if str(vid).strip().lower() in wanted:
                    filtered.append(row)
            rows = filtered

    max_findings = metadata.get("max_findings")
    if max_findings and isinstance(rows, list) and len(rows) > int(max_findings):
        rows = rows[: int(max_findings)]

    return rows


# ----------------------------------------------------------------------------
# ZIP response handling
# ----------------------------------------------------------------------------


def _is_zip_response(resp: httpx.Response, metadata: dict) -> bool:
    """Determine whether the response should be treated as a ZIP archive."""
    if (metadata.get("response_type") or "").lower() == "zip":
        return True
    content_type = (resp.headers.get("content-type") or "").split(";")[0].strip().lower()
    return content_type in _ZIP_CONTENT_TYPES


def _handle_zip_response(
    resp: httpx.Response,
    metadata: dict,
    registry_entry: dict,
    run_id: str | None,
) -> list[dict]:
    """Extract a file from the ZIP response and parse it as JSON or SARIF."""
    max_zip_bytes = int(metadata.get("max_zip_bytes") or _DEFAULT_MAX_ZIP_BYTES)
    content = resp.content

    if len(content) > max_zip_bytes:
        raise ValueError(
            f"user_endpoint connector: ZIP response is {len(content)} bytes, "
            f"exceeding the maximum allowed size of {max_zip_bytes} bytes."
        )

    pattern = metadata.get("extract_file_pattern") or _DEFAULT_EXTRACT_PATTERN

    try:
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            file_content, filename = _extract_matching_file(zf, pattern)
    except zipfile.BadZipFile as e:
        raise ValueError(
            "user_endpoint connector: response was expected to be a ZIP archive "
            "but could not be read as one."
        ) from e

    if filename.lower().endswith(".sarif"):
        return parse_sarif(file_content)

    # Treat as JSON (covers .json and any other extension)
    try:
        payload = json.loads(file_content.decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, ValueError) as e:
        raise ValueError(
            f"user_endpoint connector: extracted file '{filename}' from ZIP is not valid JSON."
        ) from e

    response_path = metadata.get("response_path")
    return _extract_with_fallbacks(payload, response_path, registry_entry, run_id)


def _extract_matching_file(zf: zipfile.ZipFile, pattern: str) -> tuple[bytes, str]:
    """Find the first file (alphabetically) matching the glob pattern inside
    the ZIP and return its content and name.
    """
    # Filter out directories and match against the pattern
    candidates = sorted(
        name
        for name in zf.namelist()
        if not name.endswith("/") and fnmatch.fnmatch(name.split("/")[-1], pattern)
    )

    if not candidates:
        available = [n for n in zf.namelist() if not n.endswith("/")]
        raise ValueError(
            f"user_endpoint connector: no file matching pattern '{pattern}' "
            f"found in ZIP archive. Available files: {available[:20]}"
        )

    chosen = candidates[0]
    return zf.read(chosen), chosen


# ----------------------------------------------------------------------------
# JSON extraction fallback chain (unchanged)
# ----------------------------------------------------------------------------


def _extract_with_fallbacks(
    payload,
    response_path: str | None,
    registry_entry: dict,
    run_id: str | None,
) -> list[dict]:
    """Tier 1+2+3 fallback chain shared with the file_upload connector."""
    rows = try_simple_extract(payload, response_path)

    if rows is None and run_id and not response_path:
        inferred = infer_response_path(payload, run_id)
        if inferred is not None:
            rows = try_simple_extract(payload, inferred or None)
            if rows is not None:
                tool = registry_entry.get("tool")
                if tool:
                    persist_response_path(tool, inferred)

    if rows is None:
        rows = [payload] if isinstance(payload, dict) else []

    return rows
