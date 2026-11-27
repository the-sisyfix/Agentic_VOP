"""Sub-Agent 1 — Smart Connector (LangChain-powered normalization).

Per run:
  1. Read the connector's last_fetched_at watermark from connection_registry.
  2. Fetch raw rows from the scanner (incremental, via connectors/).
  3. Persist all raw rows verbatim into raw_findings (audit trail).
  4. For each persisted raw row:
       a. Call ChatOpenAI.with_structured_output(LLMNormalizedIssue).
       b. Insert canonical Issue with raw_finding_id pointing back to step 3.
  5. On success, advance the watermark.

Why split raw and canonical: replay (re-normalize without re-fetching), audit
(byte-exact what the scanner returned), separation of concerns.

LangChain migration notes:
  - The raw OpenAI SDK function call is replaced by ChatOpenAI's
    `.with_structured_output(LLMNormalizedIssue)`, which binds the Pydantic
    schema as the response shape and validates automatically.
  - Multi-stage JSON repair is no longer required for the happy path —
    LangChain handles structured output internally. We keep the
    temperature-escalation retry pattern (0.1 → 0.6 → 0.9) for robustness
    against rare validation failures.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from ..config import settings
from ..db import supabase_admin
from ..leases import LeaseTimeout, hold_lease
from ..models import LLMNormalizedIssue
from .connectors import fetch_raw_rows
from .llm import invoke_structured_with_retry
from .trace import RunCancelledError, emit_trace, is_cancellation_requested


def _sanitize(value: Any) -> Any:
    """Recursively strip Postgres-incompatible NUL bytes (\\u0000) from a JSON-like structure.

    Some scanners (and downstream LLM output) can include \\x00 in description text;
    Postgres' text/jsonb types reject it with "unsupported Unicode escape sequence".
    """
    if isinstance(value, str):
        return value.replace("\x00", "")
    if isinstance(value, dict):
        return {k: _sanitize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize(v) for v in value]
    return value


def parse_cvss_vector(vector: str | None) -> tuple[float | None, str | None]:
    """Deterministically compute (base_score, version) from a CVSS vector string.

    Handles V2, V3.0, V3.1, V4.0 vectors. Used as a post-LLM step so the LLM
    only has to *recognize* a vector in the raw row (cheap) — the actual
    multi-factor subscore math is done by the `cvss` library (reliable).

    Returns (None, None) when the input is empty, malformed, or an unknown
    version. Callers should treat this as "leave cvss_score / cvss_version
    alone" and let downstream enrichment (NVD) try to fill them instead.
    """
    if not vector or not isinstance(vector, str):
        return None, None
    vector = vector.strip()
    if not vector:
        return None, None

    try:
        if vector.startswith("CVSS:4"):
            from cvss import CVSS4

            return float(CVSS4(vector).base_score), "4.0"
        if vector.startswith("CVSS:3.1"):
            from cvss import CVSS3

            return float(CVSS3(vector).base_score), "3.1"
        if vector.startswith("CVSS:3"):
            from cvss import CVSS3

            return float(CVSS3(vector).base_score), "3.0"
        # Bare V2 vectors look like "AV:N/AC:L/Au:N/C:P/I:P/A:P" — no CVSS: prefix.
        if vector.startswith(("AV:", "(AV:")):
            from cvss import CVSS2

            return float(CVSS2(vector).base_score), "2.0"
    except Exception:  # noqa: BLE001 — any parse failure → leave fields null
        return None, None

    return None, None


# Preference order for picking the best CVSS vector when a scanner emits multiple
# versions for the same finding (NVD's `metrics` often has V31 + V2; OSV starts
# shipping V4 alongside V3.1). Higher number wins.
_CVSS_VERSION_RANK = {"4.0": 4, "3.1": 3, "3.0": 2, "2.0": 1}


def pick_best_cvss_vector(vectors: list[str | None]) -> str | None:
    """From a list of CVSS vector strings, return the highest-version one.

    Preference: V4 > V3.1 > V3.0 > V2. Vectors that fail to parse are ignored.
    Returns None when no input parses cleanly.
    """
    best_rank = 0
    best_vector: str | None = None
    for v in vectors:
        if not v:
            continue
        _, version = parse_cvss_vector(v)
        if version is None:
            continue
        rank = _CVSS_VERSION_RANK.get(version, 0)
        if rank > best_rank:
            best_rank = rank
            best_vector = v
    return best_vector


def extract_all_vectors_from_raw(raw: dict) -> list[str]:
    """Find every CVSS vector string in a raw scanner payload.

    Walks the common shapes — top-level fields, OSV's severity[].score array,
    NVD's metrics.cvssMetricV{40,31,30,2}[].cvssData.vectorString, and nested
    cvss/cvss3 objects. Returns all distinct vectors found so callers can
    `pick_best_cvss_vector(...)` to choose the strongest one.
    """

    def _looks_like_vector(v) -> bool:
        if not isinstance(v, str):
            return False
        s = v.strip()
        return s.startswith(("CVSS:3", "CVSS:4", "CVSS:2", "AV:", "(AV:"))

    found: list[str] = []
    seen: set[str] = set()

    def _add(v):
        if _looks_like_vector(v):
            s = v.strip()
            if s not in seen:
                seen.add(s)
                found.append(s)

    if not isinstance(raw, dict):
        return found

    def _as_list(v) -> list:
        # Some scanners ship `severity` as a string ("HIGH") instead of a list
        # of dicts — guard so the caller doesn't crash on non-iterables.
        return v if isinstance(v, list) else []

    # 1. Top-level keys.
    for key in ("vector", "vector_string", "vectorString", "cvss_vector"):
        _add(raw.get(key))

    # 2. OSV-style severity arrays (severity / severity_entries).
    for entry in _as_list(raw.get("severity")) + _as_list(raw.get("severity_entries")):
        if isinstance(entry, dict):
            _add(entry.get("score"))
            _add(entry.get("vector"))
            _add(entry.get("vectorString"))

    # 3. NVD-style metrics.cvssMetricV*[].cvssData.vectorString.
    metrics = raw.get("metrics") if isinstance(raw.get("metrics"), dict) else {}
    for mkey in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for entry in _as_list(metrics.get(mkey)):
            cdata = entry.get("cvssData") if isinstance(entry, dict) else None
            if isinstance(cdata, dict):
                _add(cdata.get("vectorString"))

    # 4. Nested cvss / cvss3 / cvss40 objects.
    for parent_key in ("cvss", "cvss3", "cvss31", "cvss40", "cvssV3", "cvssV2"):
        parent = raw.get(parent_key)
        if isinstance(parent, dict):
            for key in ("vector", "vectorString", "vector_string"):
                _add(parent.get(key))

    return found


def _advance_watermark(sb, tool: str, new_watermark: str) -> None:
    """Move connection_registry.last_fetched_at forward to `new_watermark`, never back.

    The per-scanner lease in run_fetch already keeps two fetches from
    overlapping; this conditional UPDATE is the backstop in case one does
    (e.g. a lease lost to a long stall): a run that started earlier but
    finished later can't roll the watermark back over a newer one.
    """
    sb.table("connection_registry").update({"last_fetched_at": new_watermark}).eq("tool", tool).or_(
        f'last_fetched_at.is.null,last_fetched_at.lt."{new_watermark}"'
    ).execute()


def run_fetch(run_id: str, tool: str, registry_entry: dict) -> tuple[int, dict]:
    """Read raw rows from the connector, normalize each via the LLM, insert canonical Issues.

    Returns (count of issues inserted, token_totals dict).

    Only one fetch per scanner runs at a time (lease `sa1:<schema>:<tool>`).
    A second trigger for the same scanner waits for the first to finish,
    then re-reads the watermark the first one advanced and fetches only
    what's newer — usually nothing — instead of fetching the same window
    twice.

    Note on token totals: LangChain emits token usage via the
    `_TokenUsageCallback` in `llm.py` (one TOKEN_USAGE trace event per
    LLM call). The aggregate returned here is best-effort and will be
    zero unless the callback also writes to a sidecar — to keep the
    public contract with master.py the same, we return zeros and
    rely on the per-call TOKEN_USAGE events for observability.
    """
    sb = supabase_admin()

    def _on_wait(holder: dict | None) -> None:
        emit_trace(
            run_id,
            "sub-agent-1",
            "MESSAGE",
            f"⏳ Another run is already fetching from {tool} "
            f"({(holder or {}).get('label') or 'unknown run'}). Waiting for it to finish "
            f"so the two don't fetch the same rows…",
        )

    def _check_abort() -> None:
        if is_cancellation_requested(run_id):
            raise RunCancelledError(f"Run cancelled while waiting to fetch from {tool}")

    try:
        with hold_lease(
            f"sa1:{settings.db_schema}:{tool}",
            label=f"agent_run {run_id}",
            on_wait=_on_wait,
            check_abort=_check_abort,
        ) as waited_s:
            if waited_s:
                # The other run advanced the watermark — fetch from there, not
                # from the stale copy master.py read before we waited.
                fresh = (
                    sb.table("connection_registry")
                    .select("last_fetched_at")
                    .eq("tool", tool)
                    .limit(1)
                    .execute()
                    .data
                    or []
                )
                if fresh:
                    registry_entry = {**registry_entry, **fresh[0]}
            return _run_fetch_locked(sb, run_id, tool, registry_entry)
    except LeaseTimeout as e:
        emit_trace(run_id, "sub-agent-1", "ERROR", f"Gave up waiting to fetch from {tool}: {e}")
        raise


def _run_fetch_locked(sb, run_id: str, tool: str, registry_entry: dict) -> tuple[int, dict]:
    """Body of run_fetch — executed only while the scanner's SA-1 lease is held."""
    last_fetched_at = registry_entry.get("last_fetched_at")
    fetch_started_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")

    metadata = registry_entry.get("metadata") or {}
    connector_type = metadata.get("connector_type", "supabase_stub")

    mode = "incremental" if last_fetched_at else "initial"
    emit_trace(
        run_id,
        "sub-agent-1",
        "MESSAGE",
        f"Connecting to {tool} via connector={connector_type} "
        f"({mode}{f' — since {last_fetched_at}' if last_fetched_at else ' — fetching all rows'})",
    )

    # ------ Step 1: fetch raw rows from the connector ------
    try:
        raw_rows = fetch_raw_rows(tool, registry_entry, last_fetched_at, run_id=run_id)
    except Exception as e:
        emit_trace(
            run_id,
            "sub-agent-1",
            "ERROR",
            f"Connector failed for {tool} ({type(e).__name__}): {str(e)[:300]}",
        )
        raise

    emit_trace(
        run_id,
        "sub-agent-1",
        "MESSAGE",
        f"Fetched {len(raw_rows)} raw rows from {tool}",
    )

    if not raw_rows:
        # Still advance the watermark so the next run also looks for new rows.
        _advance_watermark(sb, tool, fetch_started_at)

        emit_trace(
            run_id,
            "sub-agent-1",
            "DONE",
            "FETCH_DONE — no new rows since last fetch",
            payload={
                "from": "sub-agent-1",
                "status": "FETCH_DONE",
                "scan_id": run_id,
                "records_fetched": 0,
                "records_persisted": 0,
                "records_normalized": 0,
                "tool_used": tool,
                "watermark_before": last_fetched_at,
                "watermark_after": fetch_started_at,
            },
        )
        return 0, {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

    # ------ Step 2: persist raw rows verbatim into raw_findings ------
    raw_inserts = [
        {"source": tool, "agent_run_id": run_id, "raw": _sanitize(row)} for row in raw_rows
    ]
    raw_insert_result = sb.table("raw_findings").insert(raw_inserts).execute()
    persisted_raws: list[dict] = raw_insert_result.data or []

    emit_trace(
        run_id,
        "sub-agent-1",
        "MESSAGE",
        f"Persisted {len(persisted_raws)} raw rows to raw_findings",
    )

    # Generic Sub-Agent 1 prompt (one prompt for all scanners)
    prompt_row = (
        sb.table("prompt_db")
        .select("*")
        .eq("agent", "sub-agent-1")
        .eq("is_active", True)
        .single()
        .execute()
        .data
    )

    # Per-scanner mapping rules from the Schema & Mapping DB
    mapping_rules = (
        sb.table("schema_mapping")
        .select("source_field,canonical_field,transform,notes")
        .eq("scanner", tool)
        .execute()
        .data
        or []
    )

    emit_trace(
        run_id,
        "sub-agent-1",
        "MESSAGE",
        f"Loaded prompt {prompt_row['agent']}@{prompt_row['version']} ({prompt_row['model']}) "
        f"+ {len(mapping_rules)} mapping rule(s) for {tool}",
    )

    # ------ Step 3: normalize each persisted raw row -> issues (parallel) ------
    inserted = 0
    failed = 0
    failure_examples: list[str] = []

    workers = max(1, int(settings.llm_parallel_workers or 10))
    emit_trace(
        run_id,
        "sub-agent-1",
        "MESSAGE",
        f"Normalizing {len(persisted_raws)} row(s)…",
    )

    def _process_one(persisted: dict) -> dict:
        """Per-row task: LLM-normalize then insert. Runs inside a worker thread."""
        # Cancellation checkpoint — skip remaining rows once a stop is requested.
        # Lightweight DB poll per row; cheap compared to the LLM call below.
        if is_cancellation_requested(run_id):
            raise RunCancelledError(f"Skipping row {persisted['id']} — run cancelled")
        raw_finding_id = persisted["id"]
        raw = persisted["raw"]
        llm_issue = _normalize_row(run_id, prompt_row, tool, raw, mapping_rules)
        # Authoritative: the source on an issue must match the tool that
        # produced it, regardless of what the LLM returned. This is the
        # single source of truth for "where this finding came from".
        llm_issue.source = tool
        # CVSS resolution — combines deterministic raw scan + the LLM's pick,
        # then chooses the highest-version vector available (V4 > V3.1 > V3.0 > V2).
        # Runs for every scanner so any future tool that ships any CVSS vector
        # gets the best one without per-connector work.
        candidate_vectors = extract_all_vectors_from_raw(raw)
        if llm_issue.cvss_vector:
            candidate_vectors.append(llm_issue.cvss_vector)
        best_vector = pick_best_cvss_vector(candidate_vectors)
        if best_vector:
            llm_issue.cvss_vector = best_vector
        # Compute numeric score + version from the chosen vector when missing.
        if llm_issue.cvss_vector and (
            llm_issue.cvss_score is None or llm_issue.cvss_version is None
        ):
            score, version = parse_cvss_vector(llm_issue.cvss_vector)
            if score is not None and llm_issue.cvss_score is None:
                llm_issue.cvss_score = score
            if version is not None and llm_issue.cvss_version is None:
                llm_issue.cvss_version = version
        _insert_issue(sb, llm_issue, raw_finding_id, run_id)
        return {"raw_finding_id": raw_finding_id}

    cancelled = False
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(_process_one, p): p for p in persisted_raws}
        completed = 0
        for future in as_completed(futures):
            persisted = futures[future]
            completed += 1
            try:
                future.result()
                inserted += 1
            except RunCancelledError:
                # User clicked Stop — drain remaining futures but skip work.
                cancelled = True
            except Exception as e:
                failed += 1
                if len(failure_examples) < 3:
                    failure_examples.append(f"{type(e).__name__}: {e}")
                    emit_trace(
                        run_id,
                        "sub-agent-1",
                        "ERROR",
                        f"Row {persisted['id']} failed ({type(e).__name__}): {str(e)[:400]}",
                        payload={
                            "raw_finding_id": persisted["id"],
                            "exception_type": type(e).__name__,
                            "exception_message": str(e)[:1000],
                        },
                    )

            if completed % 20 == 0 and completed < len(persisted_raws):
                emit_trace(
                    run_id,
                    "sub-agent-1",
                    "MESSAGE",
                    f"Processed {completed}/{len(persisted_raws)} rows "
                    f"({inserted} succeeded, {failed} failed so far)",
                )

    if cancelled:
        emit_trace(
            run_id,
            "sub-agent-1",
            "MESSAGE",
            f"Cancellation detected — stopped after {inserted} normalized row(s) "
            f"(remaining rows skipped, will be wiped by cancel endpoint)",
        )
        raise RunCancelledError("Sub-Agent 1 stopped due to user cancellation")

    if failed:
        emit_trace(
            run_id,
            "sub-agent-1",
            "MESSAGE",
            f"Completed normalization: {inserted} succeeded, {failed} failed. "
            f"Examples: {'; '.join(failure_examples)}",
        )
    else:
        emit_trace(
            run_id,
            "sub-agent-1",
            "MESSAGE",
            f"Completed normalization: {inserted}/{len(persisted_raws)} rows normalized cleanly",
        )

    # Advance watermark so the next run only fetches rows created after this point.
    # Only do this if we successfully processed at least some rows — if the entire
    # batch failed, leave the watermark alone so a retry sees the same data.
    if inserted > 0:
        _advance_watermark(sb, tool, fetch_started_at)

    emit_trace(
        run_id,
        "sub-agent-1",
        "DONE",
        f"FETCH_DONE — {len(persisted_raws)} raw / {inserted} canonical",
        payload={
            "from": "sub-agent-1",
            "status": "FETCH_DONE",
            "scan_id": run_id,
            "records_fetched": len(raw_rows),
            "records_persisted": len(persisted_raws),
            "records_normalized": inserted,
            "records_failed": failed,
            "tool_used": tool,
            "data_pointer_raw": f"pg://raw_findings?agent_run_id={run_id}",
            "data_pointer_canonical": f"pg://issues?agent_run_id={run_id}",
            "correlation_id": f"corr-{run_id[:8]}",
        },
    )

    # Token totals are accumulated in memory by _TokenUsageCallback on every
    # LLM call — no need to scan agent_trace_events here. The in-memory
    # accumulator in llm.py is the single source of truth; _summarize_node
    # in master.py reads it via get_accumulated_tokens() at run end.
    return inserted, {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}


def _normalize_row(
    run_id: str,
    prompt_row: dict,
    tool: str,
    raw_row: dict,
    mapping_rules: list[dict],
) -> LLMNormalizedIssue:
    """Call ChatOpenAI with structured output to normalize one raw row.

    Tiered retry — escalate temperature first (cheap), then escalate the model
    on the final attempt (smarter) for rows the small model can't handle.
    """
    params = prompt_row.get("parameters") or {}
    base_temp = float(params.get("temperature", 0.1))
    max_tokens = int(params.get("max_tokens", 2000))
    primary_model = prompt_row["model"]
    fallback_model = params.get("fallback_model", "gpt-4o")

    user_payload = {
        "source_scanner": tool,
        "raw_row": raw_row,
        "mapping_rules": mapping_rules,
    }

    # Per-attempt completion budget grows on each retry — gnarly OSV advisories
    # (e.g. 10k-token prompts with huge affected-version arrays) sometimes need
    # more room than the base config to finish the structured-output tool call.
    return invoke_structured_with_retry(
        run_id=run_id,
        agent="sub-agent-1",
        schema=LLMNormalizedIssue,
        messages=[
            SystemMessage(content=prompt_row["prompt_text"]),
            HumanMessage(content=str(user_payload)),
        ],
        attempts=[
            (base_temp, primary_model, max_tokens),
            (0.6, primary_model, max_tokens + 2000),
            (0.3, fallback_model, max_tokens + 4000),
        ],
    )


def _insert_issue(sb, llm_issue: LLMNormalizedIssue, raw_finding_id: int, run_id: str) -> None:
    """Insert one new canonical Issue. Points back to the raw_findings row by FK."""
    row: dict[str, Any] = {
        "source": llm_issue.source,
        "source_vuln_id": llm_issue.source_vuln_id,
        "cve_id": llm_issue.cve_id,
        "all_cves": llm_issue.all_cves,
        # Persist any CWE id Sub-Agent 1 pulled out of the raw row (e.g. for SAST
        # findings that have no CVE). Sub-Agent 2 will use it as a fallback when
        # the NVD lookup can't supply one.
        "cwe_id": llm_issue.cwe_id,
        "title": llm_issue.title,
        "description": llm_issue.description,
        "severity": llm_issue.severity,
        "cvss_score": llm_issue.cvss_score,
        "cvss_version": llm_issue.cvss_version,
        "cvss_vector": llm_issue.cvss_vector,
        "solution": llm_issue.solution,
        "asset_identity": llm_issue.asset_identity,
        "package": llm_issue.package,
        "first_detected": llm_issue.first_detected.isoformat()
        if llm_issue.first_detected
        else None,
        "raw_finding_id": raw_finding_id,
        "agent_run_id": run_id,
    }
    # Sanitize NUL bytes from any string field (some scanners emit them via the LLM).
    sb.table("issues").insert(_sanitize(row)).execute()
