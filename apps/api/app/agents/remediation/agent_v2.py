"""Sub-Agent 3 v2.0 — Agentic Remediation Researcher.

Given ONE finding, this agent:
  1. Loads prompt v2.0 from prompt_db (ReAct instructions + output schema)
  2. Binds `web_search` + `url_fetch` as tools the LLM can call
  3. Iterates: LLM reasons → calls a tool → observes → repeats
  4. When LLM stops calling tools, tries to parse its final message as JSON
  5. If parse fails, does a structured-output synthesis pass as backup
  6. Returns LLMRemediationOutput (Pydantic-validated) OR None

None means the caller should fall back to the hybrid pattern-based planner.
Failure modes that return None:
  - Budget cap reached (call count OR $ cap)
  - LLM couldn't produce valid JSON after synthesis retry
  - Any unhandled tool error
  - Max iterations exhausted without a final answer

Public API:
  run_agentic_planner(issue, asset, family, run_id, emit_fn, ...) -> LLMRemediationOutput | None
"""

from __future__ import annotations

import json
import re
from typing import Any

from langchain_core.messages import (
    AIMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)
from langchain_core.tools import tool as langchain_tool

from ...models import LLMRemediationOutput
from ..llm import get_chat_llm
from .tools.budget import AgentBudget
from .tools.url_fetch import fetch_url
from .tools.web_search import web_search
from .verifier import (
    _MIN_STEPS_BY_FAMILY,
    VerificationReport,
    _extract_commands,
    scan_placeholder_flags,
    verify_output,
)


# Return type: (output, verification_report). None means agent failed → fallback.
AgentResult = tuple[LLMRemediationOutput, VerificationReport] | None


# =============================================================================
# Enterprise floor — the agent CANNOT synthesize until it has done at least
# this many url_fetch calls against distinct authoritative sources for the
# given family. Prevents "2-step packages after 2 fetches" pathological cases.
# Kept in sync with the per-family depth minimums in verifier.py.
# =============================================================================
_MIN_FETCHES_BY_FAMILY = {
    "public_exposure": 3,
    "network_exposure": 3,
    "injection": 3,
    "vulnerable_dependency": 4,
    "os_vulnerability": 3,
}

# How many total tool calls we reserve for the depth-retry + verifier pass.
# When budget drops below this, we let the LLM synthesize with what it has
# rather than forcing more research it doesn't have budget for.
_RESERVE_CALLS_FOR_VERIFICATION = 5


# =============================================================================
# Prompt loading
# =============================================================================
def _load_prompt_v2(sb_pub) -> dict:
    """Load the v2.0 (AGENTIC) sub-agent-3 prompt. Both v1.4 (hybrid) and
    v2.0 (agent) are active in prompt_db — select by version explicitly."""
    resp = (
        sb_pub.table("prompt_db")
        .select("agent,version,model,prompt_text,parameters")
        .eq("agent", "sub-agent-3")
        .eq("version", "v2.0")
        .limit(1)
        .execute()
    )
    rows = resp.data or []
    if not rows:
        raise RuntimeError(
            "No sub-agent-3 v2.0 prompt row in prompt_db. "
            "Apply migration 0048_sub_agent_3_prompt_v2.sql."
        )
    return rows[0]


# =============================================================================
# Tool wrappers — closure captures per-run state (budget, run_id, emit_fn)
# =============================================================================
def _make_tools(
    budget: AgentBudget,
    run_id: str,
    emit_fn,
) -> list:
    """Wrap web_search + fetch_url as LangChain tools with per-run state
    baked in. LLM sees clean signatures (just the query/url arg).
    """

    @langchain_tool
    def web_search_tool(query: str) -> str:
        """Search the web for authoritative remediation guidance.

        Use this to find fix instructions for a specific CVE, IaC check ID
        (e.g. CKV_AWS_20), CWE (e.g. CWE-89), or resource + best-practice
        query. Returns up to 6 results, ranked by authority tier (Tier 1 =
        AWS/CIS/NVD/CISA docs, Tier 4 = blogs).

        Args:
            query: the search query — be specific, use identifiers.
        Returns:
            Formatted string listing each result's title, URL, tier, snippet.
        """
        result = web_search(query, budget, run_id=run_id, emit_fn=emit_fn)
        lines = [f"Search: {query}\nReturned {len(result['results'])} results:\n"]
        for i, r in enumerate(result["results"], start=1):
            lines.append(
                f"[{i}] Tier {r['authority_tier']} · {r['title']}\n"
                f"    URL: {r['url']}\n"
                f"    {r['snippet'][:300]}\n"
            )
        return "\n".join(lines)

    @langchain_tool
    def url_fetch_tool(url: str) -> str:
        """Fetch a URL and return its cleaned readable content.

        Use this to read a page found via web_search. Prefer Tier 1-2 URLs.
        Returns extracted markdown text with headings + code blocks preserved.

        Args:
            url: the URL to fetch — must be from a prior web_search result.
        Returns:
            Cleaned page content (up to 8000 chars, then truncated). If the
            page returned little/no extractable text (JS-rendered SPAs etc.),
            the response is prefixed with a WARNING telling you to find a
            different source before synthesizing.
        """
        result = fetch_url(url, budget, run_id=run_id, emit_fn=emit_fn)
        # If extraction was empty/thin, prepend an explicit directive so the
        # LLM cannot silently synthesize from a page that gave it 0 chars.
        warning = result.get("quality_warning")
        header_lines = [
            f"# {result['title']}" if result.get("title") else "",
            f"# URL: {result['final_url']}",
            f"# Chars extracted: {result['content_length']}",
        ]
        if warning:
            header_lines.append(
                f"# ⚠ CONTENT-QUALITY WARNING ({warning['level']}): {warning['directive']}"
            )
        header = "\n".join(line for line in header_lines if line)
        return f"{header}\n\n{result['text']}"

    return [web_search_tool, url_fetch_tool]


# =============================================================================
# Response content normalization
# =============================================================================
def _extract_text_content(content: Any) -> str:
    """Normalize LLM response.content to a plain text string.

    OpenAI returns `str`. Claude Sonnet (with cache_control) and Gemini 3.x
    return a `list` of content blocks like
      [{"type": "text", "text": "...", "extras": {"signature": "..."}}]
    where the actual text is inside `.text`. The old code `json.dumps(list)`
    serialized the WHOLE wrapper structure, which the JSON parser then
    couldn't dig through — the inner JSON (our RemediationPackage) stayed
    nested inside a `"text"` key and never got parsed.

    This helper handles both shapes:
      - str  → returned unchanged (OpenAI path untouched)
      - list of blocks → concatenate .text values from text-type blocks
      - fallback → json.dumps (legacy behavior)
    """
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, dict):
                txt = block.get("text")
                if isinstance(txt, str) and txt:
                    parts.append(txt)
            elif isinstance(block, str):
                parts.append(block)
        if parts:
            return "".join(parts)
    return json.dumps(content, default=str)


# =============================================================================
# JSON extraction — the LLM's final message may or may not be pure JSON
# =============================================================================
def _try_parse_final_answer(
    text: str,
    *,
    run_id: str | None = None,
    emit_fn=None,
    context: str = "parse",
) -> LLMRemediationOutput | None:
    """Parse text as LLMRemediationOutput JSON. Handles common wrappings:
      - Bare JSON
      - JSON inside ```json ... ``` fences
      - JSON with leading/trailing prose (extract first {...} balanced block)
      - Common LLM syntax issues: trailing commas, single quotes, unescaped
        newlines inside string values

    On failure, if emit_fn+run_id supplied, logs a preview of the LLM output
    and the last validation error so the developer can see WHY it failed.
    """
    if not text or not text.strip():
        return None

    last_error = ""
    candidates = _candidate_json_slices(text)

    for candidate in candidates:
        try:
            return LLMRemediationOutput.model_validate_json(candidate)
        except Exception as e:  # noqa: BLE001
            last_error = f"{type(e).__name__}: {str(e)[:250]}"
            # Try a lenient repair for common syntax slips
            repaired = _repair_common_json_errors(candidate)
            if repaired and repaired != candidate:
                try:
                    return LLMRemediationOutput.model_validate_json(repaired)
                except Exception as e2:  # noqa: BLE001
                    last_error = f"repair failed: {type(e2).__name__}: {str(e2)[:200]}"
            continue

    # All candidates failed — emit diagnostic so we can see what the LLM produced
    if emit_fn and run_id:
        preview = text[:400].replace("\n", " ⏎ ").replace("  ", " ")
        emit_fn(
            run_id,
            "sub-agent-3",
            "ERROR",
            f"[{context}] JSON parse failed after {len(candidates)} candidate(s). "
            f"Last error: {last_error}. LLM output preview (first 400 chars): {preview}",
        )
    return None


def _repair_common_json_errors(text: str) -> str | None:
    """Character-level JSON hygiene — nothing shape-aware.

    Handles:
      - Trailing commas before `}` or `]`
      - JavaScript-style comments `//` and `/* */`
      - Smart quotes replaced with ASCII

    Structural shape normalization (action/command/why → step, or step →
    command inside a ValidationTest slot) lives in the Pydantic schemas
    themselves as @model_validator(mode='before') — see RemediationStep
    and ValidationTest in app/models.py. Keeping shape logic there means
    it applies wherever the schema is used (top-level or nested) with
    zero location tracking here.

    Returns None when nothing changed (short-circuit for the caller).
    """
    repaired = text
    # Strip line comments — but ONLY when they follow whitespace or a comma
    # (avoid mutilating URLs like "http://...")
    repaired = re.sub(r"(?m)(?<=[\s,\]{}])\s*//[^\n]*", "", repaired)
    # Strip block comments
    repaired = re.sub(r"/\*.*?\*/", "", repaired, flags=re.DOTALL)
    # Trailing commas: `,}` or `,]`
    repaired = re.sub(r",(\s*[}\]])", r"\1", repaired)
    # Smart quotes → ASCII
    repaired = repaired.replace("“", '"').replace("”", '"')
    repaired = repaired.replace("‘", "'").replace("’", "'")

    return repaired if repaired != text else None


def _candidate_json_slices(text: str) -> list[str]:
    """Yield plausible JSON substrings from `text`, cheapest first.

    Order:
      1. Text stripped of leading/trailing whitespace
      2. Content inside ```json ... ``` or ``` ... ``` fences
      3. First balanced { ... } block found (crude but effective)
    """
    slices: list[str] = []
    stripped = text.strip()
    if stripped:
        slices.append(stripped)

    # Fenced code blocks (```json or plain ```)
    for m in re.finditer(r"```(?:json)?\s*\n?(.*?)```", text, re.DOTALL):
        slices.append(m.group(1).strip())

    # First balanced {...} block — crude bracket counter
    start = text.find("{")
    if start != -1:
        depth = 0
        for i, ch in enumerate(text[start:], start=start):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    slices.append(text[start : i + 1])
                    break
    return slices


# =============================================================================
# Post-parse depth check — force LLM to expand if it under-produced
# =============================================================================
def _distinct_hosts_fetched(messages: list[Any]) -> set[str]:
    """Scan the ToolMessage history for URLs the agent has read this run.
    Used both by the fetch-floor gate (below) and by the expansion prompt
    (so we can remind the LLM which sources it already has).
    """
    from urllib.parse import urlparse  # noqa: PLC0415

    hosts: set[str] = set()
    for m in messages:
        if isinstance(m, ToolMessage):
            content = m.content if isinstance(m.content, str) else ""
            for line in content.splitlines():
                if line.startswith("# URL:") or line.startswith("URL:"):
                    url = line.split(":", 1)[1].strip()
                    try:
                        h = urlparse(url).netloc.lower()
                        if h:
                            hosts.add(h)
                    except Exception:  # noqa: BLE001, S110 — malformed URL, ignore
                        pass
    return hosts


def _count_extractable_commands(parsed: LLMRemediationOutput) -> int:
    """How many CLI/code commands does the extractor find across all steps?

    Used by _maybe_expand_for_depth as a second trigger: if the LLM produced
    prose-only steps (no Command: block, no fenced code, no shell prompts),
    count is 0 and we force an expansion to fix the STEP FORMAT.
    """
    total = 0
    for pathway in parsed.pathways or []:
        for step in (pathway.remediation_steps or []) + (
            list(pathway.rollback_plan.steps) if pathway.rollback_plan else []
        ):
            text = getattr(step, "step", "") or ""
            total += len(_extract_commands(text))
    return total


def _maybe_expand_for_depth(
    parsed: LLMRemediationOutput,
    family: str | None,
    llm,
    messages: list[Any],
    run_id: str,
    emit_fn,
    budget: AgentBudget,
) -> LLMRemediationOutput:
    """Re-invoke LLM ONCE if the draft:
      (a) has any pathway below family minimum step count, OR
      (b) has zero extractable commands (all steps are pure prose)

    Both cases produce an unusable package — under-produced or unrunnable.
    Costs zero tool calls — uses only the message history already gathered.
    """
    if not parsed.pathways:
        return parsed
    # LOCAL knob (SA3_DISABLE_EXPANSION_RETRY=1) — skip the "expand to N steps"
    # re-invocation. Costs no tool calls but adds a full LLM round-trip (10-15s
    # + ~2k output tokens) per package. Turning it off accepts pathways as-is
    # even if they have <min_steps steps. Trigger B (zero-command drafts) still
    # forces expansion — those are genuinely unrunnable.
    import os as _os  # noqa: PLC0415

    if _os.getenv("SA3_DISABLE_EXPANSION_RETRY", "").lower() in ("1", "true", "yes"):
        if _count_extractable_commands(parsed) > 0:
            return parsed
        # else: fall through — zero-command drafts still need repair

    reasons: list[str] = []
    shortfalls: list[tuple[int, int]] = []

    # Trigger A — under-produced
    min_steps = _MIN_STEPS_BY_FAMILY.get(family or "") if family else None
    if min_steps:
        for i, p in enumerate(parsed.pathways):
            n = len(p.remediation_steps or [])
            if n < min_steps:
                shortfalls.append((i, n))
        if shortfalls:
            reasons.append(f"pathway step-count shortfalls: {shortfalls} (need ≥{min_steps})")

    # Trigger B — no runnable commands (all steps are prose descriptions)
    total_commands = _count_extractable_commands(parsed)
    if total_commands == 0:
        reasons.append(
            "ZERO extractable commands across all steps — steps appear to be "
            "prose descriptions, missing the required Command: block. "
            "This makes the package UNRUNNABLE for production ops."
        )

    if not reasons:
        return parsed

    fetched_hosts = _distinct_hosts_fetched(messages)

    min_rollback = max(
        2, int((min_steps or len(parsed.pathways[0].remediation_steps or [1])) * 0.5)
    )
    target_steps = min_steps or max(6, len(parsed.pathways[0].remediation_steps or [6]))

    expand_msg_parts: list[str] = [
        "Your draft is INCOMPLETE and cannot ship. Problems detected:",
        *(f"  - {r}" for r in reasons),
        "",
        "Re-emit the FULL JSON (same finding/root_cause/impact) fixing ALL of:",
        f"  - remediation_steps: ≥ {target_steps} entries",
        f"  - rollback_plan.steps: ≥ {min_rollback} entries",
        "  - validation_tests: ≥ 3 entries",
        "  - test_scripts: ≥ 2 entries",
        "",
        "**CRITICAL — every remediation_steps entry AND every rollback.steps entry**",
        "**MUST contain a `Command:` block with paste-ready CLI, not prose.** Shape:",
        "",
        "  <Action — 1-2 sentence description>",
        "",
        "  Command:",
        "      <runnable CLI, code, or Terraform block with concrete values>",
        "",
        "  Why: <rationale grounded in the cited source_url>",
        "",
        "Example of what to emit (S3 lockdown backup):",
        "",
        "  Back up the current bucket policy so the change is reversible.",
        "",
        "  Command:",
        "      aws s3api get-bucket-policy --bucket vulnerable_bucket \\",
        "        --output json > vulnerable_bucket-policy-$(date +%Y%m%d).json",
        "",
        "  Why: The AWS S3 User Guide recommends capturing the pre-change policy",
        "  before running put-public-access-block so rollback is a single apply.",
        "",
        'Do NOT emit steps that are just descriptions (e.g. "Review current',
        'security group rules" without a Command: block).',
        "",
        f"Every source_url MUST be a URL you already fetched in this run "
        f"(hosts you have content for: {sorted(fetched_hosts) or '[none]'}). "
        f"Do NOT invent new URLs. Emit JSON only.",
    ]
    expand_msg = HumanMessage(content="\n".join(expand_msg_parts))

    # NOTE: We invoke the plain LLM here (NOT with_structured_output) because
    # LLMRemediationOutput contains `confidence_components: dict[str, Any]`
    # which OpenAI's strict JSON-schema mode rejects. The main agent loop
    # uses raw JSON parsing for the same reason — mirror that shape here.
    try:
        response = llm.invoke(messages + [expand_msg])
        text = _extract_text_content(response.content)
        expanded = _try_parse_final_answer(
            text,
            run_id=run_id,
            emit_fn=emit_fn,
            context="depth-retry",
        )
        if expanded is None:
            return parsed
    except Exception as e:  # noqa: BLE001
        emit_fn(
            run_id,
            "sub-agent-3",
            "ERROR",
            f"Retry expansion failed: {type(e).__name__}: {str(e)[:150]} — keeping original draft",
        )
        return parsed

    # Guard: only accept expansion when it actually improved things.
    improved = False
    for i, before in shortfalls:
        if i < len(expanded.pathways):
            after = len(expanded.pathways[i].remediation_steps or [])
            if after > before:
                improved = True
    commands_after = _count_extractable_commands(expanded)
    if total_commands == 0 and commands_after > 0:
        improved = True
    if not improved:
        return parsed
    return expanded


# =============================================================================
# Generic placeholder retry — resource-agnostic. Takes the verifier's flags
# (which use regex patterns that match any placeholder shape, not domain
# knowledge) and asks the LLM to either add a discovery command or drop
# the offending step. No hardcoded knowledge about KMS / VPC / IAM / any
# specific resource type — the LLM decides what discovery command fits.
# =============================================================================
def _maybe_expand_for_placeholders(
    parsed: LLMRemediationOutput,
    report: VerificationReport,
    llm,
    messages: list[Any],
    run_id: str,
    emit_fn,
) -> tuple[LLMRemediationOutput, VerificationReport]:
    """If the verifier flagged unfilled placeholders, re-invoke ONCE with
    the specific placeholders shown + generic remediation instruction.

    Cost: 0 tool calls (LLM only). After a successful retry, re-scans
    placeholder flags on the new output (regex-only, no web calls) and
    updates the report's placeholder_flags in place so downstream
    confidence scoring reflects the improvement.
    """
    if not report or not report.placeholder_flags:
        return parsed, report

    # Group flags by (step_num, pattern, match) so we don't repeat ourselves
    flag_lines: list[str] = []
    seen: set[tuple] = set()
    for f in report.placeholder_flags:
        key = (f.get("step_num"), f.get("pattern"), f.get("match"))
        if key in seen:
            continue
        seen.add(key)
        flag_lines.append(
            f"  - Step {f.get('step_num')}: placeholder {f.get('match')!r} ({f.get('pattern')})"
        )

    fetched_hosts = _distinct_hosts_fetched(messages)
    expand_msg = HumanMessage(
        content="\n".join(
            [
                "Your draft has UNFILLED PLACEHOLDERS in remediation commands. Every",
                "command in the output must be directly runnable by production ops.",
                "Placeholders like `<name>`, `{name}`, `YOUR_*`, `/path/to/...`, and",
                "`example.com` make steps unrunnable. Verifier flagged:",
                "",
                *flag_lines,
                "",
                "For EACH placeholder above, choose ONE fix — no other options:",
                "",
                "  (A) Add a NEW step IMMEDIATELY BEFORE the flagged step that runs",
                "      a discovery command to resolve the value at runtime, then",
                "      reference $(that_command) or the resolved variable in the",
                "      flagged step. Example pattern (adapt to the actual resource):",
                "",
                "          aws <service> describe-<resource> \\",
                "            --filters 'Name=<attr>,Values=<from-finding>' \\",
                "            --query '<Resources[0].Id>' --output text",
                "",
                "  (B) REMOVE the flagged step from remediation_steps if the value",
                "      truly cannot be derived and the step is optional. Prefer (A)",
                "      whenever a discovery command exists in the vendor CLI.",
                "",
                "Do NOT invent hardcoded IDs, ARNs, or account numbers. Do NOT",
                "leave the placeholder in place. Do NOT rename the placeholder to a",
                "different placeholder shape.",
                "",
                "Re-emit the FULL JSON (same finding/root_cause/impact + all other",
                "pathway fields) with placeholders replaced or steps removed. Every",
                f"source_url MUST be from the fetched hosts: {sorted(fetched_hosts) or '[none]'}.",
                "Emit JSON only.",
            ]
        )
    )

    try:
        response = llm.invoke(messages + [expand_msg])
        text = _extract_text_content(response.content)
        expanded = _try_parse_final_answer(
            text,
            run_id=run_id,
            emit_fn=emit_fn,
            context="placeholder-retry",
        )
        if expanded is None:
            return parsed, report
    except Exception as e:  # noqa: BLE001
        emit_fn(
            run_id,
            "sub-agent-3",
            "ERROR",
            f"Placeholder retry failed: {type(e).__name__}: {str(e)[:150]} — "
            "keeping original draft",
        )
        return parsed, report

    # Re-scan the new output for placeholders (regex only, no web calls).
    # Only accept the retry if it strictly reduced the placeholder count.
    new_flags = scan_placeholder_flags(expanded)
    before = len(report.placeholder_flags)
    after = len(new_flags)
    if after < before:
        report.placeholder_flags = new_flags
        return expanded, report

    return parsed, report


# =============================================================================
# Fetch-floor gate — refuse LLM's premature "I'm done" if we haven't done
# enough research for the family. Injects a HumanMessage nudge and loops.
# =============================================================================
def _fetch_floor_ok(family: str | None, budget: AgentBudget) -> tuple[bool, int, int]:
    """Return (allowed_to_finish, fetches_done, fetches_required)."""
    required = _MIN_FETCHES_BY_FAMILY.get(family or "", 2) if family else 2
    done = budget.by_tool.get("url_fetch", 0)
    return (done >= required, done, required)


# =============================================================================
# Main entry point
# =============================================================================
def run_agentic_planner(
    issue: dict,
    asset: dict,
    family: str,
    *,
    run_id: str,
    sb_pub,
    emit_fn,
) -> AgentResult:
    """Run the agentic Sub-Agent 3 for one finding.

    Args:
        issue: full canonical issue row
        asset: resolved asset context (or {} if unattributed)
        family: pre-classified family (public_exposure / injection / ...)
        run_id: agent_run_id for trace correlation
        sb_pub: supabase client for reading prompt_db (public schema)
        emit_fn: trace emitter (emit_trace for real, emit_trace_demo for demo)

    Returns:
        LLMRemediationOutput on success. None when agent fails and caller
        should fall back to hybrid pattern-based planner.
    """
    # Route through the SA-3 master prompt router — picks a specialized
    # prompt for (issue.source, family) when one exists, otherwise falls
    # back to the generic sub-agent-3 v2.0 agentic prompt. This is what
    # enables per-tool + per-family prompt specialization without touching
    # the agent's execution logic (tools, budget, verification).
    from .prompt_router import load_sa3_prompt, describe_selected_prompt  # noqa: PLC0415

    issue_source = (issue.get("source") or "").strip() if isinstance(issue, dict) else ""
    try:
        prompt_row = load_sa3_prompt(
            sb_pub,
            source=issue_source,
            family=family,
            default_version="v2.0",
        )
    except Exception as e:  # noqa: BLE001
        emit_fn(
            run_id,
            "sub-agent-3",
            "ERROR",
            f"Failed to load agent prompt via router: {type(e).__name__}: {str(e)[:200]}",
        )
        return None

    params = prompt_row.get("parameters") or {}
    max_iterations = int(params.get("agent_max_iterations", 12))
    temperature = float(params.get("temperature", 0.2))
    max_tokens = int(params.get("max_tokens", 6000))
    model = prompt_row["model"]

    budget = AgentBudget()
    tools = _make_tools(budget, run_id, emit_fn)

    # Trace shows which prompt actually ran — makes it obvious in the UI
    # when a specialized prompt kicks in vs the generic fallback.
    describe_selected_prompt(prompt_row, issue_source, family)

    # Build the initial context: issue + asset + family passed as JSON.
    # Per-file batch context (attached by planner_demo._plan_and_enrich_batch)
    # is surfaced as `additional_findings` + `covered_issue_ids` so SA-3
    # composes ONE package covering every finding in the file group.
    user_payload = {
        "issue": issue,
        "asset": asset,
        "family": family,
    }

    # Hint the LLM with the scanner's OWN authoritative fix version(s) when
    # the raw finding carries one. Scanners like Trivy/OSV/Snyk/GitHub
    # Advisory Database all publish the exact patched version(s) they
    # consider "fixed" for a given CVE. Without this hint the LLM guesses
    # (from CVE advisory research → often picks a version that doesn't
    # satisfy the scanner's DB) → rescan still flags the CVE → rollback.
    # With this hint the LLM picks a version the scanner will accept.
    # Generic — checks the common field names across scanner shapes; no
    # scanner-specific branching.
    _raw_for_hint = issue.get("source_raw") or issue.get("raw") or {}
    if isinstance(_raw_for_hint, dict):
        _fix_hint = (
            _raw_for_hint.get("FixedVersion")  # Trivy (any subcommand)
            or _raw_for_hint.get("fixed_version")  # OSV, some Snyk shapes
            or _raw_for_hint.get("patchedVersions")  # Snyk vulnDB
            or _raw_for_hint.get("patched_versions")  # GitHub Advisory DB
            or (_raw_for_hint.get("Vulnerability") or {}).get("FixedVersion")  # Trivy nested
        )
        if _fix_hint:
            user_payload["hint_fix_version"] = str(_fix_hint)

    _batch_related = issue.get("_batch_related_findings")
    _batch_covered = issue.get("_batch_covered_ids")
    if _batch_related:
        user_payload["additional_findings"] = _batch_related
        user_payload["covered_issue_ids"] = _batch_covered
        user_payload["batch_mode"] = True
        # Strip internal markers from the copy that goes to the LLM so they
        # don't leak into the prompt as fake metadata.
        user_payload["issue"] = {k: v for k, v in issue.items() if not k.startswith("_batch_")}

        # Build an EXPLICIT numbered task list. The LLM historically glosses
        # over `additional_findings` (JSON-shaped, easy to skim past) and
        # produces edits for just the primary. This enumeration names each
        # finding by number + check_id + resource so it's impossible to miss.
        # Master's honest-counting pass will report any un-emitted finding as
        # UNADDRESSED — so under-emitting no longer inflates the fixed count.
        def _finding_short(iss: dict) -> tuple[str, str]:
            _raw = iss.get("source_raw") or {}
            _check = (
                _raw.get("check_id")
                or _raw.get("rule_id")
                or iss.get("source_vuln_id")
                or "unknown"
            )
            _res = (
                _raw.get("resource")
                or _raw.get("path")
                or iss.get("resource_label")
                or iss.get("file_path")
                or "unknown"
            )
            return str(_check), str(_res)

        _task_list_lines = [
            f"HARD BATCHING RULE — this package covers {len(_batch_covered)} DISTINCT findings.",
            "You MUST address each numbered finding below with its own edit + its own re-scan.",
            "If you emit fewer edits or fewer re-scans than there are distinct check_ids,",
            "the missing findings will be reported as UNADDRESSED in the run summary",
            "(not fixed — the counting layer verifies each check_id has a passing re-scan).",
            "",
            "Findings to fix (must produce ONE edit + ONE per-check re-scan for each distinct check_id):",
        ]
        _primary_check, _primary_res = _finding_short(user_payload["issue"])
        _task_list_lines.append(
            f"  1. [primary]  issue_id={user_payload['issue'].get('id')}  check_id={_primary_check}  resource={_primary_res}"
        )
        for _i, _rel in enumerate(_batch_related, start=2):
            _rc, _rr = _finding_short(_rel)
            _task_list_lines.append(
                f"  {_i}. issue_id={_rel.get('id')}  check_id={_rc}  resource={_rr}"
            )
        user_payload["batch_task_list"] = "\n".join(_task_list_lines)

    # --- Execution context injection ---
    # Tells the agent WHERE and HOW the fix should be applied (container image
    # vs host vs IaC). The generic v2.0 prompt already handles os_vulnerability
    # but without this context it defaults to host apt-get. This steers it
    # toward Dockerfile-edit + docker-build for container-image findings, or
    # host apt-get for trivy-os findings. Scalable: any scanner in the same
    # category gets the same context automatically.
    source = (issue.get("source") or "").lower()
    if "trivy-image" in source or "snyk-container" in source or "grype-image" in source:
        # Per-lab metadata (populated upstream by planner_demo from
        # connection_registry.metadata). Same block handles all image
        # scanners; each lab gets its own paths + fix_pattern via the
        # registry, so this file has NO per-lab hardcoding.
        #
        # Fallback to infra-lab defaults ONLY when the registry has no row
        # for this scanner (real deploys always register the scanner —
        # fallback exists so a fresh dev checkout with no registry doesn't
        # break at pre-flight).
        _reg_dockerfile = issue.get("file_path")
        _reg_build_dir = issue.get("working_directory")
        _reg_image_ref = issue.get("resource_name") or ""
        _reg_fix_pattern = issue.get("fix_pattern") or ""
        _reg_pkg_filter = issue.get("pkg_name_filter") or ""

        _dockerfile_path = _reg_dockerfile or "/opt/vuln-labs/infra-lab/Dockerfile"
        _build_directory = _reg_build_dir or "/opt/vuln-labs/infra-lab"
        _image_ref = _reg_image_ref or "vuln-lab-image:latest"

        user_payload["execution_context"] = {
            "target_type": "container_image",
            # Prefer the per-scanner fix_pattern from connection_registry — it
            # encodes the CORRECT fix shape for THIS lab (apt-unpin for infra,
            # FROM-bump for java tomcat, pip-upgrade for python). Falls back
            # to the generic apt-unpin advice only if no pattern is registered.
            "fix_approach": _reg_fix_pattern
            or (
                "Edit the Dockerfile to REMOVE the vulnerable package version pin entirely "
                "(e.g. change 'openssl=1.1.1f-1ubuntu2' to just 'openssl'). "
                "This lets apt-get install the latest available patched version at build time. "
                "Do NOT specify a target version — just remove the =X.Y.Z pin. "
                "Then rebuild with docker build --no-cache."
            ),
            "dockerfile_path": _dockerfile_path,
            "build_directory": _build_directory,
            "image_ref": _image_ref,
            "rebuild_command": (
                f"cd {_build_directory} && docker build --no-cache -t {_image_ref} ."
            ),
            "sed_pattern_example": (f"sed -i 's/<pkg>=<any_version>/<pkg>/' {_dockerfile_path}"),
            "rescan_command": (
                f"trivy image {_image_ref} --scanners vuln --severity HIGH,CRITICAL --format json"
            ),
            "rescan_target": (
                f"{_image_ref} (the rebuilt image — NOT the base image tag it inherits from)"
            ),
            "validation_guidance": (
                "IMPORTANT: The re-scan validation must check for the ABSENCE of the SPECIFIC CVE being fixed, "
                "NOT for zero total vulnerabilities. The image has OTHER packages with their own CVEs — "
                "fixing one CVE does not make the entire image vuln-free. "
                "Use a command like: trivy image vuln-lab-image:latest --format json 2>&1 | grep -c '<CVE_ID>' || true "
                "with expected='0' (zero occurrences of that specific CVE). "
                "Do NOT use expected='\"Vulnerabilities\": []' — that will always fail on a multi-package image."
            ),
            "rescan_exit_code_note": (
                "CRITICAL SHELL SEMANTICS: grep -c returns exit code 1 when match count is 0 "
                "(i.e. when the CVE is GONE — the desired outcome). This will cause the execution "
                "engine to treat a SUCCESSFUL fix as a failure. You MUST append '|| true' to any "
                "grep -c command so the exit code is always 0. The validation engine checks the "
                "OUTPUT value (expecting '0'), not the exit code. "
                "Correct:  trivy image ... --format json 2>&1 | grep -c 'CVE-xxx' || true "
                "Wrong:    trivy image ... --format json | grep -c 'CVE-xxx'"
            ),
            "remediation_steps_rules": (
                "Do NOT put the re-scan/validation command in remediation_steps. "
                "remediation_steps should contain ONLY actionable fix commands: "
                "backup, sed edit, docker build, verify edit (grep Dockerfile). "
                "The re-scan belongs EXCLUSIVELY in validation_tests with is_rescan=true."
            ),
            "prohibited_commands": [
                "sudo reboot",
                "apt-get install on host",
                "edits to /etc/ or /usr/ on host",
                "specifying a fixed version number in sed (just remove the pin)",
                "expecting zero total vulnerabilities in validation (check only the specific CVE)",
                "grep -c without || true (grep returns exit 1 on zero matches, which breaks execution)",
            ],
        }
        # Python-lab specific: registry can list which pip package names in
        # the Dockerfile are in scope for this scanner. When present, SA-3
        # scopes edits to those packages only (avoids touching OS packages
        # like gcc-8-base that aren't in the Dockerfile).
        if _reg_pkg_filter:
            user_payload["execution_context"]["pkg_name_filter"] = _reg_pkg_filter
    elif "trivy-os" in source or "tenable" in source or "qualys" in source or "rapid7" in source:
        user_payload["execution_context"] = {
            "target_type": "host_os",
            "fix_approach": (
                "Run apt-get update && apt-get install --only-upgrade <pkg> -y directly on the host. "
                "NEVER pin to a specific version (apt-get install <pkg>=<version>) — public Ubuntu/Debian "
                "repos only serve the LATEST point release and historical versions are removed. Always use: "
                "apt-get install --only-upgrade <pkg> -y (upgrades to latest available, which includes all "
                "prior security fixes). This is how AWS SSM Patch Manager, Ansible, and all enterprise "
                "patch tools operate."
            ),
            "verification_approach": (
                "After the upgrade, verify the installed version is GREATER than the vulnerable version "
                "using: dpkg -l <pkg> | grep <pkg>. Do NOT check for an exact target version — just "
                "confirm the version number is higher than the one reported in the finding."
            ),
            "rescan_command": "trivy rootfs / --scanners vuln --severity HIGH,CRITICAL --format json",
            "rescan_target": "/ (the host root filesystem)",
            "validation_guidance": (
                "IMPORTANT: The re-scan must check for the ABSENCE of the SPECIFIC CVE being fixed, "
                "NOT for zero total vulnerabilities. The host has many packages with other CVEs. "
                "Use: trivy rootfs / --format json 2>&1 | grep -c '<CVE_ID>' || true "
                "with expected='0'. The '|| true' is CRITICAL because grep -c returns exit 1 when "
                "the count is 0 (the desired outcome), which would otherwise fail the step."
            ),
            "remediation_steps_rules": (
                "Do NOT put the re-scan/validation command in remediation_steps. "
                "remediation_steps should contain ONLY actionable fix commands: "
                "1. apt-get update, 2. apt-get install --only-upgrade <pkg> -y, "
                "3. dpkg -l <pkg> (version verification). "
                "The re-scan belongs EXCLUSIVELY in validation_tests with is_rescan=true."
            ),
            "reboot_policy": (
                "Do NOT include 'sudo reboot' unless the CVE is in a KERNEL package "
                "(linux-image-*, linux-headers-*), libc6, or systemd. Userspace packages "
                "(apparmor, apport, openssl, curl, etc.) do NOT require a reboot — the fix "
                "takes effect immediately or on next service restart."
            ),
            "prohibited_commands": [
                "sudo reboot (unless kernel/libc/systemd CVE)",
                "docker build",
                "terraform",
                "apt-get install <pkg>=<specific_version> (never pin versions against public repos)",
                "grep -c without || true (grep returns exit 1 on zero matches)",
            ],
        }
    elif "trivy-fs" in source or "snyk-appsec" in source or "dependabot" in source:
        user_payload["execution_context"] = {
            "target_type": "dependency_manifest",
            "fix_approach": (
                "Edit the dependency manifest file to bump the vulnerable package version "
                "pin to a fixed version. The manifest (requirements.txt / package.json / "
                "pom.xml / go.mod / etc.) IS the artifact — there is no separate IaC or "
                "container layer. The fix is: change the version pin from the vulnerable "
                "version to the fixed version specified in the finding's FixedVersion field. "
                "If no specific fixed version is known, remove the version pin entirely so "
                "the package manager installs the latest available."
            ),
            "rescan_command": "trivy fs {working_directory} --scanners vuln --format json",
            "rescan_filter_note": (
                "The re-scan must check for the ABSENCE of the specific CVE that fired, "
                "NOT for zero total vulnerabilities. Other packages in the same manifest "
                "may still have CVEs. Use: "
                "trivy fs {working_directory} --scanners vuln --format json 2>&1 | "
                "grep -c '<CVE_ID>' || true with expected='0'."
            ),
            "edit_guidance": (
                "PREFERRED: use the #EDIT_FILE structured tool for manifest edits. "
                "The old_text is the vulnerable version pin (e.g., 'flask==1.0') and "
                "new_text is the fixed version pin (e.g., 'flask==2.3.3'). This is a "
                "simple single-line replacement in most cases.\n\n"
                "IMPORTANT: copy old_text VERBATIM from the ground-truth file content "
                "provided. Include the exact package name, operator (==, >=, ~=), and "
                "version string as they appear in the file. Do NOT add whitespace or "
                "change casing."
            ),
            "edit_file_marker": (
                "To emit a structured edit, put this in the step's Command block:\n"
                "  #EDIT_FILE\n"
                '  {"path": "<absolute path to manifest file>",\n'
                '   "old_text": "<exact vulnerable version pin, e.g. flask==1.0>",\n'
                '   "new_text": "<fixed version pin, e.g. flask==2.3.3>"}\n\n'
                "Rules:\n"
                "  - old_text must match exactly ONCE in the file\n"
                "  - path must be absolute (starts with /)\n"
                "  - For Python requirements.txt: the pin format is pkg==version\n"
                "  - For package.json: the pin is inside the JSON dependencies object\n"
                "  - Executor auto-backups the file before writing\n"
                "  - No shell escaping needed — base64 transport"
            ),
            "verify_absent_marker": (
                "For verify steps that check the vulnerable pin is GONE after the edit:\n"
                "  #VERIFY_ABSENT\n"
                '  {"path": "<absolute path to manifest>",\n'
                '   "pattern": "<vulnerable pin, e.g. flask==1.0>"}\n\n'
                "Exit 0 = pin absent (success). Exit 3 = still present (fail)."
            ),
            "structural_constraint": (
                "Step order MUST be: "
                "1. Backup manifest (cp file file.bak-timestamp), "
                "2. Edit manifest — bump version pin (#EDIT_FILE), "
                "3. Verify edit — confirm old pin removed (#VERIFY_ABSENT), "
                "4. Verify new pin present (grep to confirm new version in file). "
                "The re-scan belongs EXCLUSIVELY in validation_tests. "
                "Do NOT run pip install, pip download, or any package manager command — "
                "the target environment uses pip 20.0.2 which does not support --dry-run, "
                "and actually installing packages is out of scope (we fix the manifest, "
                "not the runtime). The trivy re-scan in validation_tests is the "
                "authoritative proof that the CVE is resolved."
            ),
            "batch_mode_guidance": (
                "BATCH MODE — when the payload contains `additional_findings`, ALL "
                "findings target the SAME manifest file. Emit ONE pathway:\n"
                "  Step 1: Backup manifest ONCE\n"
                "  Step 2..N+1: One #EDIT_FILE per vulnerable pin\n"
                "  Step N+2..2N+1: One #VERIFY_ABSENT per old pin\n"
                "  Step last: dry-run install check ONCE\n"
                "Each edit is independent (different lines), so order doesn't matter."
            ),
            "prohibited_commands": [
                "terraform (no IaC layer for this target)",
                "docker build (manifest fix, not container rebuild)",
                "sudo reboot",
                "pip install (do NOT install packages — just edit the manifest pin; pip 20.0.2 on env2 does not support --dry-run)",
                "pip download (not supported reliably on pip 20.0.2)",
                "apt-get / yum (not an OS package vulnerability)",
                "grep -c without || true (grep returns exit 1 on zero matches)",
                "rm or unlink on manifest files (edit in place, never delete)",
            ],
        }
    elif "serverless" in source:
        # Serverless Lambda findings from custom Semgrep rules can target
        # EITHER Lambda handler source (.py) OR the Terraform config that
        # defines the function (.tf). These need DIFFERENT strategies:
        #   .py  → CodeEditStrategy → supports #EDIT_FILE structured edits
        #   .tf  → IaCStrategy      → shell-only, needs sed + terraform apply
        # Same scanner, same re-scan command, but different execute() shape.
        _serverless_fp = (issue.get("file_path") or "").lower()
        _is_iac = _serverless_fp.endswith((".tf", ".tf.json", ".yaml", ".yml", ".json"))
        if _is_iac:
            user_payload["execution_context"] = {
                "target_type": "iac_terraform",
                "fix_approach": (
                    "Edit the Terraform (.tf) file to replace the hardcoded secret with a "
                    "reference to aws_secretsmanager_secret_version / data.aws_ssm_parameter "
                    "/ var.<name>. The .tf file IS the artifact. Fix by editing the source "
                    "in place with sed, then reconcile the deployed state via terraform apply "
                    "so the drift-check semgrep re-scan sees the corrected file."
                ),
                "file_base_path": "/opt/vuln-labs/serverless-lab",
                "rescan_command": (
                    "semgrep scan --config /opt/vuln-labs/results/serverless-rules.yaml "
                    "{file_path} --json --no-git-ignore"
                ),
                "rescan_filter_note": (
                    "The re-scan must check for ABSENCE of the specific rule_id that fired. "
                    "Use: semgrep scan --config /opt/vuln-labs/results/serverless-rules.yaml "
                    "{file_path} --json --no-git-ignore 2>&1 | grep -c '<rule_id>' || true "
                    "with expected='0'.\n\n"
                    "CRITICAL: --config takes a FILE PATH "
                    "(/opt/vuln-labs/results/serverless-rules.yaml), NOT a dotted rule ID."
                ),
                "edit_guidance": (
                    "USE sed -i FOR ALL EDITS on .tf files. IaC strategy runs your steps as "
                    "shell commands only — it does NOT interpret #EDIT_FILE or #VERIFY_ABSENT "
                    "markers. Emitting those markers here causes exit=127 ('{path:: not found') "
                    "because the shell sees the JSON payload as a command.\n\n"
                    "Preferred sed pattern:\n"
                    '  sed -i \'s|DB_PASSWORD *= *"[^"]*"|DB_PASSWORD = var.db_password|\' '
                    "/opt/vuln-labs/serverless-lab/main.tf\n"
                    "Verify with:\n"
                    "  grep -c 'DB_PASSWORD.*=.*\"' /opt/vuln-labs/serverless-lab/main.tf || true "
                    "(expected 0 hardcoded assignments)."
                ),
                "structural_constraint": (
                    "Step order MUST be: "
                    "1. Backup (cp file file.bak-timestamp), "
                    "2. sed -i to replace the hardcoded literal with a reference, "
                    "3. terraform validate (syntax check), "
                    "4. terraform apply -auto-approve (reconcile deployed state — required "
                    "so downstream re-scans see the file that matches deployed reality). "
                    "The scanner re-scan belongs EXCLUSIVELY in validation_tests with "
                    "is_rescan=true.\n\n"
                    "CRITICAL — terraform apply syntax: NEVER pass the config directory as a "
                    "positional argument. `terraform apply -auto-approve` (no path) is correct "
                    "because cwd is already set. `terraform apply -auto-approve /opt/vuln-labs/"
                    "serverless-lab` FAILS with 'Failed to load ... as a plan file' — that "
                    "positional slot expects a saved plan file from `terraform plan -out=X`, "
                    "NOT a config directory."
                ),
                "prohibited_commands": [
                    "#EDIT_FILE marker (IaCStrategy does not interpret it — use sed -i)",
                    "#VERIFY_ABSENT marker (IaCStrategy does not interpret it — use grep)",
                    "cat >> file << EOF (append leaves the vulnerable literal in place)",
                    "docker build (this is Terraform, not a container)",
                    "pip install / apt-get (not a package fix)",
                    "sudo reboot",
                    "rm or unlink on .tf files (edit in place, never delete)",
                    "semgrep --config <dotted.rule.id> (--config takes a FILE PATH "
                    "like /opt/vuln-labs/results/serverless-rules.yaml)",
                    "terraform apply <path> (positional path = saved plan file only. Use "
                    "`terraform apply -auto-approve` with no path — cwd is already set)",
                ],
            }
        else:
            user_payload["execution_context"] = {
                "target_type": "source_code",
                "fix_approach": (
                    "Edit the Lambda handler source file to replace the vulnerable code "
                    "pattern with the secure equivalent. The source file IS the artifact. "
                    "Fix the code directly: os.environ.get() or Secrets Manager lookup for "
                    "hardcoded secrets, parameterized queries for SQLi, subprocess with list "
                    "args for command injection, strong algorithms for weak hashing, etc. "
                    "The specific secure pattern should be derived from the CWE classification "
                    "in the finding and the ground-truth file content provided."
                ),
                "file_base_path": "/opt/vuln-labs/serverless-lab",
                "rescan_command": (
                    "semgrep scan --config /opt/vuln-labs/results/serverless-rules.yaml "
                    "{file_path} --json --no-git-ignore"
                ),
                "rescan_filter_note": (
                    "The re-scan must check for the ABSENCE of the specific rule_id that fired, "
                    "NOT for zero total findings. Other rules may still fire on the same file. "
                    "Use: semgrep scan --config /opt/vuln-labs/results/serverless-rules.yaml "
                    "{file_path} --json --no-git-ignore 2>&1 | grep -c '<rule_id>' || true "
                    "with expected='0'.\n\n"
                    "CRITICAL: --config takes a FILE PATH "
                    "(/opt/vuln-labs/results/serverless-rules.yaml), NOT a dotted rule ID "
                    "(e.g. opt.vuln-labs.results.serverless-hardcoded-secret). Passing the "
                    "rule ID makes semgrep exit 7 with 'unable to find a config' — the "
                    "re-scan then always 'fails' and rolls back an otherwise-successful fix."
                ),
                "syntax_check": "python3 -m py_compile {file_path}",
                "edit_guidance": (
                    "PREFERRED: use the #EDIT_FILE structured tool for ALL source-code edits. "
                    "Emit it as a step's Command block (see edit_file_marker spec below). "
                    "The executor does exact-string replace with no shell parsing of the "
                    "payload — so f-strings, quotes, curly braces, backslashes, and any "
                    "regex metacharacters pass through untouched. This eliminates the "
                    "entire class of sed/quoting failures. Use #EDIT_FILE for both "
                    "single-line and multi-line edits.\n\n"
                    "DO NOT use `cat >> file << EOF` to APPEND new code — it leaves the "
                    "vulnerable code in place and adds an unused function below it. "
                    "Always replace the vulnerable lines in-place via #EDIT_FILE so the "
                    "callers of the original code path actually change."
                ),
                "edit_file_marker": (
                    "To emit a structured edit, put this in the step's Command block:\n"
                    "  #EDIT_FILE\n"
                    '  {"path": "<absolute file path>",\n'
                    '   "old_text": "<exact substring currently in the file — must match ONCE>",\n'
                    '   "new_text": "<what it becomes after edit>"}\n\n'
                    "CRITICAL — old_text composition rules:\n"
                    "  - The GROUND TRUTH file content is provided to you at the top of "
                    "this conversation. Copy old_text VERBATIM byte-for-byte from that "
                    "content. Do NOT add characters that aren't in the file.\n"
                    "  - old_text must uniquely locate the edit — include surrounding "
                    "lines if the vulnerable pattern appears multiple times.\n"
                    "  - old_text and new_text cannot be identical (no-op rejected).\n\n"
                    "CRITICAL — new_text must FULLY REMOVE the vulnerable pattern.\n"
                    "After the edit, a #VERIFY_ABSENT check runs against the vulnerable "
                    "substring. If ANY occurrence of the vulnerable pattern remains in "
                    "new_text, verification FAILS and the fix rolls back. Replace, don't wrap.\n\n"
                    "Common mistakes that cause the wrap trap:\n"
                    "  ✗ Vulnerable: `response = requests.get(target_url)`\n"
                    "    Wrong fix : `if is_safe(target_url): response = requests.get(target_url)` "
                    "— `requests.get(target_url)` STILL PRESENT, verify_absent will fail\n"
                    "  ✓ Right fix : `p = urlparse(target_url); "
                    "if p.netloc in ALLOWLIST: response = requests.get(p.geturl())` "
                    "— original literal is gone\n\n"
                    "  ✗ Vulnerable: `hashlib.md5(x)`\n"
                    "    Wrong fix : `hashlib.sha256(hashlib.md5(x).hexdigest())` "
                    "— `hashlib.md5(` still there\n"
                    "  ✓ Right fix : `hashlib.sha256(x)`\n\n"
                    "Rule of thumb: if the vulnerable identifier (function name, call, literal) "
                    "appears anywhere in new_text, redesign the fix. Wrappers, comments, string "
                    "concatenations that include the vulnerable token all fail verify_absent."
                ),
                "verify_absent_marker": (
                    "For verify steps that check a vulnerable pattern is GONE from a file "
                    "after the edit, PREFER the structured #VERIFY_ABSENT marker over "
                    "shell grep. Shell grep is brittle: quoting the pattern is error-prone, "
                    "grep exits 1 when zero matches are found (which is the SUCCESS state "
                    "for absence checks), and `|| true` is easy to forget.\n\n"
                    "To emit a structured absence check:\n"
                    "  #VERIFY_ABSENT\n"
                    '  {"path": "<absolute file path>",\n'
                    '   "pattern": "<vulnerable substring that must NOT appear in the file>"}\n\n'
                    "Rules:\n"
                    "  - Exit 0 = pattern absent (success). Exit 3 = still present (fail).\n"
                    "  - `pattern` is checked with exact substring match — NO regex.\n"
                    "  - Include enough of the vulnerable line to avoid false positives "
                    "from unrelated code with the same substring (e.g., prefer "
                    '`AWS_ACCESS_KEY = "AKIA` over the bare `AWS_ACCESS_KEY`, which '
                    "matches both hardcoded values AND the fixed code's dict lookup "
                    "`secret['AWS_ACCESS_KEY']`)."
                ),
                "structural_constraint": (
                    "Step order MUST be: "
                    "1. Backup (cp file file.bak-timestamp), "
                    "2. Edit source (#EDIT_FILE), "
                    "3. Verify edit (#VERIFY_ABSENT the vulnerable substring), "
                    "4. Syntax check (python3 -m py_compile). "
                    "The re-scan belongs EXCLUSIVELY in validation_tests with is_rescan=true."
                ),
                "prohibited_commands": [
                    "terraform (no IaC layer for this target — Lambda code, not infra)",
                    "docker build (source code fix, not container rebuild)",
                    "sudo reboot",
                    "apt-get / yum (not a package vulnerability)",
                    "pip install (fix the source code, not dependencies)",
                    "aws lambda update-function-code (deploy belongs to CI/CD)",
                    "cat >> file (APPEND leaves the vulnerable code in place — use #EDIT_FILE)",
                    "grep -c without || true (grep returns exit 1 on zero matches)",
                    "rm or unlink on source files (edit in place, never delete)",
                    "semgrep --config <dotted.rule.id> (--config takes a FILE PATH like "
                    "/opt/vuln-labs/results/serverless-rules.yaml, not the rule ID)",
                ],
            }
    elif "semgrep" in source or "bandit" in source or "sonarqube" in source or "gosec" in source:
        user_payload["execution_context"] = {
            "target_type": "source_code",
            "fix_approach": (
                "Edit the source file to replace the vulnerable code pattern with the secure "
                "equivalent. The source file IS the artifact — there is no IaC, container, or "
                "cloud layer. Fix the code directly: parameterized queries for SQLi, input "
                "escaping for XSS, subprocess with list args for command injection, "
                "os.environ.get() for hardcoded secrets, strong algorithms for weak hashing, "
                "etc. The language and specific secure pattern should be derived from the "
                "file extension and CWE classification in the finding."
            ),
            "file_base_path": "/opt/vuln-labs/appsec-lab",
            "rescan_command": (
                "semgrep scan --config /opt/vuln-labs/appsec-lab/semgrep-rules.yaml "
                "{file_path} --json --no-git-ignore"
            ),
            "rescan_filter_note": (
                "The re-scan must check for the ABSENCE of the specific rule_id that fired, "
                "NOT for zero total findings. Other rules may still fire on the same file. "
                "Use: semgrep scan --config /opt/vuln-labs/appsec-lab/semgrep-rules.yaml "
                "{file_path} --json --no-git-ignore 2>&1 | grep -c '<rule_id>' || true "
                "with expected='0'."
            ),
            "syntax_check": "python3 -m py_compile {file_path}",
            "edit_guidance": (
                "PREFERRED: use the #EDIT_FILE structured tool for ALL source-code edits. "
                "Emit it as a step's Command block (see edit_file_marker spec below). "
                "The executor does exact-string replace with no shell parsing of the "
                "payload — so f-strings, quotes, curly braces, backslashes, and any "
                "regex metacharacters pass through untouched. This eliminates the "
                "entire class of sed/quoting failures. Use #EDIT_FILE for both "
                "single-line and multi-line edits.\n\n"
                "FALLBACK ONLY (avoid unless #EDIT_FILE truly doesn't fit): "
                "For single-line literal changes (debug=True to debug=False), sed -i "
                "may work. For multi-line rewrites, use cat > file << 'EOF' with the "
                "FULL corrected file. Always verify with grep afterward."
            ),
            "edit_file_marker": (
                "To emit a structured edit, put this in the step's Command block:\n"
                "  #EDIT_FILE\n"
                '  {"path": "<absolute file path>",\n'
                '   "old_text": "<exact substring currently in the file — must match ONCE>",\n'
                '   "new_text": "<what it becomes after edit>"}\n\n'
                "CRITICAL — old_text composition rules:\n"
                "  - The GROUND TRUTH file content is provided to you at the top of "
                "this conversation. Copy old_text VERBATIM byte-for-byte from that "
                "content. Do NOT add characters that aren't in the file (parens, "
                "quotes, whitespace) — the tool does exact-string match, and any "
                "difference means no match found.\n"
                "  - Common composition mistakes to avoid:\n"
                '      • Wrapping in parens: file has `query = f"..."` — do NOT '
                'emit `query = (f"...")` in old_text\n'
                "      • Adding trailing whitespace or newlines not in the file\n"
                '      • "Cleaning up" quotes (single↔double) or spacing\n'
                "  - old_text must uniquely locate the edit — include surrounding "
                "lines if the vulnerable pattern appears multiple times\n"
                "  - old_text and new_text cannot be identical (no-op rejected)\n"
                "  - JSON strings: escape internal quotes and backslashes per JSON rules\n\n"
                "CRITICAL — new_text must FULLY REMOVE the vulnerable pattern:\n"
                "  - After the edit, a #VERIFY_ABSENT check runs against the "
                "vulnerable substring. If ANY occurrence of the vulnerable pattern "
                "remains in new_text, verification FAILS and the fix rolls back.\n"
                "  - Examples of the mistake:\n"
                "      • Fixing `resp = urllib.request.urlopen(endpoint)` with "
                "new_text that still contains `urllib.request.urlopen` (e.g., adding "
                "a wrapper but keeping the call) — check for the SUBSTRING absence\n"
                "      • Fixing `pickle.loads(x)` with new_text containing "
                "`json.loads(x); # was: pickle.loads(x)` — the comment still has the "
                "vulnerable substring\n"
                "      • Fixing `hashlib.md5(...)` with `hashlib.sha256(hashlib.md5(...))` "
                "— the old call is still there\n"
                "  - Rule: new_text must NOT contain any identifier or call from the "
                "vulnerable pattern. Replace, don't wrap.\n\n"
                "Other:\n"
                "  - path must be absolute (starts with /)\n"
                "  - Executor auto-backups the file before writing\n"
                "  - Executor auto-preserves indentation of multi-line new_text: if "
                "the line containing old_text is indented N spaces, every new_text "
                "line AFTER the first will be prefixed with the same indent. You can "
                "write new_text with lines at column 0 (`import json\\nx = json.loads(d)`) "
                "— the executor aligns them to the surrounding block.\n"
                "  - No shell escaping needed for the payload — base64 transport."
            ),
            "verify_absent_marker": (
                "For verify steps that check a vulnerable pattern is GONE from a file "
                "after the edit, PREFER the structured #VERIFY_ABSENT marker over "
                "shell grep. Shell grep is brittle: quoting the pattern is error-prone, "
                "grep exits 1 when zero matches are found (which is the SUCCESS state "
                "for absence checks), and `|| true` is easy to forget.\n\n"
                "To emit a structured absence check:\n"
                "  #VERIFY_ABSENT\n"
                '  {"path": "<absolute file path>",\n'
                '   "pattern": "<vulnerable substring that must NOT appear in the file>"}\n\n'
                "Rules:\n"
                "  - Exit 0 = pattern absent (success). Exit 3 = still present (fail).\n"
                "  - `pattern` is checked with exact substring match — NO regex, "
                "no glob, no fuzzy matching. Include enough of the vulnerable line to "
                "avoid false positives from unrelated code with the same substring.\n"
                "  - Same base64 transport as #EDIT_FILE — no shell escaping of the "
                "pattern needed. Curly braces, quotes, backslashes all safe.\n"
                "Use plain shell only for verifies that #VERIFY_ABSENT can't express "
                "(e.g., checking a NEW pattern is PRESENT, or running py_compile / "
                "the scanner re-scan which belong in validation_tests anyway)."
            ),
            "structural_constraint": (
                "Step order MUST be: "
                "1. Backup (cp file file.bak-timestamp), "
                "2. Edit source (sed -i or cat > heredoc), "
                "3. Verify edit (grep to confirm vulnerable pattern removed), "
                "4. Syntax check (python3 -m py_compile or equivalent). "
                "The re-scan belongs EXCLUSIVELY in validation_tests."
            ),
            "batch_mode_guidance": (
                "BATCH MODE — when the payload contains `additional_findings`, ALL "
                "of those findings target the SAME file as the primary issue. Emit "
                "ONE pathway that fixes EVERY finding (primary + additional) in a "
                "single package.\n\n"
                "SEE `batch_task_list` in the payload — it enumerates every finding "
                "by number + check_id + resource. Address each numbered item.\n\n"
                "Structure:\n"
                "  Step 1: Backup the file ONCE (cp file file.bak-<timestamp>)\n"
                "  Step 2..N+1: One #EDIT_FILE per finding (in ANY safe order; the "
                "                executor applies them sequentially against the "
                "                accumulating file state)\n"
                "  Step N+2..2N+1: One #VERIFY_ABSENT per finding's vulnerable "
                "                   substring (all must pass)\n"
                "  Step last: py_compile the file ONCE\n"
                "Do NOT emit a separate backup per finding. The single backup at "
                "Step 1 is the rollback anchor for the whole batch.\n"
                "Consult the ground-truth file content (provided) to derive each "
                "old_text verbatim. Since edit_file steps run sequentially on the "
                "accumulating file, each subsequent edit's old_text must match the "
                "file state AFTER prior edits — but since edits touch different "
                "lines of the file (different findings = different code sites), "
                "this normally 'just works'. If two findings target the SAME line, "
                "combine them into ONE #EDIT_FILE with a new_text that fixes both.\n\n"
                "VALIDATION — the re-scan must cover every distinct rule_id in the "
                "batch. Emit ONE validation_test per distinct rule_id with a grep "
                "narrowed to that rule_id, e.g.:\n"
                "  {name: 'Re-scan rule <rule_id_X>', method: 'cli',\n"
                "   command: 'semgrep scan ... {file_path} ... | grep -c '<rule_id_X>' || true',\n"
                "   expected: '0', is_rescan: true}\n"
                "The counting layer credits a finding as FIXED only when its rule_id "
                "has a passing per-rule re-scan. A single broad re-scan without "
                "rule filtering credits ALL findings only if it returns 0 total "
                "matches — otherwise the un-rescanned findings show as UNADDRESSED "
                "in the run summary."
            ),
            "prohibited_commands": [
                "terraform (no IaC layer for this target)",
                "docker build (source code fix, not container rebuild)",
                "sudo reboot",
                "apt-get / yum (not a package vulnerability)",
                "pip install (fix the source code, not dependencies)",
                "grep -c without || true (grep returns exit 1 on zero matches)",
                "rm or unlink on source files (edit in place, never delete)",
            ],
        }

    # --- Pre-fetch target file content into turn-1 context (GROUND TRUTH) ---
    # Toggle: SA3_DISABLE_FILE_FETCH=true to skip (falls back to legacy blind
    # generation). Default = enabled. Reads the exact file the fix will edit
    # via SSM so the LLM composes edits against real bytes, not guesses.
    # Any-scanner: works for main.tf, Dockerfile, app.py, sshd_config, etc.
    # Zero env-specific knowledge — SSM cat + inject as data section.
    file_ctx_msg: list[Any] = []
    import os as _os  # noqa: PLC0415

    if _os.getenv("SA3_DISABLE_FILE_FETCH", "").lower() not in ("1", "true", "yes"):
        file_path_hint = (
            user_payload.get("issue", {}).get("file_path")
            if isinstance(user_payload, dict)
            else None
        )
        if not file_path_hint:
            # Fall back to raw finding + working_dir composition
            _wd = (
                user_payload.get("issue", {}).get("working_directory")
                if isinstance(user_payload, dict)
                else None
            )
            _fp = (
                user_payload.get("issue", {}).get("file_path")
                if isinstance(user_payload, dict)
                else None
            )
            file_path_hint = _fp or (_wd + "/main.tf" if _wd else None)
        if file_path_hint and isinstance(file_path_hint, str) and file_path_hint.startswith("/"):
            try:
                from .tools.file_fetch import fetch_file  # noqa: PLC0415

                prefetch = fetch_file(
                    file_path_hint,
                    budget,
                    target_instance_id=None,  # falls back to settings.fixer_env2_instance_id
                    run_id=run_id,
                    emit_fn=emit_fn,
                )
                if prefetch.get("exists") and prefetch.get("content"):
                    content = prefetch["content"]
                    trunc_note = " (TRUNCATED)" if prefetch.get("truncated") else ""
                    file_ctx_msg = [
                        HumanMessage(
                            content=(
                                f"# GROUND TRUTH — actual current content of {file_path_hint}{trunc_note}\n"
                                f"# When generating any edit / sed / grep / regex, use the EXACT SYNTAX below.\n"
                                f"# Web sources are for concept understanding only — this file is authoritative.\n\n"
                                f"{content}"
                            )
                        )
                    ]
            except Exception:  # noqa: BLE001, S110
                pass  # LLM will work without file pre-inject

    # --- Knowledge Base injection (few-shot from proven fixes) ---
    kb_context_msg: list[Any] = []
    try:
        from .kb_retrieval import retrieve_examples, format_examples_for_agentic_prompt  # noqa: PLC0415
        from ...db import supabase_admin  # noqa: PLC0415

        sb_pub = supabase_admin()
        check_id = (
            issue.get("source_vuln_id")
            or issue.get("cve_id")
            or (issue.get("source_raw") or {}).get("check_id")
        )
        kb_examples = retrieve_examples(sb_pub, check_id=check_id, family=family)
        if kb_examples:
            kb_text = format_examples_for_agentic_prompt(kb_examples)
            if kb_text:
                kb_context_msg = [HumanMessage(content=kb_text)]
    except Exception:  # noqa: BLE001, S110
        pass  # KB retrieval is best-effort

    messages: list[Any] = [
        SystemMessage(content=prompt_row["prompt_text"]),
        *kb_context_msg,
        *file_ctx_msg,
        HumanMessage(content=json.dumps(user_payload, default=str)),
    ]

    llm = get_chat_llm(
        run_id=run_id,
        agent="sub-agent-3",
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
        emit_fn=emit_fn,
    )
    llm_with_tools = llm.bind_tools(tools)

    # =========================================================================
    # The agent loop: LLM → maybe tool calls → observations → repeat
    # =========================================================================
    # `family` captured for the verifier below (both direct + synth paths need it)
    _family_for_verify = family

    for iteration in range(max_iterations):
        try:
            response: AIMessage = llm_with_tools.invoke(messages)  # type: ignore[assignment]
        except Exception as e:  # noqa: BLE001
            emit_fn(
                run_id,
                "sub-agent-3",
                "ERROR",
                f"LLM call failed at iteration {iteration + 1}: {type(e).__name__}: {str(e)[:200]}",
            )
            return None

        messages.append(response)

        tool_calls = getattr(response, "tool_calls", None) or []
        if not tool_calls:
            # Model didn't request tools — wants to finish. Gate on fetch floor.
            floor_ok, done, required = _fetch_floor_ok(family, budget)
            budget_remaining = budget.max_calls - budget.call_count
            can_afford_more = budget_remaining > _RESERVE_CALLS_FOR_VERIFICATION

            if not floor_ok and can_afford_more and iteration < max_iterations - 2:
                # PUSH BACK — research floor not met. Force more fetching.
                messages.append(
                    HumanMessage(
                        content=(
                            f"You've only called url_fetch {done} time(s). Family "
                            f"'{family}' requires content from AT LEAST {required} distinct "
                            f"authoritative sources before you may synthesize a package "
                            f"a production ops team can trust.\n\n"
                            f"Continue researching NOW: call web_search for an angle you "
                            f"haven't explored (a different vendor's docs, CIS Benchmark, "
                            f"MITRE ATT&CK/CWE, or the OS/language-ecosystem security "
                            f"advisory) and url_fetch a Tier-1/2 result. Do not emit JSON "
                            f"until you have ≥ {required} url_fetch calls of substantive "
                            f"(non-EMPTY, non-THIN) content. Marketplace / product / "
                            f"pricing / console pages do NOT count."
                        )
                    )
                )
                continue  # LLM will now do more research

            # Floor met OR budget nearly out — accept the finish attempt
            final_text = response.content or ""
            parsed = _try_parse_final_answer(
                _extract_text_content(final_text),
                run_id=run_id,
                emit_fn=emit_fn,
                context="loop-final",
            )
            if parsed is not None:
                # Depth retry: expand pathways that fell short of family minimum
                parsed = _maybe_expand_for_depth(
                    parsed,
                    family,
                    llm,
                    messages,
                    run_id,
                    emit_fn,
                    budget,
                )
                # Enterprise safety: cross-source consensus + destructive scan
                report = verify_output(
                    parsed, budget=budget, run_id=run_id, emit_fn=emit_fn, family=family
                )
                # Generic placeholder retry — LLM decides discovery cmd vs drop
                parsed, report = _maybe_expand_for_placeholders(
                    parsed,
                    report,
                    llm,
                    messages,
                    run_id,
                    emit_fn,
                )
                return (parsed, report)
            # Fall through to synthesis backup below
            return _synthesize_backup(llm, messages, run_id, emit_fn, budget, family)

        # Execute each tool call
        budget_exhausted = False
        for tc in tool_calls:
            tool_name = tc["name"]
            tool_args = tc.get("args", {}) or {}
            tool_call_id = tc["id"]

            selected_tool = next((t for t in tools if t.name == tool_name), None)
            if selected_tool is None:
                messages.append(
                    ToolMessage(
                        content=f"Error: unknown tool '{tool_name}'",
                        tool_call_id=tool_call_id,
                    )
                )
                continue

            try:
                observation = selected_tool.invoke(tool_args)
                messages.append(ToolMessage(content=str(observation), tool_call_id=tool_call_id))
            except RuntimeError as e:
                # Budget cap or tool-level failure — tell the LLM so it can adapt.
                err_msg = str(e)
                messages.append(
                    ToolMessage(
                        content=f"Tool error: {err_msg}",
                        tool_call_id=tool_call_id,
                    )
                )
                if "cap" in err_msg.lower() or "denied" in err_msg.lower():
                    budget_exhausted = True

        if budget_exhausted:
            return _synthesize_backup(llm, messages, run_id, emit_fn, budget, _family_for_verify)

    # Loop exhausted without a final answer — force synthesis
    return _synthesize_backup(llm, messages, run_id, emit_fn, budget, _family_for_verify)


# =============================================================================
# Synthesis backup — used when agent doesn't emit valid JSON in the loop
# =============================================================================
def _synthesize_backup(
    llm,
    messages: list[Any],
    run_id: str,
    emit_fn,
    budget: AgentBudget,
    family: str | None = None,
) -> AgentResult:
    """Ask the LLM to produce ONLY the JSON output, using structured_output
    to force schema compliance. Uses the message history for context —
    everything the agent has already learned from tools carries over.
    """
    # NOTE: same schema-strict caveat as _maybe_expand_for_depth — use raw
    # invoke + JSON parse instead of with_structured_output, because
    # LLMRemediationOutput has dict[str, Any] fields OpenAI strict rejects.
    try:
        synth_messages = messages + [
            HumanMessage(
                content=(
                    "Now produce the final RemediationPackage as a single JSON object "
                    "matching the schema in the system prompt. Every source_url MUST be "
                    "one of the URLs you called url_fetch on during this run. No prose, "
                    "just the JSON."
                )
            )
        ]
        response = llm.invoke(synth_messages)
        text = _extract_text_content(response.content)
        result = _try_parse_final_answer(
            text,
            run_id=run_id,
            emit_fn=emit_fn,
            context="synthesis-backup",
        )
        if result is None:
            # Claude-only repair-retry: Sonnet sometimes produces JSON that
            # parses but fails Pydantic validation. One extra round-trip with
            # the actual validation error in the prompt lets the model fix the
            # specific field it got wrong. Gated by model name so OpenAI /
            # Gemini paths are untouched. Costs ≈ $0.015 per repair attempt.
            model_name = str(getattr(llm, "model", "")).lower()
            if "claude" in model_name:
                try:
                    LLMRemediationOutput.model_validate_json(text.strip())
                    validation_err = "(no validation error — JSON parse failed instead)"
                except Exception as ve:  # noqa: BLE001
                    validation_err = f"{type(ve).__name__}: {str(ve)[:600]}"
                repair_messages = synth_messages + [
                    response,
                    HumanMessage(
                        content=(
                            "Your previous JSON failed schema validation with the "
                            f"following error:\n\n{validation_err}\n\n"
                            "Produce the RemediationPackage JSON again, correcting ONLY "
                            "the fields the error points to. Keep every other field "
                            "exactly as before. Output ONLY the JSON object, no prose."
                        )
                    ),
                ]
                try:
                    repair_response = llm.invoke(repair_messages)
                    repair_text = _extract_text_content(repair_response.content)
                    result = _try_parse_final_answer(
                        repair_text,
                        run_id=run_id,
                        emit_fn=emit_fn,
                        context="synthesis-repair",
                    )
                    if result is not None:
                        emit_fn(
                            run_id,
                            "sub-agent-3",
                            "INFO",
                            "Claude repair-retry succeeded after synthesis-backup failed",
                        )
                except Exception as e:  # noqa: BLE001
                    emit_fn(
                        run_id,
                        "sub-agent-3",
                        "ERROR",
                        f"Claude repair-retry failed: {type(e).__name__}: {str(e)[:200]}",
                    )
        if result is None:
            emit_fn(
                run_id,
                "sub-agent-3",
                "ERROR",
                "Synthesis pass returned non-parseable content — no package produced",
            )
            return None
        # Depth retry: expand if the backup synthesis under-produced.
        result = _maybe_expand_for_depth(
            result,
            family,
            llm,
            messages,
            run_id,
            emit_fn,
            budget,
        )
        # Same enterprise safety pass whether we came from the loop or the backup.
        report = verify_output(result, budget=budget, run_id=run_id, emit_fn=emit_fn, family=family)
        # Generic placeholder retry — LLM decides discovery cmd vs drop
        result, report = _maybe_expand_for_placeholders(
            result,
            report,
            llm,
            messages,
            run_id,
            emit_fn,
        )
        return (result, report)
    except Exception as e:  # noqa: BLE001
        emit_fn(
            run_id,
            "sub-agent-3",
            "ERROR",
            f"Synthesis pass failed: {type(e).__name__}: {str(e)[:200]}",
        )
        return None
