"""Master scorer — LLM-judge for plan validity.

Master produces a MasterPlan with a plan_summary + ordered steps. Scores
on 3 dimensions:

  1. covers_pipeline (0-1): does the plan include the expected sub-agents
     for the trigger action (SA-1 → SA-2 → SA-3 → SA-4 for FULL)?
  2. order_sensible (0-1): are the steps in the right order (fetch before
     enrich, enrich before remediate, remediate before fix)?
  3. summary_matches (0-1): does the plan_summary describe what the steps
     actually do, or hallucinate different work?

Mean of 3 = efficacy_score. Hallucinated = True if summary_matches < 0.5.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel, Field

from apps.api.app.agents.llm import invoke_structured_with_retry


_JUDGE_MODEL = "gpt-4o"


class _MasterVerdict(BaseModel):
    covers_pipeline: float = Field(..., ge=0.0, le=1.0)
    order_sensible: float = Field(..., ge=0.0, le=1.0)
    summary_matches: float = Field(..., ge=0.0, le=1.0)
    short_rationale: str = Field(..., max_length=400)


_JUDGE_SYSTEM = """You are an impartial judge of an ORCHESTRATION PLAN.

The agent's job is to plan which sub-agents to invoke for a given trigger.
Expected agents (in order): sub-agent-1 (normalize) → sub-agent-2 (enrich)
→ sub-agent-3 (remediation planning) → sub-agent-4 (fix).

Score the plan on 3 dimensions (0.0-1.0 each):

1. covers_pipeline: does the plan include the right sub-agents for the
   trigger action? FULL = all 4; otherwise a sensible subset.
2. order_sensible: are steps in the right dependency order?
3. summary_matches: does plan_summary describe what the steps actually do?

Return 3 scores + a ≤ 60-word rationale."""


def score_master(fixture_id: str, actual_output: dict | None) -> dict[str, Any]:
    """Judge the Master plan output."""
    if actual_output is None:
        return _empty("no_output")

    judge_payload = {"master_plan_output": actual_output}

    try:
        verdict: _MasterVerdict = invoke_structured_with_retry(
            run_id=str(uuid.uuid4()),
            agent="master-judge",
            schema=_MasterVerdict,
            messages=[
                SystemMessage(content=_JUDGE_SYSTEM),
                HumanMessage(content=json.dumps(judge_payload, default=str)[:8000]),
            ],
            attempts=[(0.0, _JUDGE_MODEL, 300)],
            emit_fn=None,
        )
    except Exception as e:  # noqa: BLE001
        return _empty(f"judge_failed:{type(e).__name__}")

    scores = {
        "covers_pipeline": verdict.covers_pipeline,
        "order_sensible": verdict.order_sensible,
        "summary_matches": verdict.summary_matches,
    }
    mean_score = round(sum(scores.values()) / 3.0, 3)
    hallucinated = verdict.summary_matches < 0.5
    passed = [n for n, s in scores.items() if s >= 0.75]
    failed = [n for n, s in scores.items() if s < 0.75]

    return {
        "efficacy_score": mean_score,
        "fields_passed": ",".join(passed),
        "fields_failed": ",".join(failed),
        "hallucinated": hallucinated,
        "efficacy_reason": verdict.short_rationale[:200],
    }


def _empty(reason: str) -> dict[str, Any]:
    return {
        "efficacy_score": None,
        "fields_passed": "",
        "fields_failed": "",
        "hallucinated": False,
        "efficacy_reason": reason,
    }
