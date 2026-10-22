"""SA-2 (enrichment) scorer — LLM-as-judge against a rubric.

SA-2 produces free-form prose (risk_explanation + remediation_prose). There's
no exact-match ground truth; instead we use a strong judge model (gpt-4o)
to score the actual output on a rubric:

  1. severity_consistency (0-1): does the explanation match the severity the
     scoring block gave?
  2. factual_grounding (0-1): does the explanation cite real EPSS/NVD/CVSS
     numbers from the input, or does it invent them?
  3. actionability (0-1): is the remediation prose concrete and specific,
     or vague ("patch the vulnerability")?
  4. hallucination_free (0-1): no fabricated CVEs, package versions, or
     mitigation claims not supported by the input?

Final efficacy_score = mean of the four dimensions. hallucinated = True
when hallucination_free < 0.5.

Judge cost per fixture ≈ $0.003. For 100 benchmark runs that's $0.30 —
acceptable overhead on top of the model-under-test's own cost.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel, Field

from apps.api.app.agents.llm import invoke_structured_with_retry


_FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "raw"
_JUDGE_MODEL = "gpt-4o"


class _JudgeVerdict(BaseModel):
    """Structured output shape the judge returns."""

    severity_consistency: float = Field(..., ge=0.0, le=1.0)
    factual_grounding: float = Field(..., ge=0.0, le=1.0)
    actionability: float = Field(..., ge=0.0, le=1.0)
    hallucination_free: float = Field(..., ge=0.0, le=1.0)
    short_rationale: str = Field(..., max_length=400)


_JUDGE_SYSTEM = """You are an impartial judge of a security-finding ENRICHMENT output.

Score the enrichment output on 4 dimensions (0.0 to 1.0 each):

1. severity_consistency: does the prose match the scoring block's severity/priority?
   1.0 = fully consistent  0.0 = contradicts

2. factual_grounding: does the prose cite the actual EPSS/CVSS/KEV/MITRE values from
   the input, or invent numbers?
   1.0 = all numbers cited are in the input  0.0 = numbers are made up

3. actionability: is the recommended remediation specific and executable?
   1.0 = concrete steps ("upgrade openssl to 1.1.1f-ubuntu2.12") 0.0 = vague ("patch it")

4. hallucination_free: any invented CVEs, versions, package names, mitigations?
   1.0 = zero hallucinations  0.0 = key claims unsupported by input

Return the 4 scores + a short rationale (≤ 60 words)."""


def score_sa2(fixture_id: str, actual_output: dict | None) -> dict[str, Any]:
    """Score SA-2 output via LLM-judge rubric."""
    fixture_path = _find_fixture(fixture_id)
    if not fixture_path:
        return _empty("fixture_not_found")
    with fixture_path.open() as f:
        fixture = json.load(f)
    enrichment_input = fixture.get("input") or {}
    if not enrichment_input:
        return _empty("fixture_missing_input")
    if actual_output is None:
        return _empty("no_output")

    judge_payload = {
        "input_to_sa2": enrichment_input,
        "sa2_output_to_score": actual_output,
    }

    try:
        verdict: _JudgeVerdict = invoke_structured_with_retry(
            run_id=str(uuid.uuid4()),
            agent="sa2-judge",
            schema=_JudgeVerdict,
            messages=[
                SystemMessage(content=_JUDGE_SYSTEM),
                HumanMessage(content=json.dumps(judge_payload, default=str)[:12000]),
            ],
            attempts=[(0.0, _JUDGE_MODEL, 400)],
            emit_fn=None,
        )
    except Exception as e:  # noqa: BLE001
        return _empty(f"judge_failed:{type(e).__name__}")

    mean_score = round(
        (
            verdict.severity_consistency
            + verdict.factual_grounding
            + verdict.actionability
            + verdict.hallucination_free
        )
        / 4.0,
        3,
    )
    hallucinated = verdict.hallucination_free < 0.5
    passed = [
        n
        for n, s in {
            "severity_consistency": verdict.severity_consistency,
            "factual_grounding": verdict.factual_grounding,
            "actionability": verdict.actionability,
            "hallucination_free": verdict.hallucination_free,
        }.items()
        if s >= 0.75
    ]
    failed = [
        n
        for n, s in {
            "severity_consistency": verdict.severity_consistency,
            "factual_grounding": verdict.factual_grounding,
            "actionability": verdict.actionability,
            "hallucination_free": verdict.hallucination_free,
        }.items()
        if s < 0.75
    ]

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


def _find_fixture(fixture_id: str) -> Path | None:
    for path in list(_FIXTURES_DIR.rglob("*.json")) + list(
        (_FIXTURES_DIR.parent / "success").rglob("*.json")
    ):
        try:
            with path.open() as f:
                data = json.load(f)
            if data.get("fixture_id") == fixture_id:
                return path
        except Exception:  # noqa: BLE001, S112
            continue
    return None
