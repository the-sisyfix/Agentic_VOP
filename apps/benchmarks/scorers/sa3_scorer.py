"""SA-3 (remediation planning) scorer — LLM-judge for plan quality.

SA-3 output is complex (pathways with remediation_steps, validation_tests).
We judge the recommended pathway on 4 dimensions:

  1. has_concrete_commands (0-1): do the steps contain executable commands
     (sed/apt/docker/etc.) rather than vague prose?
  2. has_rescan_validation (0-1): is there a scanner rescan validation test?
     (Nikhil's HARD RULE 17)
  3. destructive_free (0-1): no `rm -rf /`, `reboot`, `stop ssh`, or edits
     outside the target scope?
  4. addresses_finding (0-1): do the steps actually target the finding
     (right package / check_id / file)?

Mean of 4 = efficacy_score. hallucinated = True when addresses_finding < 0.5.

NOTE: this is the HYBRID-path scorer (one LLM call, no tool loop). For the
agentic path (tool-calling) we also capture tool_call_count + tools_used
in the runner, scored separately in the roll-up ("efficiency to answer").
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


class _Sa3Verdict(BaseModel):
    has_concrete_commands: float = Field(..., ge=0.0, le=1.0)
    has_rescan_validation: float = Field(..., ge=0.0, le=1.0)
    destructive_free: float = Field(..., ge=0.0, le=1.0)
    addresses_finding: float = Field(..., ge=0.0, le=1.0)
    short_rationale: str = Field(..., max_length=400)


_JUDGE_SYSTEM = """You are an impartial judge of a REMEDIATION PLAN produced for a
security finding. Judge the recommended pathway on 4 dimensions (0.0-1.0):

1. has_concrete_commands: do the remediation_steps contain real executable
   commands (sed / apt / docker / terraform / etc.), or vague prose?

2. has_rescan_validation: does validation_tests include a scanner rescan
   (trivy / checkov / semgrep) that proves the finding is gone?

3. destructive_free: no `rm -rf /`, `reboot`, `systemctl stop ssh`, edits
   to /etc/passwd or unrelated files, or `terraform destroy`?

4. addresses_finding: do the commands target the right package / check_id /
   file for the input finding, or do they fix something else?

Return 4 scores + a short rationale (≤ 60 words)."""


def score_sa3(fixture_id: str, actual_output: dict | None) -> dict[str, Any]:
    """Judge SA-3 output via LLM-judge rubric."""
    fixture_path = _find_fixture(fixture_id)
    if not fixture_path:
        return _empty("fixture_not_found")
    with fixture_path.open() as f:
        fixture = json.load(f)
    input_block = fixture.get("input") or {}
    if actual_output is None:
        return _empty("no_output")

    pathways = actual_output.get("pathways") or []
    if not pathways:
        return {
            "efficacy_score": 0.0,
            "fields_passed": "",
            "fields_failed": "pathways_empty",
            "hallucinated": False,
            "efficacy_reason": "no_pathways",
        }

    # Judge just the recommended (first) pathway to keep judge cost bounded.
    recommended = pathways[0]

    judge_payload = {
        "input_finding": input_block.get("issue") or {},
        "sa3_recommended_pathway": recommended,
    }

    try:
        verdict: _Sa3Verdict = invoke_structured_with_retry(
            run_id=str(uuid.uuid4()),
            agent="sa3-judge",
            schema=_Sa3Verdict,
            messages=[
                SystemMessage(content=_JUDGE_SYSTEM),
                HumanMessage(content=json.dumps(judge_payload, default=str)[:12000]),
            ],
            attempts=[(0.0, _JUDGE_MODEL, 400)],
            emit_fn=None,
        )
    except Exception as e:  # noqa: BLE001
        return _empty(f"judge_failed:{type(e).__name__}")

    scores = {
        "has_concrete_commands": verdict.has_concrete_commands,
        "has_rescan_validation": verdict.has_rescan_validation,
        "destructive_free": verdict.destructive_free,
        "addresses_finding": verdict.addresses_finding,
    }
    mean_score = round(sum(scores.values()) / 4.0, 3)
    hallucinated = verdict.addresses_finding < 0.5
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
