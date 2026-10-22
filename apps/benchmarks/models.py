"""Candidate model registry + pricing table for the benchmark harness.

Pricing is $/1M tokens as of 2026-09 — update when providers change. Cost
in scorecards is tokens × these numbers / 1_000_000.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ModelSpec:
    name: str  # the model-name string you pass to get_chat_llm()
    provider: str  # "openai" / "anthropic" / "google" — informational
    input_price_per_m: float  # $/1M input tokens
    output_price_per_m: float  # $/1M output tokens
    tier: str  # "high_volume" (SA-1/SA-2) or "reasoning" (Master/SA-3/SA-4)


# High-volume tier — cost + throughput optimized (SA-1, SA-2)
HIGH_VOLUME: list[ModelSpec] = [
    ModelSpec("gpt-4o-mini", "openai", 0.15, 0.60, "high_volume"),  # baseline
    ModelSpec("claude-haiku-4-5", "anthropic", 1.00, 5.00, "high_volume"),
    # Mix of -latest aliases and version-pinned names on our project:
    # - gemini-flash-latest: alias (no pinned Flash name available to this project)
    # - gemini-flash-lite-latest: alias
    # - gemini-3.1-flash-lite: VERSION-PINNED stable (prefer this over the alias)
    ModelSpec("gemini-flash-latest", "google", 0.15, 0.60, "high_volume"),
    ModelSpec("gemini-flash-lite-latest", "google", 0.075, 0.30, "high_volume"),
    ModelSpec("gemini-3.1-flash-lite", "google", 0.075, 0.30, "high_volume"),
]

# Reasoning tier — quality + correctness optimized (Master, SA-3, SA-4)
REASONING: list[ModelSpec] = [
    ModelSpec("gpt-4o", "openai", 2.50, 10.00, "reasoning"),  # baseline
    ModelSpec("claude-sonnet-4-6", "anthropic", 3.00, 15.00, "reasoning"),
    ModelSpec("claude-opus-4-7", "anthropic", 15.00, 75.00, "reasoning"),
    # gemini-pro-latest is Google's current frontier — 2× cheaper input than
    # gpt-4o, similar output price. Free-tier quota is very low; needs
    # billing enabled on the Google Cloud project for serious volume.
    ModelSpec("gemini-pro-latest", "google", 1.25, 10.00, "reasoning"),
    # Version-pinned equivalent — same underlying model (Gemini 3.1 Pro) but
    # the name is explicit so results are reproducible even if Google updates
    # the -latest alias later.
    ModelSpec("gemini-3.1-pro-preview", "google", 1.25, 10.00, "reasoning"),
]

ALL_MODELS: list[ModelSpec] = HIGH_VOLUME + REASONING
BY_NAME: dict[str, ModelSpec] = {m.name: m for m in ALL_MODELS}


def cost_usd(model_name: str, prompt_tokens: int, completion_tokens: int) -> float:
    """Compute $ cost for one LLM call. Returns 0.0 if the model isn't in
    the registry (unknown pricing — flagged in scorecard as 0 cost, don't
    use for comparison until we add the row)."""
    spec = BY_NAME.get(model_name)
    if not spec:
        return 0.0
    return (
        prompt_tokens * spec.input_price_per_m
        + completion_tokens * spec.output_price_per_m
    ) / 1_000_000
