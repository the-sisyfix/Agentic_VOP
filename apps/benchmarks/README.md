# LLM Benchmark Harness

Compares candidate LLMs per agent on real pipeline inputs. Reuses production
code (`get_chat_llm`, `invoke_structured_with_retry`) — only the model name
is swapped per run.

## Layout

```
apps/benchmarks/
├── models.py           # Candidate registry + $/token pricing
├── runner.py           # CLI entry point
├── agents/             # Per-agent invocation wrappers
│   └── sa1_runner.py   # SA-1 (normalization) — DAY 1
├── fixtures/raw/       # Pinned raw-finding JSON files
├── scorecards/         # Output CSVs (one per agent × model)
├── baselines/          # (Phase 2) Reference outputs from current prod models
└── scorers/            # (Phase 3) Per-agent quality scorers
```

## Usage

```bash
# From repo root
python -m apps.benchmarks.runner --agent sa1 --model gpt-4o-mini --runs 3

# Filter to one scanner's fixtures
python -m apps.benchmarks.runner --agent sa1 --model gpt-4o-mini --scanner trivy-image-ec2

# When Anthropic key arrives:
python -m apps.benchmarks.runner --agent sa1 --model claude-haiku-4-5 --runs 3

# When Gemini key arrives:
python -m apps.benchmarks.runner --agent sa1 --model gemini-2.0-flash --runs 3
```

Each run appends rows to `scorecards/{agent}_{model}.csv`. Compare models by
opening the CSVs side-by-side in a spreadsheet.

## Fixtures

Each fixture is a single JSON file in `fixtures/raw/`:

```json
{
  "fixture_id": "trivy-image-ec2-cve-2022-0778-01",
  "scanner": "trivy-image-ec2",
  "raw": { ... the actual raw scanner payload ... }
}
```

Hand-pick 2-3 representative findings per scanner for Day 1 coverage.

## Metrics captured (Day 1 — Tier 1)

- `latency_ms` — wall-clock per LLM call
- `input_chars` — honest cross-provider cost basis (tokens vary per tokenizer)
- `cost_usd_estimated` — tokens × price (char-based estimate until token
  readback plumbing lands in iteration 2)
- `schema_valid` — did Pydantic validation pass?
- `retries` — count of internal retries
- `failure_mode` — refusal / timeout / rate_limited / schema_violation /
  format_drift / provider_5xx / other

## Later (Phase 3)

- Per-agent quality scorers under `scorers/`
- Ground-truth labeled expected outputs
- LLM-judge rubrics for SA-2 + Master
- Sandbox-oracle (reuses env2) for SA-3 + SA-4 end-to-end eval

## Adding a new model

1. Add a `ModelSpec` entry to `models.py` with pricing
2. Make sure the corresponding API key is in `apps/api/.env`:
   - `OPENAI_API_KEY` (have it)
   - `ANTHROPIC_API_KEY` (placeholder — replace when key arrives)
   - `GOOGLE_API_KEY` (placeholder — replace when key arrives)
3. Run `python -m apps.benchmarks.runner --agent sa1 --model <new-model-name>`

The existing `get_chat_llm()` router routes by model-name prefix
(`gpt-*`/`o*` → OpenAI, `claude-*` → Anthropic, `gemini-*` → Google) — no
code changes needed to add new models from existing providers.
