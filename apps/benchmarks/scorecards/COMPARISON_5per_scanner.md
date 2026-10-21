# 3-way comparison — 45 fixtures per provider

Sample sizes: OpenAI=45, Gemini=45, Claude=45


## 1. EFFICACY

| Metric | OpenAI | Gemini | Claude |
|---|---|---|---|
| Pipeline chain success | 45/45 (100%) | 40/45 (89%) | 45/45 (100%) |
| Sandbox RESCAN VERIFIED | 28/45 (62%) | 27/45 (60%) | 25/45 (56%) |
| Sandbox rolled_back | 10/45 (22%) | 8/45 (18%) | 15/45 (33%) |
| Sandbox failed | 7/45 (16%) | 5/45 (11%) | 5/45 (11%) |

## 2. PERFORMANCE — mean seconds per agent (successful chains)

| Agent | OpenAI | Gemini | Claude |
|---|---|---|---|
| master1 | 1.4 | 20.0 | 2.4 |
| sa1 | 2.1 | 1.6 | 3.9 |
| master2 | 1.1 | 10.7 | 2.4 |
| sa2 | 1.3 | 10.9 | 2.7 |
| master3 | 1.1 | 8.8 | 2.4 |
| sa3 | 36.5 | 135.2 | 159.5 |
| master4 | 1.1 | 8.2 | 2.5 |
| sa4 | 0.7 | 10.3 | 1.9 |
| **TOTAL mean per chain** | **45.3** | **200.9** | **177.7** |

## 3. COST — raw $ (sum across 45 fixtures)

| Agent | OpenAI | Gemini | Claude |
|---|---|---|---|
| master1 | $0.1265 | $0.0822 | $0.1164 |
| sa1 | $0.0256 | $0.0146 | $0.3044 |
| master2 | $0.1291 | $0.0429 | $0.1220 |
| sa2 | $0.0283 | $0.0619 | $0.2765 |
| master3 | $0.1280 | $0.0344 | $0.1214 |
| sa3 | $0.0000 | $0.0000 | $0.0000 |
| master4 | $0.1267 | $0.0301 | $0.1204 |
| sa4 | $0.1990 | $0.4856 | $0.4700 |
| sa3_tool_cost (Tavily) | $5.8010 | $7.6310 | $10.1460 |
| **TOTAL $** | **$6.5642** | **$8.4241** | **$11.6772** |
| **Mean $ / chain** | **$0.1459** | **$0.2106** | **$0.2595** |

## 4. COST per 1k input chars (normalized)

| Agent | OpenAI | Gemini | Claude |
|---|---|---|---|
| master1 | $0.00091 | $0.00059 | $0.00084 |
| sa1 | $0.00006 | $0.00003 | $0.00066 |
| master2 | $0.00091 | $0.00030 | $0.00086 |
| sa2 | $0.00004 | $0.00009 | $0.00038 |
| master3 | $0.00091 | $0.00024 | $0.00086 |
| sa3 | $0.00000 | $0.00000 | $0.00000 |
| master4 | $0.00090 | $0.00023 | $0.00086 |
| sa4 | $0.00083 | $0.00200 | $0.00142 |

## 5. AGENT-SPECIFIC: SA-3 Tool Use

| Metric | OpenAI | Gemini | Claude |
|---|---|---|---|
| Mean SA-3 tool calls / run | 5.9 | 7.3 | 12.0 |

## 6. TOKEN TOTALS (45 fixtures, prompt / completion in k)

| Agent | OpenAI | Gemini | Claude |
|---|---|---|---|
| master1 | 39k / 2k | 42k / 126k | 76k / 8k |
| sa1 | 128k / 10k | 142k / 13k | 190k / 22k |
| master2 | 40k / 2k | 43k / 60k | 77k / 8k |
| sa2 | 170k / 4k | 188k / 56k | 233k / 8k |
| master3 | 39k / 2k | 42k / 46k | 76k / 8k |
| sa3 | 0k / 0k | 0k / 0k | 0k / 0k |
| master4 | 40k / 2k | 39k / 40k | 76k / 8k |
| sa4 | 77k / 0k | 83k / 38k | 144k / 2k |
