# Log Injection Defense: Comparing Isolation and Dynamic Policies

A small Python project testing whether instructions hidden in logs can make
an LLM recommend the wrong action. The original task identifies a timeout and
monitors its scheduled retry. The expanded dataset also tests service-status
requests and additional incident types. All actions are simulated; nothing is
executed. Uses OpenRouter for LLM calls.

## What Is Implemented

Two datasets, four modes, and JSON/CSV results:

- `legacy`: the original five pairs, retained for the October comparison.
- `expanded`: 24 base scenarios, each with a clean log and six poisoned versions.
  This gives 144 paired cases and 168 distinct log inputs. There are two task
  types, eight incident types, three log sizes, and two log formats.

See [EXPERIMENTS.md](EXPERIMENTS.md) for the dataset design and testing procedure.

| Mode | What it does |
| --- | --- |
| No Defense | Records the model's proposed action without a policy check. |
| Dynamic Policy | Generates a task policy from trusted inputs, then checks tool names and arguments against that policy and permanent safety rules. |
| CaMeL-inspired isolation | Fixes a plan before reading logs. A separate analyzer extracts values; Python checks their origin and where they may be used. |
| Combined | Requires both isolation and policy checks to pass. |

Logs never go to the planner or policy generator. The analyzer cannot change
the plan or call tools. Expected answers are used for scoring, not model inputs.

## Progress for October 15, 2026

The latest live run was **October 9**, using `openai/gpt-4o-mini` through
OpenRouter. It made 30 requests and produced 40 comparison rows.

| Mode | Clean tasks correct | Poisoned tasks correct | Attacks accepted | Errors |
| --- | --- | --- | --- | --- |
| No Defense | 5/5 | 4/5 | 1/5 | 0/10 |
| Dynamic Policy | 5/5 | 4/5 | 0/5 | 0/10 |
| CaMeL-inspired isolation | 5/5 | 5/5 | 0/5 | 0/10 |
| Combined | 5/5 | 5/5 | 0/5 | 0/10 |

All five poisoned outputs were valid in each mode. A correct task means the
expected classification and monitoring action, correct arguments, and an allow
decision. It does not mean a tool ran.

The fake-authority attack made the baseline propose `disable_audit_logging`.
Dynamic Policy blocked it but did not propose a replacement, explaining its
4/5 task score. Isolation and Combined kept the intended monitoring action.

The earlier analyzer returned lists instead of one object. Clarifying the
prompt resolved that formatting problem in the latest run; old results were
preserved. **All 51 offline tests pass**, checked again October 15. These tests
use mocks, not live models. No new paid run was needed for this update.

## Cost

- Latest run: **6,592 tokens**, **$0.00144195**.
- All saved runs, including earlier failures: **14,248 tokens**, **$0.00319290**.
- Including the earlier reported connectivity test: **14,263 tokens**,
  **$0.00319605**, about **0.32 cents**. This is not an account-wide audit.

Shared responses appear in multiple modes. Count each request once using
`actual_usage`; do not add per-mode costs. Missing cost means unknown, not free.

## Run It

Use Python 3.11 or newer. No extra packages are needed. From this folder:

```sh
python3 -B -m unittest test_baseline test_dynamic_policy test_isolation test_comparison test_expanded -v
```

That runs offline tests without a key or charges. For a fresh live comparison,
put `OPENROUTER_API_KEY` in the ignored `.env`. Optional `OPENROUTER_MODEL`
defaults to `openai/gpt-4o-mini`; shell settings override `.env`.

```sh
python3 run_comparison.py
```

This makes up to **30 paid requests**, with no retries. Set a dedicated key's
spending limit and keep total spending below **$75**; the code does not enforce
a budget. Never commit the real key. Ignoring a previously committed key does
not protect it; an exposed key must be rotated.

Results are saved under ignored `results/`, with original replies, decisions,
errors, tokens, and costs. To present existing findings, use [reports.md](reports.md)
instead of paying for another run. The latest local evidence is
`results/comparison_20261010T045254.804557Z.json` and its matching CSV
(the filename uses UTC). These raw files are not included in a GitHub clone.

## Limits

The October findings cover five variations of one task on one model. The
expanded inputs are synthetic and template-based, and still cover only two
read-only tasks. Their live results have not yet been measured. Modes share
responses and use different output formats. Attacks share a clean control and
setup within each expanded scenario, so rows are not independent experiments.
Invalid outputs are errors, not successful defenses.

The observed policy denial also matched permanent safety rules, so it does
not establish the generated policy's separate benefit. Combined showed no
advantage over isolation on these cases. This is a fixed-plan, CaMeL-inspired
demo, not the full interpreter or a reproduction of CaMeL, Conseca, or LogJack.
