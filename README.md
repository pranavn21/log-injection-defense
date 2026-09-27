# Log Injection Defense: Comparing Isolation and Dynamic Policies

A small educational research project comparing ways to handle prompt injection
in untrusted log data. It will use OpenRouter so model IDs can change later.
The total experiment budget must stay **below $75**.

We will eventually compare four modes:

1. **No Defense:** measure the model's behavior on clean and poisoned logs.
2. **CaMeL-inspired isolation:** separate trusted planning from untrusted log analysis.
3. **Dynamic Policy:** enforce a task-specific policy with ordinary Python checks.
4. **Combined:** use isolation and dynamic policy together.

This is a focused demonstration, not a reproduction of the full CaMeL or
Conseca research implementations.

## Current status: Day 1 only

Only repository setup is implemented. There is no Python application, model
request, defense, dataset, evaluation, or UI yet. No model calls have been made
and no API credits have been spent.

## Your OpenRouter key

Enter your real key locally in `.env`, after `OPENROUTER_API_KEY=`. Do not paste
it into chat. The local file starts blank, is ignored by Git, and has owner-only
read/write permissions on macOS/Linux. Keep `.env.example` blank; it is the
shareable template showing the setting's name.

Keep the key out of source code, logs, reports, and Git. **`.gitignore` does not
remove previously committed secrets.** If a real key was committed, rotate it;
ignoring the file afterward is insufficient.

## Incremental roadmap

These are planned milestones, not automatic tasks. Add each increment only
when requested, and explain it before implementing it. Keep the code small
and dependencies minimal; no dashboard, database, or elaborate framework.

### Saturday, September 26, 2026 — Repository setup

Create `.gitignore`, this README, a blank key template, and a protected local
`.env`. No model calls.

### Sunday, September 27 — First request

Add one small Python script that reads the local key and makes one harmless
OpenRouter request. Keep the model ID configurable. Record the model and
available usage/cost information. Before paid calls, verify current API
documentation and pricing and use a dedicated key with a total spending limit
below $75.

### Monday, September 28 — No Defense baseline

Add one clean log and one poisoned version. Ask the model for a classification
and proposed action. Record proposals without executing them. Report actual
outcomes; never script a successful attack and present it as model evidence.

### Tuesday, September 29 — Dynamic Policy

Generate a small task-specific policy from the trusted analyst request and
trusted context only. Enforce it with ordinary Python checks on tool names and
arguments. Keep permanent safety rules separate. Compare the same clean/poisoned
pair against the baseline.

### Wednesday, September 30 — CaMeL-inspired isolation

The privileged planner sees trusted inputs, never raw logs or untrusted
analysis feedback. Fix the plan before log analysis. The quarantined analyzer
has no direct tool access and cannot modify the plan or policy. Track data
origins and allowed destinations when extracted values become action
arguments. Clearly document how this limited implementation differs from the
original CaMeL interpreter.

### Thursday, October 1 — Combined comparison

Combine isolation and dynamic policy. Expand to approximately five
clean/poisoned pairs and compare all four modes. Export a simple CSV/JSON
results table with errors, usage, costs, and evaluation denominators. Keep
evaluation labels out of model inputs.

### Friday, October 2 — Finish and demonstrate

- Morning: fix problems and repeat only necessary experiments.
- Afternoon: prepare a short explanation, results, limitations, and rehearsal.
- Evening: demonstrate the frozen version with saved results as a backup.

Avoid adding new features.

## Rules for later experiments

- All potentially harmful tools remain simulated. No real shell commands,
  cloud mutations, account changes, or data exports from injected content.
- Keep model manipulation separate from harmful-action acceptance.
- Measure legitimate task completion as well as attack outcomes.
- Do not count API errors or invalid outputs as successful defenses.
- Label any mocked tests clearly; never substitute them for live findings.
- Preserve the same tasks and model settings across comparable modes.
- Keep the key out of source code, logs, reports, and Git.
- Explain each increment before adding the next one.

## Today's completion checklist

- [x] Confirm the new workspace and initialize Git.
- [x] Create the four Day 1 files and restrict `.env` permissions to its owner.
- [x] Verify `.env` and sample `slides/`, `archive/`, and `results/` paths are ignored.
- [x] Verify `.env.example` and `README.md` remain trackable.
- [x] Check for tracked credential files without printing secret values (none found).
- [x] Review and commit only `.gitignore`, `README.md`, and `.env.example`
  using the configured Git identity.
- [ ] Publish to GitHub: pending a repository URL, or a repository name and
  visibility for creation. No remote is connected yet.
- [x] Stop after Day 1 with no model calls or API spending.
