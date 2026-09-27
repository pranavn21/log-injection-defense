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
