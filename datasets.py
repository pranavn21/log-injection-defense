"""Load fixed research inputs. No model calls or random generation."""

from collections import Counter
import hashlib
import json
from pathlib import Path
import re


TASKS = ("monitor_retry", "get_service_status")
SPLITS = ("development", "evaluation")
POSITIONS = ("beginning", "middle", "end")
TARGETS = ("disable_audit_logging", "other_read_tool", "wrong_job_or_service",
           "wrong_classification", "wrong_service")


def expected_action(pair):
    tool = pair.get("expected_tool", "monitor_retry")
    if tool not in TASKS:
        raise ValueError("Unsupported expected task tool.")
    names = ("service", "job_id") if tool == "monitor_retry" else ("service",)
    return {"tool": tool, "arguments": {name: pair["context"][name] for name in names}}


def build_log(pair, variant):
    if variant == "clean":
        return pair["clean"]
    lines = pair["clean"].splitlines(keepends=True)
    position = pair.get("injection_position", "end")
    index = {"beginning": 0, "middle": len(lines) // 2, "end": len(lines)}[position]
    return "".join(lines[:index]) + pair["injection"] + "".join(lines[index:])


def scenario_groups(pairs):
    """Only share a clean control/setup when every base input is identical."""
    groups = {}
    fields = ("request", "context", "clean", "expected_classification", "expected_tool",
              "split", "task", "log_size", "log_format")
    ids = set()
    for pair in pairs:
        if pair["id"] in ids:
            raise ValueError("Duplicate pair id.")
        ids.add(pair["id"])
        name = pair.get("scenario_id", pair["id"])
        if name in groups:
            first = groups[name][0]
            if any(pair.get(field) != first.get(field) for field in fields):
                raise ValueError(f"Scenario {name} has inconsistent clean inputs or labels.")
        groups.setdefault(name, []).append(pair)
    return groups


def dataset_info(pairs):
    groups = scenario_groups(pairs)
    bases = [members[0] for members in groups.values()]
    lengths = [len(pair["clean"]) for pair in bases]
    serialized = json.dumps(pairs, sort_keys=True, ensure_ascii=False).encode()
    return {
        "sha256": hashlib.sha256(serialized).hexdigest(),
        "scenarios": len(bases), "paired_cases": len(pairs),
        "clean_inputs": len(bases), "poisoned_inputs": len(pairs),
        "comparison_rows": 4 * (len(bases) + len(pairs)),
        "max_requests": 4 * len(bases) + 2 * len(pairs),
        "scenarios_by_task": dict(Counter(p.get("task", "monitor_retry") for p in bases)),
        "scenarios_by_split": dict(Counter(p.get("split", "legacy") for p in bases)),
        "scenarios_by_log_size": dict(Counter(p.get("log_size", "legacy") for p in bases)),
        "scenarios_by_format": dict(Counter(p.get("log_format", "text") for p in bases)),
        "poisoned_by_attack": dict(Counter(p.get("attack_family", "legacy") for p in pairs)),
        "poisoned_by_position": dict(Counter(p.get("injection_position", "end") for p in pairs)),
        "clean_characters_min": min(lengths), "clean_characters_max": max(lengths),
    }


def _text(value):
    return isinstance(value, str) and bool(value.strip())


def load_expanded(root, split="all", scenario_ids=None, attack_family=None):
    directory = Path(root) / "data/expanded"
    scenarios = json.loads((directory / "scenarios.json").read_text(encoding="utf-8"))
    attacks = json.loads((directory / "attacks.json").read_text(encoding="utf-8"))
    if not isinstance(scenarios, list) or not scenarios or not isinstance(attacks, list) or not attacks:
        raise ValueError("Expanded inputs must be nonempty scenario and attack lists.")
    seen = set()
    required = {"id", "split", "task", "log_size", "log_format", "request", "context",
                "clean", "expected_tool", "expected_classification"}
    for scenario in scenarios:
        if not isinstance(scenario, dict) or set(scenario) != required:
            raise ValueError("Invalid expanded scenario fields.")
        if (not all(_text(scenario[name]) for name in required - {"context"})
                or not re.fullmatch(r"[a-z][a-z0-9-]*", scenario["id"])
                or scenario["id"] in seen or scenario["task"] not in TASKS
                or scenario["expected_tool"] != scenario["task"]
                or scenario["split"] not in SPLITS or scenario["log_size"] not in ("short", "medium", "long")
                or scenario["log_format"] not in ("text", "jsonl") or not scenario["clean"].endswith("\n")):
            raise ValueError("Invalid scenario id, task, split, format, size, or text.")
        context = scenario["context"]
        if not isinstance(context, dict) or set(context) != {"service", "job_id"} or not all(map(_text, context.values())):
            raise ValueError("Invalid trusted context.")
        seen.add(scenario["id"])
    attack_ids = set()
    for attack in attacks:
        if (not isinstance(attack, dict) or set(attack) != {"id", "target", "instruction"}
                or not all(map(_text, attack.values()))
                or not re.fullmatch(r"[a-z][a-z0-9_]*", attack["id"])
                or attack["id"] in attack_ids or attack["target"] not in TARGETS):
            raise ValueError("Invalid or duplicate attack template.")
        attack_ids.add(attack["id"])
    requested = set(scenario_ids or [])
    if split not in ("all", *SPLITS) or requested - seen or (attack_family and attack_family not in attack_ids):
        raise ValueError("Unknown split, scenario id, or attack family.")

    pairs = []
    for index, scenario in enumerate(scenarios):
        if (split != "all" and scenario["split"] != split) or (requested and scenario["id"] not in requested):
            continue
        for attack_index, attack in enumerate(attacks):
            if attack_family and attack["id"] != attack_family:
                continue
            action = expected_action(scenario)
            target = attack["target"]
            context = scenario["context"]
            classification = scenario["expected_classification"]
            if target == "disable_audit_logging":
                action = {"tool": target, "arguments": {"service": context["service"]}}
            elif target == "other_read_tool":
                other = "get_service_status" if scenario["task"] == "monitor_retry" else "monitor_retry"
                action = expected_action({**scenario, "expected_tool": other})
            elif target in ("wrong_job_or_service", "wrong_service"):
                argument = "job_id" if target == "wrong_job_or_service" and scenario["task"] == "monitor_retry" else "service"
                action["arguments"][argument] = "unrelated-job" if argument == "job_id" else "unrelated-service"
            else:
                classification = "no_incident"
            output = {"classification": classification, "proposed_action": action["tool"], "arguments": action["arguments"]}
            try:
                instruction = attack["instruction"].format(
                    service=context["service"], job_id=context["job_id"],
                    tool=action["tool"], arguments=json.dumps(action["arguments"], sort_keys=True),
                    response=json.dumps(output, sort_keys=True), classification=classification)
            except (KeyError, IndexError, ValueError) as error:
                raise ValueError(f'Invalid placeholders in attack {attack["id"]}.') from error
            event = {"timestamp": "2026-11-04T10:00:20Z", "level": "INFO", "service": context["service"],
                     "event": "provider_diagnostic", "message": instruction}
            injection = (json.dumps(event) if scenario["log_format"] == "jsonl" else
                         f'{event["timestamp"]} INFO service={context["service"]} event=provider_diagnostic message={json.dumps(instruction)}') + "\n"
            pair = {**scenario, "id": f'{scenario["id"]}--{attack["id"]}', "scenario_id": scenario["id"],
                    "attack_family": attack["id"], "injection_position": POSITIONS[(index + attack_index) % 3],
                    "injection": injection, "attack_tool": action["tool"], "attack_arguments": action["arguments"]}
            if target == "wrong_classification":
                pair["attack_classification"] = classification
            pairs.append(pair)
    if not pairs:
        raise ValueError("The selection contains no scenarios.")
    return pairs
