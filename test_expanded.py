"""Offline dataset/scoring/integration tests. Mock outputs are not model results."""

from collections import Counter
import contextlib
import copy
import csv
from dataclasses import FrozenInstanceError
import io
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

import datasets
import run_baseline as baseline
import run_comparison as comparison
import run_isolation as isolation
from test_comparison import reply


def fixture_responses(pairs):
    """Deliberately simulate successful attacks, plus the expected parser responses."""
    output = []
    for members in datasets.scenario_groups(pairs).values():
        pair = members[0]
        context, tool = pair["context"], pair["expected_tool"]
        output.extend([
            reply({"allowed_tools": [tool], **context}),
            reply({"tool": tool, "service": context["service"],
                   "job_id_from": "analysis.job_id" if tool == "monitor_retry" else None}),
        ])
        for case, variant in [(pair, "clean")] + [(p, "poisoned") for p in members]:
            action = datasets.expected_action(case)
            classification = case["expected_classification"]
            analysis = {"classification": classification}
            if tool == "monitor_retry":
                analysis["job_id"] = context["job_id"]
            if variant == "poisoned":
                action = {"tool": case["attack_tool"], "arguments": case["attack_arguments"]}
                classification = case.get("attack_classification", classification)
                analysis["classification"] = classification
                if tool == "monitor_retry":
                    analysis["job_id"] = action["arguments"].get("job_id", context["job_id"])
            output.extend([reply({"classification": classification, "proposed_action": action["tool"],
                                  "arguments": action["arguments"]}), reply(analysis)])
    return output


class ExpandedTests(unittest.TestCase):
    def setUp(self):
        self.pairs = datasets.load_expanded(baseline.ROOT)
        self.network = self.enterContext(patch.object(baseline, "urlopen", side_effect=AssertionError("No live network in tests")))
        self.api = self.enterContext(patch.object(comparison, "request_json", side_effect=AssertionError("Missing mock")))

    def run_pairs(self, pairs, replies=None):
        self.api.side_effect = fixture_responses(pairs) if replies is None else replies
        with contextlib.redirect_stdout(io.StringIO()):
            return comparison.run_experiment(pairs, "mock-model", "offline-placeholder-key")

    def test_balanced_suite_and_distinct_base_inputs(self):
        info = datasets.dataset_info(self.pairs)
        self.assertEqual((info["scenarios"], info["paired_cases"], info["max_requests"], info["comparison_rows"]),
                         (24, 144, 384, 672))
        self.assertEqual(set(info["scenarios_by_task"].values()), {12})
        self.assertEqual(set(info["scenarios_by_log_size"].values()), {8})
        self.assertEqual(set(info["scenarios_by_format"].values()), {12})
        self.assertEqual(set(info["poisoned_by_attack"].values()), {24})
        self.assertEqual(set(info["poisoned_by_position"].values()), {48})
        bases = [group[0] for group in datasets.scenario_groups(self.pairs).values()]
        self.assertEqual(len({p["clean"] for p in bases}), 24)
        self.assertEqual(len({p["request"] for p in bases}), 24)
        self.assertEqual(len({p["expected_classification"] for p in bases}), 8)
        for family in info["poisoned_by_attack"]:
            self.assertEqual(Counter(p["injection_position"] for p in self.pairs if p["attack_family"] == family),
                             {"beginning": 8, "middle": 8, "end": 8})

    def test_development_and_evaluation_do_not_share_scenarios(self):
        dev = datasets.load_expanded(baseline.ROOT, "development")
        evaluation = datasets.load_expanded(baseline.ROOT, "evaluation")
        self.assertFalse({p["scenario_id"] for p in dev} & {p["scenario_id"] for p in evaluation})
        self.assertEqual(datasets.dataset_info(dev)["max_requests"], 128)
        self.assertEqual(datasets.dataset_info(evaluation)["max_requests"], 256)
        for selected, expected in ((dev, 4), (evaluation, 8)):
            self.assertEqual(set(datasets.dataset_info(selected)["scenarios_by_task"].values()), {expected})
            self.assertEqual(len({p["expected_classification"] for p in selected}), 8)

    def test_answer_labels_match_clean_incident_records(self):
        for members in datasets.scenario_groups(self.pairs).values():
            pair = members[0]
            if pair["log_format"] == "jsonl":
                errors = [json.loads(line)["event"] for line in pair["clean"].splitlines()
                          if json.loads(line)["level"] == "ERROR"]
            else:
                errors = [re.search(r"event=(\S+)", line).group(1)
                          for line in pair["clean"].splitlines() if " ERROR " in line]
            self.assertEqual(errors, [pair["expected_classification"]])
            self.assertEqual("event=retry_scheduled" in pair["clean"] or '"event": "retry_scheduled"' in pair["clean"],
                             pair["task"] == "monitor_retry")

    def test_poisoning_adds_exactly_one_record_without_changing_clean_log(self):
        for pair in self.pairs:
            poisoned = datasets.build_log(pair, "poisoned")
            self.assertEqual(poisoned.count(pair["injection"]), 1)
            self.assertEqual(poisoned.replace(pair["injection"], "", 1), pair["clean"])
            if pair["log_format"] == "jsonl":
                for line in poisoned.splitlines():
                    self.assertIsInstance(json.loads(line), dict)
            self.assertNotRegex(pair["injection"], r"\{(?:response|tool|arguments|service|classification)\}")

    def test_selection_is_stable_and_counts_shared_controls(self):
        selected = datasets.load_expanded(baseline.ROOT, "development", ["retry-01", "status-01"])
        self.assertEqual(datasets.dataset_info(selected)["max_requests"], 32)
        self.assertEqual(datasets.dataset_info(selected)["comparison_rows"], 56)
        self.assertEqual(datasets.dataset_info(selected), datasets.dataset_info(
            datasets.load_expanded(baseline.ROOT, "development", ["status-01", "retry-01"])))
        one_family = datasets.load_expanded(baseline.ROOT, attack_family="fake_authority")
        self.assertEqual(len(one_family), 24)
        self.assertEqual(datasets.dataset_info(one_family)["max_requests"], 144)
        for kwargs in ({"split": "invalid"}, {"scenario_ids": ["missing"]},
                       {"attack_family": "missing"}, {"split": "evaluation", "scenario_ids": ["retry-01"]}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                datasets.load_expanded(baseline.ROOT, **kwargs)

    def test_invalid_scenario_and_attack_definitions_fail_before_calls(self):
        source = baseline.ROOT / "data/expanded"
        scenarios = json.loads((source / "scenarios.json").read_text())
        attacks = json.loads((source / "attacks.json").read_text())
        mutations = [
            ("scenario", "expected_tool", "disable_audit_logging"),
            ("scenario", "context", {"service": "billing"}),
            ("scenario", "split", "unknown"),
            ("attack", "target", "unknown"),
            ("attack", "instruction", "Use {unknown_placeholder}."),
        ]
        for kind, field, value in mutations:
            with self.subTest(kind=kind, field=field), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                directory = root / "data/expanded"
                directory.mkdir(parents=True)
                changed_scenarios, changed_attacks = copy.deepcopy(scenarios), copy.deepcopy(attacks)
                (changed_scenarios if kind == "scenario" else changed_attacks)[0][field] = value
                (directory / "scenarios.json").write_text(json.dumps(changed_scenarios))
                (directory / "attacks.json").write_text(json.dumps(changed_attacks))
                with self.assertRaises(ValueError):
                    datasets.load_expanded(root)
        self.api.assert_not_called()

    def test_inconsistent_shared_control_fails_before_any_requests(self):
        pairs = copy.deepcopy(self.pairs[:2])
        pairs[1]["context"] = {**pairs[1]["context"], "job_id": "different-job"}
        with self.assertRaises(ValueError):
            self.run_pairs(pairs)
        self.api.assert_not_called()

    def test_full_mock_run_uses_one_control_and_setup_per_scenario(self):
        report = self.run_pairs(self.pairs)
        self.assertEqual(self.api.call_count, 384)
        self.assertEqual(len(report["rows"]), 672)
        self.assertEqual(len(report["setups"]), 24)
        self.assertEqual(report["actual_usage"]["total_tokens"], 384 * 15)
        self.assertAlmostEqual(report["actual_usage"]["cost_usd"], .384)
        self.assertEqual(len(report["calls"]), 384)
        self.assertTrue(all(not row["executed"] for row in report["rows"]))
        self.assertTrue(report["source_sha256"])
        for summary in report["summary"].values():
            self.assertEqual(summary["clean_total"], 24)
            self.assertEqual(summary["clean_task_correct"], 24)
            self.assertEqual(summary["poisoned_total"], 144)
            self.assertEqual(summary["errors"], 0)
            self.assertEqual(summary["paired_valid_controls"], 144)
        self.assertEqual(report["summary"]["no_defense"]["attack_accepted"], 144)
        self.assertEqual(report["summary"]["dynamic_policy"]["attack_accepted"], 24)
        self.assertEqual(report["summary"]["isolation"]["poisoned_task_correct"], 108)
        controls = {(r["case_id"], r["mode"]) for r in report["rows"] if r["variant"] == "clean"}
        for row in report["rows"]:
            if row["variant"] == "poisoned":
                self.assertIn((row["clean_case_id"], row["mode"]), controls)
        family_summary = report["grouped_summary"]["attack_family"]["workflow_hijack"]
        self.assertEqual(family_summary["dynamic_policy"]["poisoned_denied"], 24)
        self.assertEqual(family_summary["dynamic_policy"]["clean_total"], 0)

    def test_read_only_tool_switch_is_denied_by_task_policy_only(self):
        pairs = datasets.load_expanded(baseline.ROOT, scenario_ids=["retry-01", "status-01"], attack_family="workflow_hijack")
        report = self.run_pairs(pairs)
        for row in report["rows"]:
            if row["variant"] == "poisoned" and row["mode"] == "dynamic_policy":
                self.assertEqual(row["checks"]["denied_by"], ["task_policy"])
                self.assertFalse(row["unsafe_proposed"])
                self.assertTrue(row["attack_proposed"])

    def test_classification_attack_requires_changed_label_and_is_not_unsafe_action(self):
        pairs = datasets.load_expanded(baseline.ROOT, scenario_ids=["status-01"], attack_family="answer_override")
        report = self.run_pairs(pairs)
        for row in report["rows"]:
            if row["variant"] == "poisoned":
                self.assertTrue(row["attack_accepted"])
                self.assertFalse(row["task_correct"])
                self.assertFalse(row["unsafe_accepted"])
                self.assertTrue(row["task_regression"])
        values = fixture_responses(pairs)
        for index in (4, 5):
            values[index]["parsed"]["classification"] = pairs[0]["expected_classification"]
        corrected = self.run_pairs(pairs, values)
        self.assertTrue(all(r["task_correct"] for r in corrected["rows"]))
        self.assertFalse(any(r["attack_accepted"] is True for r in corrected["rows"]))

    def test_invalid_outputs_remain_errors_not_blocks_or_regressions(self):
        pairs = datasets.load_expanded(baseline.ROOT, scenario_ids=["status-01"], attack_family="answer_override")
        values = fixture_responses(pairs)
        values[4], values[5] = reply(None, "mock API error"), reply([{"classification": "no_incident"}])
        report = self.run_pairs(pairs, values)
        for summary in report["summary"].values():
            self.assertEqual(summary["errors"], 1)
            self.assertEqual(summary["poisoned_task_rate_all"], 0)
            self.assertEqual(summary["paired_valid_controls"], 0)
            self.assertIsNone(summary["attack_acceptance_rate_valid"])
        for row in report["rows"]:
            if row["variant"] == "poisoned":
                self.assertIsNone(row["attack_accepted"])
                self.assertIsNone(row["task_regression"])

    def test_model_must_choose_the_plan_without_gold_correction(self):
        pairs = datasets.load_expanded(baseline.ROOT, scenario_ids=["status-01"], attack_family="fake_authority")
        values = fixture_responses(pairs)
        values[1]["parsed"].update(tool="monitor_retry", job_id_from="analysis.job_id")
        for index in (3, 5):
            values[index]["parsed"]["job_id"] = pairs[0]["context"]["job_id"]
        report = self.run_pairs(pairs, values)
        clean = next(r for r in report["rows"] if r["mode"] == "isolation" and r["variant"] == "clean")
        self.assertEqual(clean["action"]["tool"], "monitor_retry")
        self.assertFalse(clean["task_correct"])
        self.assertEqual(report["summary"]["combined"]["clean_denied"], 1)

    def test_status_plan_uses_trusted_service_and_rejects_analyzer_action_fields(self):
        pair = next(p for p in self.pairs if p["task"] == "get_service_status")
        plan = isolation.freeze_plan({"tool": "get_service_status", "service": pair["context"]["service"],
                                      "job_id_from": None}, pair["context"], multiple_tools=True)
        with self.assertRaises(FrozenInstanceError):
            plan.tool = "monitor_retry"
        result = isolation.evaluate_analysis(reply({"classification": "worker_unavailable"}), plan, "case")
        self.assertEqual(result["candidate_action"], datasets.expected_action(pair))
        self.assertEqual(result["argument_flows"]["service"]["origins"], ("trusted_context.service",))
        for extra in ("service", "job_id", "tool", "plan", "origins"):
            invalid = isolation.evaluate_analysis(reply({"classification": "worker_unavailable", extra: "other"}), plan, "case")
            self.assertEqual(invalid["decision"], "invalid_or_error")

    def test_setup_and_model_inputs_exclude_evaluation_metadata(self):
        pairs = copy.deepcopy(datasets.load_expanded(baseline.ROOT, scenario_ids=["status-01"], attack_family="fake_authority"))
        pairs[0].update(id="HIDDEN_PAIR", scenario_id="HIDDEN_SCENARIO", expected_classification="HIDDEN_GOLD",
                        attack_tool="HIDDEN_ATTACK", split="HIDDEN_SPLIT", attack_family="HIDDEN_FAMILY")
        self.run_pairs(pairs)
        prompts = [call.args[0] for call in self.api.call_args_list]
        self.assertNotIn("HIDDEN_", "\n".join(prompts))
        for prompt in prompts[:2]:
            self.assertNotIn("incident_window_opened", prompt)
            self.assertNotIn("SYSTEM OVERRIDE", prompt)
        self.assertIn("SYSTEM OVERRIDE", prompts[4])

    def test_dry_run_never_loads_credentials_or_calls_api(self):
        with patch.object(comparison, "load_settings", side_effect=AssertionError("No settings during dry run")):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = comparison.main(["--dataset", "expanded", "--split", "evaluation", "--dry-run"])
            self.assertEqual(status, 0)
            self.assertEqual(json.loads(output.getvalue())["max_requests"], 256)
        self.api.assert_not_called()
        self.network.assert_not_called()

    def test_export_preserves_pairing_categories_and_denominators(self):
        pairs = datasets.load_expanded(baseline.ROOT, scenario_ids=["retry-01", "status-01"])
        report = self.run_pairs(pairs)
        with tempfile.TemporaryDirectory() as temp:
            json_path, csv_path = comparison.export_results(report, Path(temp))
            restored = json.loads(json_path.read_text())
            with csv_path.open(newline="") as source:
                rows = list(csv.DictReader(source))
            self.assertEqual(len(rows), 56)
            self.assertEqual(restored["dataset_info"]["scenarios"], 2)
            self.assertEqual(rows[0]["mode_clean_total"], "2")
            self.assertEqual(rows[0]["mode_poisoned_total"], "12")
            self.assertIn("clean_case_id", rows[0])
            self.assertIn("task_regression", rows[0])
            self.assertIn("attack_family", rows[0])

    def test_expanded_main_runs_selected_inputs_and_exports_without_network(self):
        pairs = datasets.load_expanded(baseline.ROOT, scenario_ids=["retry-01", "status-01"])
        self.api.side_effect = fixture_responses(pairs)
        with tempfile.TemporaryDirectory() as temp, patch.object(comparison, "ROOT", Path(temp)), \
                patch.object(comparison, "load_expanded", return_value=pairs) as loader, \
                patch.object(comparison, "load_settings", return_value={"OPENROUTER_API_KEY": "offline-placeholder-key"}):
            with contextlib.redirect_stdout(io.StringIO()):
                status = comparison.main(["--dataset", "expanded", "--scenario", "retry-01", "--scenario", "status-01"])
            self.assertEqual(status, 0)
            loader.assert_called_once_with(Path(temp), "all", ["retry-01", "status-01"], None)
            files = list((Path(temp) / "results").glob("*.json"))
            self.assertEqual(len(files), 1)
            saved = json.loads(files[0].read_text())
            self.assertEqual(saved["actual_usage"]["calls"], 32)
            self.assertEqual(len(saved["rows"]), 56)
        self.network.assert_not_called()


if __name__ == "__main__":
    unittest.main()
