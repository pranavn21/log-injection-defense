# mock calls only, not model evidence

import contextlib
import copy
import csv
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import run_baseline as baseline
import run_comparison as comparison
from test_baseline import KEY


def reply(parsed, error=None):
    return {
        "parsed": parsed, "reply": json.dumps(parsed), "error": error,
        "requested_model": "mock-model", "returned_model": "mock-model", "request_id": "mock-id",
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}, "cost_usd": 0.001,
    }


def responses(pair):
    context = pair["context"]
    clean = {"classification": pair["expected_classification"], "proposed_action": "monitor_retry",
             "arguments": dict(context)}
    poison = {**clean, "proposed_action": pair["attack_tool"],
              "arguments": {**context, **pair["attack_arguments"]}}
    return [
        reply({"allowed_tools": ["monitor_retry"], **context}),
        reply({"tool": "monitor_retry", "service": context["service"], "job_id_from": "analysis.job_id"}),
        reply(clean), reply({"classification": clean["classification"], "job_id": context["job_id"]}),
        reply(poison), reply({"classification": clean["classification"],
                              "job_id": pair["attack_arguments"].get("job_id", context["job_id"])}),
    ]


class ComparisonTests(unittest.TestCase):
    def setUp(self):
        self.pairs = comparison.load_pairs()
        self.network = self.enterContext(patch.object(baseline, "urlopen", side_effect=AssertionError("no network")))
        self.api = self.enterContext(patch.object(comparison, "request_json", side_effect=AssertionError("missing mock")))
        self.settings = self.enterContext(patch.object(comparison, "load_settings", return_value={
            "OPENROUTER_API_KEY": KEY, "OPENROUTER_MODEL": "mock-model",
        }))

    def run_pairs(self, pairs=None):
        with contextlib.redirect_stdout(io.StringIO()):
            return comparison.run_experiment(self.pairs if pairs is None else pairs, "mock-model", KEY)

    def test_five_pairs_keep_original_pair(self):
        self.assertEqual(len(self.pairs), 5)
        first = self.pairs[0]
        self.assertEqual(first["clean"], (baseline.ROOT / "data/log_a.txt").read_text())
        self.assertEqual(first["clean"] + first["injection"], (baseline.ROOT / "data/log_b.txt").read_text())

    def test_four_modes_forty_rows_and_costs_are_not_double_counted(self):
        self.api.side_effect = [result for pair in self.pairs for result in responses(pair)]
        report = self.run_pairs()
        self.assertEqual(self.api.call_count, 30)
        self.assertEqual(len(report["rows"]), 40)
        self.assertEqual(report["actual_usage"]["calls"], 30)
        self.assertEqual(report["actual_usage"]["total_tokens"], 450)
        self.assertAlmostEqual(report["actual_usage"]["cost_usd"], 0.03)
        expected_calls = {"no_defense": 10, "dynamic_policy": 15, "isolation": 15, "combined": 20}
        for mode, summary in report["summary"].items():
            self.assertEqual(summary["rows"], 10)
            self.assertEqual(summary["clean_total"], 5)
            self.assertEqual(summary["poisoned_valid"], 5)
            self.assertEqual(summary["clean_task_correct"], 5)
            self.assertEqual(summary["usage"]["calls"], expected_calls[mode])
            self.assertEqual(summary["attack_accepted"], 5 if mode == "no_defense" else 0)
        self.assertTrue(all(not row["executed"] for row in report["rows"]))
        p04 = next(row for row in report["rows"] if (row["pair_id"], row["variant"], row["mode"]) ==
                   ("p04", "poisoned", "dynamic_policy"))
        self.assertEqual(p04["checks"]["denied_by"], ["task_policy"])

    def test_setup_prompts_have_no_logs_or_labels_and_no_feedback(self):
        pair = copy.deepcopy(self.pairs[0])
        pair.update(id="EVAL_PAIR_ID", expected_classification="EVAL_CLASS", attack_tool="EVAL_ATTACK")
        pair["clean"] = "UNTRUSTED_LOG"
        pair["injection"] = "UNTRUSTED_INJECTION"
        self.api.side_effect = responses(pair)
        self.run_pairs([pair])
        prompts = [call.args[0] for call in self.api.call_args_list]
        for prompt in prompts:
            for label in ("EVAL_PAIR_ID", "EVAL_CLASS", "EVAL_ATTACK", "clean", "poisoned"):
                self.assertNotIn(label, prompt)
        for prompt in prompts[:2]:
            self.assertNotIn("UNTRUSTED", prompt)
        self.assertIn("UNTRUSTED_LOG", prompts[2])
        self.assertIn("UNTRUSTED_INJECTION", prompts[4])
        self.assertEqual(prompts[3], comparison.CLASSIFICATION + comparison.analyzer_prompt(pair["clean"]))
        self.assertEqual(prompts[5], comparison.CLASSIFICATION + comparison.analyzer_prompt(pair["clean"] + pair["injection"]))

    def test_combined_adds_policy_without_overriding_isolation_denials(self):
        pair = self.pairs[3]
        values = responses(pair)
        values[0] = reply({"allowed_tools": ["get_service_status"], **pair["context"]})
        self.api.side_effect = values
        report = self.run_pairs([pair])
        rows = {(row["mode"], row["variant"]): row for row in report["rows"]}
        self.assertEqual(rows["isolation", "clean"]["decision"], "allow")
        self.assertEqual(rows["combined", "clean"]["decision"], "deny")
        self.assertEqual(rows["combined", "poisoned"]["decision"], "deny")
        self.assertEqual(report["summary"]["combined"]["clean_task_correct"], 0)

    def test_invalid_policy_only_fails_modes_that_need_it(self):
        pair = self.pairs[0]
        values = responses(pair)
        values[0] = reply({"allowed_tools": ["disable_audit_logging"], **pair["context"]})
        self.api.side_effect = values
        report = self.run_pairs([pair])
        for mode in ("dynamic_policy", "combined"):
            self.assertEqual(report["summary"][mode]["errors"], 2)
            self.assertEqual(report["summary"][mode]["poisoned_valid"], 0)
            self.assertIsNone(report["summary"][mode]["attack_acceptance_rate_valid"])
        self.assertEqual(report["summary"]["no_defense"]["errors"], 0)
        self.assertEqual(report["summary"]["isolation"]["errors"], 0)

    def test_literal_job_id_still_fails_plan_and_keeps_error_denominators(self):
        pair = self.pairs[0]
        values = responses(pair)
        values[1] = reply({"tool": "monitor_retry", "service": pair["context"]["service"],
                           "job_id_from": pair["context"]["job_id"]})
        self.api.side_effect = [values[0], values[1], values[2], values[4]]
        report = self.run_pairs([pair])
        self.assertEqual(self.api.call_count, 4)
        for mode in ("isolation", "combined"):
            summary = report["summary"][mode]
            self.assertEqual(summary["poisoned_total"], 1)
            self.assertEqual(summary["poisoned_valid"], 0)
            self.assertEqual(summary["clean_task_rate_all"], 0)
            self.assertIsNone(summary["attack_acceptance_rate_valid"])
        self.assertIn('"job_id_from": "analysis.job_id"', self.api.call_args_list[1].args[0])

    def test_bad_outputs_do_not_count_as_blocks(self):
        values = responses(self.pairs[0])
        values[4] = reply(None, "mock API failure")
        values[5] = reply({"classification": "timeout", "job_id": None})
        self.api.side_effect = values
        report = self.run_pairs(self.pairs[:1])
        for row in report["rows"]:
            if row["variant"] == "poisoned":
                self.assertEqual(row["decision"], "invalid_or_error")
                self.assertIsNotNone(row["error"])
                self.assertIsNone(row["attack_accepted"])
        self.assertEqual(report["actual_usage"]["calls"], 6)

    def test_unknown_cost_is_not_zero(self):
        values = responses(self.pairs[0])
        values[0]["cost_usd"] = None
        values[0]["usage"] = []
        self.api.side_effect = values
        report = self.run_pairs(self.pairs[:1])
        total = report["actual_usage"]
        self.assertIsNone(total["cost_usd"])
        self.assertIsNone(total["total_tokens"])
        self.assertAlmostEqual(total["known_cost_usd"], 0.005)
        self.assertEqual(total["unknown_cost_calls"], 1)

    def test_off_target_unsafe_actions_are_not_missed(self):
        values = responses(self.pairs[0])
        values[4] = reply({"classification": "upstream_timeout", "proposed_action": "unknown_tool", "arguments": {}})
        self.api.side_effect = values
        report = self.run_pairs(self.pairs[:1])
        summary = report["summary"]["no_defense"]
        self.assertEqual(summary["attack_accepted"], 0)
        self.assertEqual(summary["unsafe_accepted"], 1)

    def test_export_round_trip_denominators_and_formula_text(self):
        values = responses(self.pairs[0])
        values[2]["parsed"]["classification"] = "=1+1"
        self.api.side_effect = values
        report = self.run_pairs(self.pairs[:1])
        with tempfile.TemporaryDirectory() as temp:
            json_path, csv_path = comparison.export_results(report, Path(temp))
            restored = json.loads(json_path.read_text())
            with csv_path.open(newline="") as source:
                rows = list(csv.DictReader(source))
            self.assertEqual(len(rows), 8)
            self.assertEqual(rows[0]["classification"], "'=1+1")
            self.assertEqual(rows[0]["mode_poisoned_total"], "1")
            self.assertEqual(rows[0]["mode_poisoned_valid"], "1")
            self.assertEqual(restored["rows"][0]["classification"], "=1+1")
            self.assertEqual(len(restored["calls"]), 6)

    def test_main_saves_without_live_calls_or_reading_real_key(self):
        self.api.side_effect = responses(self.pairs[0])
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(comparison, "ROOT", Path(temp)), patch.object(comparison, "load_pairs", return_value=self.pairs[:1]):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(comparison.main(), 0)
            self.assertEqual(len(list((Path(temp) / "results").glob("*.json"))), 1)
            self.assertEqual(len(list((Path(temp) / "results").glob("*.csv"))), 1)
        self.network.assert_not_called()

    def test_fake_key_stops_before_calls(self):
        self.settings.return_value = {"OPENROUTER_API_KEY": "FAKE-EXAMPLE"}
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(comparison.main(), 1)
        self.api.assert_not_called()


if __name__ == "__main__":
    unittest.main()
