from __future__ import annotations

import json
from dataclasses import replace
from unittest.mock import patch

from capagap.html_report import render_matrix_html
from capagap.io import load_document
from capagap.matrix import compare_matrix
from capagap.repeatability import analyze_repeatability, render_repeatability
from tests.test_evidence import HTTP, rich_document, write_document
from tests.test_workflows import WorkflowTestCase


class RepeatabilityTests(WorkflowTestCase):
    def setUp(self):
        super().setUp()
        raw = rich_document("dynamic")
        raw["meta"]["timestamp"] = "2026-01-02T00:00:00Z"
        raw["rules"].pop(HTTP)
        self.repeat_path = write_document(self.root, raw, "repeat.json")
        self.repeat = load_document(self.repeat_path)

    def matrix(self, second=None, conditions=None):
        return compare_matrix(
            self.static,
            [("a", self.dynamic), ("b", second or self.repeat)],
            experiment_conditions=conditions
            if conditions is not None
            else [("a", "network", "off"), ("b", "network", "off")],
        )

    def test_counts_intermittent_observations(self):
        matrix = self.matrix()
        result = analyze_repeatability(matrix)
        group = result["groups"][0]
        row = next(row for row in group["capabilities"] if row["name"] == HTTP)
        self.assertEqual(row["observed_count"], 1)
        self.assertEqual(row["run_count"], 2)
        self.assertEqual(row["state"], "intermittent")
        self.assertEqual(
            sum(group["counts"].values()), matrix.summary.comparable_static_rules
        )
        self.assertEqual(matrix.to_dict()["repeatability"], result)
        self.assertIn("1/2 observed", render_repeatability(result))

    def test_duplicates_do_not_count_as_trials(self):
        result = analyze_repeatability(self.matrix(self.dynamic))
        self.assertEqual(result["duplicates"], [{"label": "b", "duplicate_of": "a"}])
        self.assertFalse(result["groups"][0]["assessed"])
        self.assertEqual(result["groups"][0]["capabilities"], [])

    def test_unknown_and_incomplete_conditions_are_not_pooled(self):
        for conditions in ([], [("a", "network", "off"), ("b", "locale", "en")]):
            result = analyze_repeatability(self.matrix(conditions=conditions))
            self.assertEqual(result["groups"], [])
            self.assertEqual(len(result["unassessed_runs"]), 2)

    def test_extractor_or_condition_changes_split_groups(self):
        different = replace(self.repeat, extractor="OtherExtractor")
        self.assertEqual(
            len(analyze_repeatability(self.matrix(different))["groups"]), 2
        )
        result = analyze_repeatability(
            self.matrix(conditions=[("a", "network", "off"), ("b", "network", "on")])
        )
        self.assertEqual(len(result["groups"]), 2)
        self.assertFalse(any(g["assessed"] for g in result["groups"]))

    def test_missing_context_or_identity_is_unassessed(self):
        for second in (
            replace(self.repeat, extractor="unknown"),
            replace(self.repeat, sample_sha256=""),
        ):
            result = analyze_repeatability(self.matrix(second))
            self.assertEqual(result["unassessed_runs"][0]["label"], "b")

    def test_drift_is_not_classified_as_repeatability(self):
        rule = replace(self.dynamic.rules[HTTP], source_digest="e" * 64)
        changed = replace(self.repeat, rules={**self.repeat.rules, HTTP: rule})
        result = analyze_repeatability(self.matrix(changed))
        row = next(r for r in result["groups"][0]["capabilities"] if r["name"] == HTTP)
        self.assertEqual(row["state"], "source-unverified")
        self.assertTrue(result["warnings"])

    def test_detail_budget_does_not_change_summary(self):
        with patch("capagap.repeatability.MAX_DETAIL_ROWS", 1):
            group = analyze_repeatability(self.matrix())["groups"][0]
        self.assertEqual(len(group["capabilities"]), 1)
        self.assertEqual(group["capabilities"][0]["state"], "intermittent")
        self.assertEqual(group["omitted_capabilities"], 3)
        self.assertEqual(sum(group["counts"].values()), 4)

    def test_empty_denominator_does_not_claim_success(self):
        matrix = replace(self.matrix(), findings=())
        group = analyze_repeatability(matrix)["groups"][0]
        self.assertEqual(group["capabilities"], [])
        self.assertEqual(sum(group["counts"].values()), 0)

    def test_html_escapes_condition_values(self):
        html = render_matrix_html(
            self.matrix(
                conditions=[
                    ("a", "network", "<img src=x>"),
                    ("b", "network", "<img src=x>"),
                ]
            )
        )
        self.assertIn('id="run-repeatability"', html)
        self.assertIn("&lt;img src=x&gt;", html)
        self.assertNotIn("<img src=x>", html)

    def test_cli_formats_strict_and_input_protection(self):
        args = [
            "repeatability",
            self.static_path,
            "--run",
            f"a={self.dynamic_path}",
            "--run",
            f"b={self.repeat_path}",
            "--condition",
            "a:network=off",
            "--condition",
            "b:network=off",
        ]
        for fmt in ("text", "markdown", "json", "html"):
            code, output, errors = self.cli(*args, "--format", fmt, "--strict")
            self.assertEqual(code, 0, errors)
            self.assertIn("repeatability", output.lower())
        self.assertEqual(self.cli(*args, "--output", self.static_path)[0], 2)
        code, output, errors = self.cli(
            "repeatability",
            self.static_path,
            "--run",
            f"a={self.dynamic_path}",
            "--run",
            f"b={self.repeat_path}",
            "--strict",
        )
        self.assertEqual(code, 4)
        self.assertEqual(output, "")

    def test_cli_json_is_standalone_repeatability_report(self):
        code, output, errors = self.cli(
            "repeatability",
            self.static_path,
            "--run",
            f"a={self.dynamic_path}",
            "--run",
            f"b={self.repeat_path}",
            "--format",
            "json",
        )
        self.assertEqual(code, 0, errors)
        self.assertEqual(json.loads(output)["schema"], "capagap-repeatability")
