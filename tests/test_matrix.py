from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from capagap.analysis import ComparisonError
from capagap.cli import main
from capagap.html_report import render_matrix_html
from capagap.io import load_document
from capagap.matrix import compare_matrix
from capagap.render import (
    render_matrix_json,
    render_matrix_markdown,
    render_matrix_text,
)

ROOT = Path(__file__).resolve().parents[1]
STATIC_PATH = ROOT / "examples" / "static.json"
BASELINE_PATH = ROOT / "examples" / "dynamic.json"
INTERACTIVE_PATH = ROOT / "examples" / "dynamic-interactive.json"
STATIC = load_document(STATIC_PATH)
BASELINE = load_document(BASELINE_PATH)
INTERACTIVE = load_document(INTERACTIVE_PATH)
MATRIX = compare_matrix(STATIC, (("baseline", BASELINE), ("interactive", INTERACTIVE)))


class MatrixComparisonTests(unittest.TestCase):
    def test_calculates_union_coverage(self):
        self.assertEqual(MATRIX.summary.run_count, 2)
        self.assertEqual(MATRIX.summary.comparable_static_rules, 4)
        self.assertEqual(MATRIX.summary.union_observed_rules, 3)
        self.assertEqual(MATRIX.summary.union_coverage, 0.75)

    def test_separates_never_and_environment_sensitive(self):
        self.assertEqual(
            [item.rule.name for item in MATRIX.never_observed],
            ["inject shellcode into remote process"],
        )
        self.assertEqual(
            {item.rule.name for item in MATRIX.environment_sensitive},
            {"check for sandbox process names", "create scheduled task"},
        )
        self.assertEqual(
            [item.rule.name for item in MATRIX.observed_in_all],
            ["communicate over HTTP"],
        )

    def test_tracks_run_labels_for_deltas(self):
        scheduled = next(
            item
            for item in MATRIX.environment_sensitive
            if item.rule.name == "create scheduled task"
        )
        self.assertEqual(scheduled.observed_in, ("interactive",))
        self.assertEqual(scheduled.unobserved_in, ("baseline",))

    def test_aggregates_runtime_only_discoveries(self):
        self.assertEqual(MATRIX.dynamic_only["execute shell command"], ("baseline",))
        self.assertEqual(MATRIX.dynamic_only["capture screenshot"], ("interactive",))

    def test_preserves_per_run_evasion_context(self):
        self.assertEqual(
            MATRIX.gate_signals["baseline"], ("check for sandbox process names",)
        )
        self.assertNotIn("interactive", MATRIX.gate_signals)

    def test_requires_two_runs(self):
        with self.assertRaisesRegex(ComparisonError, "at least two"):
            compare_matrix(STATIC, (("only", BASELINE),))

    def test_rejects_duplicate_labels(self):
        with self.assertRaisesRegex(ComparisonError, "unique"):
            compare_matrix(STATIC, (("same", BASELINE), ("same", INTERACTIVE)))

    def test_enforces_sample_identity_per_run(self):
        mismatched = replace(INTERACTIVE, sample_sha256="f" * 64)
        with self.assertRaisesRegex(ComparisonError, "SHA-256"):
            compare_matrix(STATIC, (("baseline", BASELINE), ("other", mismatched)))

    def test_tracks_controlled_experiment_conditions(self):
        result = compare_matrix(
            STATIC,
            (("baseline", BASELINE), ("interactive", INTERACTIVE)),
            experiment_conditions=(
                ("baseline", "interaction", "off"),
                ("interactive", "interaction", "on"),
            ),
        )
        self.assertEqual(result.experiment_baseline, "baseline")
        self.assertEqual(result.runs[1].changed_conditions, ("interaction",))
        self.assertEqual(result.experiment_warnings, ())

    def test_warns_when_experiment_changes_multiple_conditions(self):
        result = compare_matrix(
            STATIC,
            (("baseline", BASELINE), ("interactive", INTERACTIVE)),
            experiment_conditions=(
                ("baseline", "interaction", "off"),
                ("baseline", "network", "off"),
                ("interactive", "interaction", "on"),
                ("interactive", "network", "on"),
            ),
        )
        self.assertTrue(
            any("causal attribution" in value for value in result.experiment_warnings)
        )

    def test_rejects_invalid_condition_metadata(self):
        with self.assertRaisesRegex(ComparisonError, "unknown run label"):
            compare_matrix(
                STATIC,
                (("baseline", BASELINE), ("interactive", INTERACTIVE)),
                experiment_conditions=(("missing", "network", "on"),),
            )
        with self.assertRaisesRegex(ComparisonError, "duplicate condition"):
            compare_matrix(
                STATIC,
                (("baseline", BASELINE), ("interactive", INTERACTIVE)),
                experiment_conditions=(
                    ("baseline", "network", "off"),
                    ("baseline", "network", "on"),
                ),
            )


class MatrixRenderTests(unittest.TestCase):
    def test_text_report_shows_deltas(self):
        report = render_matrix_text(MATRIX)
        self.assertIn("Union coverage:  75.0%", report)
        self.assertIn("Environment-sensitive behavior deltas", report)
        self.assertIn("interactive", report)

    def test_markdown_report_has_capability_matrix(self):
        report = render_matrix_markdown(MATRIX)
        self.assertIn("# CapaGap multi-environment report", report)
        self.assertIn("## Capability matrix", report)
        self.assertIn("| communicate over HTTP | info | ✓ | ✓ |", report)

    def test_json_report_is_versioned(self):
        payload = json.loads(render_matrix_json(MATRIX))
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["analysis_type"], "multi-run-matrix")
        self.assertEqual(payload["summary"]["union_coverage"], 0.75)

    def test_html_dashboard_is_self_contained(self):
        report = render_matrix_html(MATRIX)
        self.assertIn("<!doctype html>", report)
        self.assertIn("Multi-run capability coverage", report)
        self.assertNotIn("https://", report)
        self.assertNotIn("<script src=", report)
        self.assertNotIn("radial-gradient", report)
        self.assertNotIn("conic-gradient", report)
        self.assertNotIn("Change the lab", report)

    def test_cli_writes_matrix_dashboard(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "matrix.html"
            exit_code = main(
                [
                    "matrix",
                    str(STATIC_PATH),
                    "--run",
                    f"baseline={BASELINE_PATH}",
                    "--run",
                    f"interactive={INTERACTIVE_PATH}",
                    "--format",
                    "html",
                    "--output",
                    str(output),
                ]
            )
            self.assertEqual(exit_code, 0)
            self.assertIn("Capability matrix", output.read_text(encoding="utf-8"))

    def test_cli_can_fail_on_never_observed(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "matrix.json"
            exit_code = main(
                [
                    "matrix",
                    str(STATIC_PATH),
                    "--run",
                    f"baseline={BASELINE_PATH}",
                    "--run",
                    f"interactive={INTERACTIVE_PATH}",
                    "--format",
                    "json",
                    "--output",
                    str(output),
                    "--fail-on-never-observed",
                ]
            )
            self.assertEqual(exit_code, 3)


if __name__ == "__main__":
    unittest.main()
