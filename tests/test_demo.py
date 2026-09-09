from __future__ import annotations

import json
import os
from importlib.resources import files
from unittest.mock import patch

from capagap.cases import CaseError, load_case
from capagap.demo import create_demo
from tests.test_workflows import WorkflowTestCase


class DemoTests(WorkflowTestCase):
    def test_demo_is_portable_synthetic_and_self_contained(self):
        target = self.root / "demo"
        report = create_demo(target)
        case, comparison = load_case(target / "case")
        self.assertEqual(comparison.summary.union_coverage, 0.75)
        self.assertTrue(comparison.static.synthetic)
        self.assertTrue(
            all(run.comparison.dynamic.synthetic for run in comparison.runs)
        )
        self.assertIn("Synthetic example", report.read_text())
        self.assertEqual(
            json.loads((target / "report.json").read_text()), comparison.to_dict()
        )
        self.assertEqual(len(case["runs"]), 2)
        self.assertEqual(
            sorted(path.name for path in target.iterdir()),
            ["case", "report.html", "report.json"],
        )

    def test_resource_files_are_packaged_and_synthetic(self):
        for name in ("static", "baseline", "interactive"):
            resource = files("capagap").joinpath("demo_data", name + ".json")
            self.assertTrue(
                json.loads(resource.read_text(encoding="utf-8"))["meta"]["capagap"][
                    "synthetic"
                ]
            )

    def test_existing_output_is_never_replaced(self):
        target = self.root / "existing"
        target.mkdir()
        marker = target / "keep.txt"
        marker.write_text("preserve")
        with self.assertRaisesRegex(CaseError, "already exists"):
            create_demo(target)
        self.assertEqual(marker.read_text(), "preserve")

    def test_render_failure_leaves_no_partial_demo(self):
        target = self.root / "demo"
        with (
            patch("capagap.demo.render_matrix_html", side_effect=OSError("failed")),
            self.assertRaises(OSError),
        ):
            create_demo(target)
        self.assertFalse(target.exists())
        self.assertEqual(list(self.root.glob(".capagap-demo-*")), [])

    def test_cli_does_not_open_a_browser_without_request(self):
        with patch("capagap.workflows.webbrowser.open") as opener:
            code, output, error = self.cli("demo", "--output", self.root / "demo")
        self.assertEqual(code, 0, error)
        self.assertIn("synthetic demo", output)
        opener.assert_not_called()

    def test_explicit_open_uses_only_the_generated_local_file(self):
        target = self.root / "demo"
        with patch("capagap.workflows.webbrowser.open", return_value=True) as opener:
            code, _, error = self.cli("demo", "--output", target, "--open")
        self.assertEqual(code, 0, error)
        opener.assert_called_once_with((target / "report.html").resolve().as_uri())

    def test_failed_browser_launch_keeps_the_report(self):
        target = self.root / "demo"
        with patch("capagap.workflows.webbrowser.open", return_value=False):
            code, _, error = self.cli("demo", "--output", target, "--open")
        self.assertEqual(code, 4)
        self.assertTrue((target / "report.html").is_file())
        self.assertIn("Open the report path", error)

    def test_no_arguments_works_outside_the_checkout(self):
        previous = os.getcwd()
        try:
            os.chdir(self.root)
            code, _, error = self.cli("demo")
            self.assertEqual(code, 0, error)
            self.assertTrue((self.root / "capagap-demo/report.html").is_file())
        finally:
            os.chdir(previous)
