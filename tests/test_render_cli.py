from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from capagap.analysis import compare_documents
from capagap.cli import main
from capagap.html_report import render_html
from capagap.io import load_document
from capagap.render import render_json, render_markdown, render_text

ROOT = Path(__file__).resolve().parents[1]
STATIC_PATH = ROOT / "examples" / "static.json"
DYNAMIC_PATH = ROOT / "examples" / "dynamic.json"
RESULT = compare_documents(load_document(STATIC_PATH), load_document(DYNAMIC_PATH))


class RenderTests(unittest.TestCase):
    def test_text_report_has_boundary_language(self):
        report = render_text(RESULT)
        self.assertIn("Prioritized unobserved capabilities", report)
        self.assertIn("It does not prove", report)
        self.assertIn("inject shellcode into remote process", report)

    def test_markdown_report_is_structured(self):
        report = render_markdown(RESULT)
        self.assertIn("# CapaGap analysis report", report)
        self.assertIn("| Priority | Score |", report)
        self.assertIn("## Interpretation boundary", report)

    def test_json_report_is_machine_readable(self):
        payload = json.loads(render_json(RESULT))
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["summary"]["unobserved_rules"], 2)
        self.assertEqual(payload["unobserved"][0]["status"], "unobserved")

    def test_html_report_escapes_rule_content(self):
        first = RESULT.unobserved[0]
        unsafe = replace(
            first, rule=replace(first.rule, name="<script>alert(1)</script>")
        )
        report = render_html(
            replace(RESULT, unobserved=(unsafe, *RESULT.unobserved[1:]))
        )
        self.assertNotIn("<script>alert(1)</script>", report)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", report)

    def test_cli_writes_report(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.md"
            exit_code = main(
                [
                    "compare",
                    str(STATIC_PATH),
                    str(DYNAMIC_PATH),
                    "--format",
                    "markdown",
                    "--output",
                    str(output),
                ]
            )
            self.assertEqual(exit_code, 0)
            self.assertIn("CapaGap analysis report", output.read_text(encoding="utf-8"))

    def test_cli_can_fail_on_unobserved(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            exit_code = main(
                [
                    "compare",
                    str(STATIC_PATH),
                    str(DYNAMIC_PATH),
                    "--format",
                    "json",
                    "--output",
                    str(output),
                    "--fail-on-unobserved",
                ]
            )
            self.assertEqual(exit_code, 3)


if __name__ == "__main__":
    unittest.main()
