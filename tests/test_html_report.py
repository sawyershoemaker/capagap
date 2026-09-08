from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from html.parser import HTMLParser
from pathlib import Path

from capagap.analysis import compare_documents
from capagap.html_report import render_html, render_matrix_html
from capagap.io import load_document
from capagap.matrix import compare_matrix
from capagap.models import AddressRecord

ROOT = Path(__file__).resolve().parents[1]
STATIC = load_document(ROOT / "examples" / "static.json")
DYNAMIC = load_document(ROOT / "examples" / "dynamic.json")
INTERACTIVE = load_document(ROOT / "examples" / "dynamic-interactive.json")
SINGLE = compare_documents(STATIC, DYNAMIC)
MATRIX = compare_matrix(
    STATIC,
    (("baseline", DYNAMIC), ("interactive", INTERACTIVE)),
    experiment_conditions=(
        ("baseline", "interaction", "off"),
        ("interactive", "interaction", "on"),
    ),
)


class ReportDOM(HTMLParser):
    def __init__(self, report: str):
        super().__init__(convert_charrefs=True)
        self.elements: list[tuple[str, dict[str, str | None]]] = []
        self.scripts: list[str] = []
        self.in_script = False
        self.feed(report)

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))
        if tag == "script":
            self.in_script = True
            self.scripts.append("")

    def handle_endtag(self, tag):
        if tag == "script":
            self.in_script = False

    def handle_data(self, data):
        if self.in_script:
            self.scripts[-1] += data

    def with_attr(self, attribute: str):
        return [attrs for _, attrs in self.elements if attribute in attrs]


class HTMLReportTests(unittest.TestCase):
    def test_export_name_is_explicit_and_payload_is_not_reserialized(self):
        for result, render, name in (
            (SINGLE, render_html, "comparison"),
            (MATRIX, render_matrix_html, "matrix"),
        ):
            dom = ReportDOM(render(result))
            self.assertEqual(
                dom.with_attr("data-export")[0]["data-export"], f"capagap-{name}.json"
            )
            handler = (
                dom.scripts[1]
                .split('select("[data-export]").addEventListener')[1]
                .split("let printState")[0]
            )
            self.assertNotIn("JSON.parse", handler)
            self.assertNotIn("JSON.stringify", handler)

    def test_single_and_matrix_use_the_same_offline_controls(self):
        for report, expected in (
            (render_html(SINGLE), 6),
            (render_matrix_html(MATRIX), 7),
        ):
            with self.subTest(expected=expected):
                dom = ReportDOM(report)
                self.assertEqual(len(dom.with_attr("data-record")), expected)
                self.assertEqual(len(dom.with_attr("data-group-button")), 3)
                ids = [attrs["id"] for attrs in dom.with_attr("id")]
                self.assertEqual(len(ids), len(set(ids)))
                toggles = dom.with_attr("aria-controls")
                self.assertEqual(len(toggles), expected)
                self.assertTrue(
                    all(toggle["aria-controls"] in ids for toggle in toggles)
                )
                self.assertEqual(
                    sum(toggle["aria-expanded"] == "true" for toggle in toggles), 1
                )
                self.assertEqual(len(dom.scripts), 2)
                self.assertFalse(dom.with_attr("src"))
                self.assertNotIn("fetch(", report)
                self.assertNotIn("@import", report)

    def test_embedded_export_matches_command_line_payload(self):
        for result, render in ((SINGLE, render_html), (MATRIX, render_matrix_html)):
            with self.subTest(type=type(result).__name__):
                dom = ReportDOM(render(result))
                self.assertEqual(json.loads(dom.scripts[0]), result.to_dict())

    def test_untrusted_text_cannot_create_markup_or_close_json_script(self):
        unsafe = '</script><img src=x onerror="alert(1)">&\' \\ "'
        rule = replace(
            SINGLE.unobserved[0].rule,
            name=unsafe,
            namespace=unsafe,
            description=unsafe,
            attack=({"id": unsafe},),
            evidence=(unsafe,),
            evidence_addresses=(AddressRecord("unknown", None, unsafe),),
        )
        result = replace(
            SINGLE,
            static=replace(STATIC, sample_path=unsafe),
            unobserved=(
                replace(
                    SINGLE.unobserved[0], rule=rule, reasons=(unsafe,), action=unsafe
                ),
            ),
            warnings=(unsafe,),
        )
        dom = ReportDOM(render_html(result))
        self.assertEqual(json.loads(dom.scripts[0]), result.to_dict())
        self.assertEqual(len(dom.scripts), 2)
        self.assertFalse(any(tag == "img" for tag, _ in dom.elements))
        self.assertFalse(
            any(key.startswith("on") for _, attrs in dom.elements for key in attrs)
        )
        self.assertIn(
            unsafe, [attrs["data-copy"] for attrs in dom.with_attr("data-copy")]
        )

    def test_run_labels_and_conditions_are_escaped(self):
        label = 'run"><svg onload=alert(1)>'
        condition = '</script>&"'
        result = compare_matrix(
            STATIC,
            ((label, DYNAMIC), ("other", INTERACTIVE)),
            experiment_conditions=((label, "interaction", condition),),
        )
        dom = ReportDOM(render_matrix_html(result))
        self.assertEqual(json.loads(dom.scripts[0]), result.to_dict())
        self.assertFalse(any("onload" in attrs for _, attrs in dom.elements))
        self.assertIn(
            label, [attrs["data-label"] for attrs in dom.with_attr("data-label")]
        )

    def test_all_evidence_locations_and_portable_rvas_are_available(self):
        addresses = tuple(
            AddressRecord("absolute", 0x404000 + n, f"0x{0x404000 + n:X}")
            for n in range(12)
        )
        finding = replace(
            SINGLE.unobserved[0],
            rule=replace(SINGLE.unobserved[0].rule, evidence_addresses=addresses),
        )
        dom = ReportDOM(render_html(replace(SINGLE, unobserved=(finding,))))
        values = [attrs["data-copy"] for attrs in dom.with_attr("data-copy")]
        for n in range(12):
            self.assertIn(f"0x{0x404000 + n:X}", values)
            self.assertIn(f"0x{0x4000 + n:X}", values)

    def test_unknown_base_does_not_invent_an_rva(self):
        result = compare_documents(replace(STATIC, base_address=None), DYNAMIC)
        report = render_html(result)
        dom = ReportDOM(report)
        evidence_buttons = [
            attrs
            for attrs in dom.with_attr("data-copy")
            if attrs.get("aria-label", "").startswith("Copy RVA")
        ]
        self.assertFalse(evidence_buttons)
        self.assertIn("Unmapped", report)
        self.assertIn("Not recorded", report)

    def test_relative_and_non_binary_addresses_keep_their_meaning(self):
        addresses = (
            AddressRecord("relative", 0x1234, "relative(0x1234)"),
            AddressRecord("file", 32, "file(0x20)"),
            AddressRecord("absolute", 0x100, "0x100"),
        )
        finding = replace(
            SINGLE.unobserved[0],
            rule=replace(SINGLE.unobserved[0].rule, evidence_addresses=addresses),
        )
        report = render_html(
            replace(SINGLE, unobserved=(finding,), evidence_hotspots=())
        )
        values = [
            attrs["data-copy"] for attrs in ReportDOM(report).with_attr("data-copy")
        ]
        self.assertIn("0x1234", values)
        self.assertIn("file(0x20)", values)
        self.assertIn("0x401234", report)
        self.assertNotIn("0x-3FFF00", report)

    def test_runtime_evidence_is_kept_separate_for_each_run(self):
        name = "execute shell command"
        rule = replace(
            DYNAMIC.rules[name],
            evidence_addresses=(AddressRecord("call", (8, 9, 10), "call(8:9:10)"),),
        )
        other = replace(INTERACTIVE, rules={**INTERACTIVE.rules, name: rule})
        result = compare_matrix(STATIC, (("baseline", DYNAMIC), ("interactive", other)))
        report = render_matrix_html(result)
        self.assertIn("baseline evidence", report)
        self.assertIn("interactive evidence", report)
        self.assertIn("call(8:9:10)", report)
        dom = ReportDOM(report)
        copies = dom.with_attr("data-copy")
        self.assertFalse(
            any(attrs.get("aria-label") == "Copy RVA call(8:9:10)" for attrs in copies)
        )

    def test_excluded_rules_have_no_missing_observation_claim(self):
        result = replace(
            SINGLE,
            ruleset_unverified=(
                replace(SINGLE.unobserved[0], status="ruleset-unverified"),
            ),
        )
        dom = ReportDOM(render_html(result))
        excluded = [
            attrs
            for attrs in dom.with_attr("data-record")
            if attrs["data-group"] == "excluded"
        ]
        self.assertEqual(
            {attrs["data-state"] for attrs in excluded},
            {"static-only", "ruleset-unverified"},
        )
        self.assertTrue(all("hidden" in attrs for attrs in excluded))
        report = render_html(result)
        self.assertIn("Not comparable", report)
        self.assertIn("Its source could not be verified", report)

    def test_empty_report_uses_na_coverage_and_no_fake_findings(self):
        result = compare_documents(
            replace(STATIC, rules={}), replace(DYNAMIC, rules={})
        )
        report = render_html(result)
        self.assertFalse(ReportDOM(report).with_attr("data-record"))
        self.assertIn("<strong>n/a</strong>", report)
        self.assertIn("No comparable capabilities", report)

    def test_synthetic_banner_requires_explicit_metadata_on_every_input(self):
        self.assertIn("Synthetic example", render_matrix_html(MATRIX))
        mixed = compare_documents(STATIC, replace(DYNAMIC, synthetic=False))
        self.assertNotIn("Synthetic example", render_html(mixed))
        payload = json.loads(
            (ROOT / "examples" / "static.json").read_text(encoding="utf-8")
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            for marker in (None, "true", 1, {}, []):
                with self.subTest(marker=marker):
                    payload["meta"]["capagap"] = {"synthetic": marker}
                    path.write_text(json.dumps(payload), encoding="utf-8")
                    self.assertFalse(load_document(path).synthetic)


if __name__ == "__main__":
    unittest.main()
