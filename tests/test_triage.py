from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from capagap.analysis import compare_documents
from capagap.cli import main
from capagap.handoff import build_single_handoff, write_handoff
from capagap.io import load_document
from capagap.triage import (
    TriageError,
    apply_triage,
    build_triage_worksheet,
    load_handoff,
    load_triage,
    render_triage_report,
)

ROOT = Path(__file__).resolve().parents[1]
STATIC = load_document(ROOT / "examples" / "static.json")
DYNAMIC = load_document(ROOT / "examples" / "dynamic.json")
BUNDLE = build_single_handoff(compare_documents(STATIC, DYNAMIC), run_label="baseline")


class TriageTests(unittest.TestCase):
    def test_malformed_applied_reviews_are_rejected_consistently(self):
        worksheet = build_triage_worksheet(BUNDLE)
        worksheet["reviews"] = []
        for invalid in (
            None,
            [],
            {},
            {"disposition": []},
            {"disposition": "unknown"},
            {"disposition": "confirmed", "analyst_notes": []},
        ):
            bundle = copy.deepcopy(BUNDLE)
            bundle["findings"][0]["triage"] = invalid
            with self.subTest(triage=invalid):
                for operation in (apply_triage, render_triage_report):
                    with self.assertRaises(TriageError):
                        operation(bundle, worksheet)
                with self.assertRaises(TriageError):
                    build_triage_worksheet(bundle)
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "handoff.json"
                    path.write_text(json.dumps(bundle), encoding="utf-8")
                    with self.assertRaises(TriageError):
                        load_handoff(path)

    def test_worksheet_creation_rejects_boolean_handoff_version(self):
        bundle = copy.deepcopy(BUNDLE)
        bundle["schema_version"] = True
        with self.assertRaises(TriageError):
            build_triage_worksheet(bundle)

    def test_empty_and_partial_worksheets_count_missing_reviews_as_unreviewed(self):
        for retained in (0, 1):
            worksheet = build_triage_worksheet(BUNDLE)
            worksheet["reviews"] = worksheet["reviews"][:retained]
            if retained:
                worksheet["reviews"][0]["disposition"] = "confirmed"
            applied = apply_triage(BUNDLE, worksheet)
            self.assertEqual(
                applied["summary"]["triage"]["unreviewed"],
                len(BUNDLE["findings"]) - retained,
            )
            for markdown in (False, True):
                report = render_triage_report(BUNDLE, worksheet, markdown=markdown)
                self.assertIn(f"Reviewed: {'**' if markdown else ''}{retained}", report)
                for finding in BUNDLE["findings"]:
                    self.assertIn(finding["name"], report)

    def test_report_and_apply_reject_unknown_finding_ids(self):
        worksheet = build_triage_worksheet(BUNDLE)
        worksheet["reviews"][0]["id"] = "unknown"
        for operation in (apply_triage, render_triage_report):
            with (
                self.subTest(operation=operation.__name__),
                self.assertRaisesRegex(TriageError, "unknown finding id"),
            ):
                operation(BUNDLE, worksheet)

    def test_partial_update_preserves_previously_applied_reviews(self):
        worksheet = build_triage_worksheet(BUNDLE)
        worksheet["reviews"][0]["disposition"] = "confirmed"
        reviewed = apply_triage(BUNDLE, worksheet)
        partial = build_triage_worksheet(reviewed)
        partial["reviews"] = []
        self.assertIn("Reviewed: 1", render_triage_report(reviewed, partial))
        self.assertEqual(
            apply_triage(reviewed, partial)["summary"]["triage"]["confirmed"], 1
        )

    def test_direct_api_rejects_malformed_dispositions(self):
        worksheet = build_triage_worksheet(BUNDLE)
        worksheet["reviews"][0]["disposition"] = []
        for operation in (apply_triage, render_triage_report):
            with (
                self.subTest(operation=operation.__name__),
                self.assertRaises(TriageError),
            ):
                operation(BUNDLE, worksheet)

    def test_applies_review_without_mutating_original(self):
        worksheet = build_triage_worksheet(BUNDLE)
        worksheet["reviews"][0]["disposition"] = "confirmed"
        worksheet["reviews"][0]["analyst_notes"] = "validated in debugger"
        reviewed = apply_triage(BUNDLE, worksheet)

        self.assertNotIn("triage", BUNDLE["findings"][0])
        self.assertEqual(reviewed["findings"][0]["triage"]["disposition"], "confirmed")
        self.assertIn("triage: confirmed", reviewed["findings"][0]["comment"])
        self.assertEqual(reviewed["summary"]["triage"]["confirmed"], 1)

    def test_rejects_wrong_handoff_and_bad_disposition(self):
        worksheet = build_triage_worksheet(BUNDLE)
        worksheet["handoff_identity"] = "wrong"
        with self.assertRaisesRegex(TriageError, "does not belong"):
            apply_triage(BUNDLE, worksheet)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "triage.json"
            worksheet = build_triage_worksheet(BUNDLE)
            worksheet["reviews"][0]["disposition"] = "maybe-ish"
            path.write_text(json.dumps(worksheet), encoding="utf-8")
            with self.assertRaisesRegex(TriageError, "invalid disposition"):
                load_triage(path)

    def test_reports_review_counts(self):
        worksheet = build_triage_worksheet(BUNDLE)
        worksheet["reviews"][0]["disposition"] = "likely"
        text = render_triage_report(BUNDLE, worksheet)
        markdown = render_triage_report(BUNDLE, worksheet, markdown=True)
        self.assertIn("Reviewed: 1", text)
        self.assertIn("| likely | 1 |", markdown)

    def test_cli_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            write_handoff(BUNDLE, output, tool="json")
            handoff = output / "capagap-handoff.json"
            worksheet = output / "custom-triage.json"
            reviewed = output / "reviewed.json"
            report = output / "triage.md"

            self.assertEqual(
                main(
                    [
                        "triage",
                        "init",
                        str(handoff),
                        "--output",
                        str(worksheet),
                    ]
                ),
                0,
            )
            payload = json.loads(worksheet.read_text(encoding="utf-8"))
            payload["reviews"][0]["disposition"] = "needs-data"
            worksheet.write_text(json.dumps(payload), encoding="utf-8")
            self.assertEqual(
                main(
                    [
                        "triage",
                        "report",
                        str(handoff),
                        str(worksheet),
                        "--format",
                        "markdown",
                        "--output",
                        str(report),
                    ]
                ),
                0,
            )
            self.assertEqual(
                main(
                    [
                        "triage",
                        "apply",
                        str(handoff),
                        str(worksheet),
                        "--output",
                        str(reviewed),
                    ]
                ),
                0,
            )
            loaded = load_handoff(reviewed)
            self.assertEqual(
                loaded["findings"][0]["triage"]["disposition"], "needs-data"
            )


if __name__ == "__main__":
    unittest.main()
