from __future__ import annotations

import gzip
import json
import shutil
from pathlib import Path
from unittest.mock import patch

from capagap.batch import BatchError, analyze_directory
from capagap.cases import create_case, load_case
from tests.test_evidence import rich_document, write_document
from tests.test_workflows import WorkflowTestCase


class BatchTests(WorkflowTestCase):
    def setUp(self):
        super().setUp()
        self.inputs = self.root / "inputs"
        self.inputs.mkdir()
        shutil.copy2(self.static_path, self.inputs / "static.json")
        shutil.copy2(self.dynamic_path, self.inputs / "dynamic.json")
        self.output = self.root / "batch"

    def test_produces_portable_cases_reports_and_index(self):
        result = analyze_directory(self.inputs, self.output)
        self.assertEqual(result["summary"]["completed"], 1)
        row = result["samples"][0]
        self.assertEqual(row["coverage"], 0.5)
        self.assertTrue((self.output / row["report"]).is_file())
        case, comparison = load_case(self.output / row["case"])
        self.assertEqual(case["id"], row["case_id"])
        report = json.loads((self.output / row["json_report"]).read_text())
        self.assertEqual(report, comparison.to_dict())
        self.assertTrue(Path(report["provenance"]["static"]["input"]).is_file())
        self.assertEqual(json.loads((self.output / "index.json").read_text()), result)

    def test_groups_samples_only_by_hash(self):
        for flavor in ("static", "dynamic"):
            raw = rich_document(flavor)
            raw["meta"]["sample"]["sha256"] = "b" * 64
            write_document(self.inputs, raw, f"second-{flavor}.json")
        result = analyze_directory(self.inputs, self.output, report_format="json")
        self.assertEqual(result["summary"]["completed"], 2)
        self.assertEqual(
            {r["sample_sha256"] for r in result["samples"]},
            {self.static.sample_sha256, "b" * 64},
        )

    def test_missing_hash_is_rejected_not_guessed(self):
        raw = rich_document("dynamic")
        raw["meta"]["sample"]["sha256"] = ""
        write_document(self.inputs, raw, "unidentified.json")
        result = analyze_directory(self.inputs, self.output)
        self.assertEqual(result["summary"]["rejected_inputs"], 1)
        self.assertEqual(result["samples"][0]["run_count"], 1)

    def test_distinct_static_results_are_ambiguous(self):
        raw = rich_document()
        raw["meta"]["timestamp"] = "2026-01-02"
        write_document(self.inputs, raw, "other-static.json")
        result = analyze_directory(self.inputs, self.output)
        self.assertEqual(result["summary"]["failed"], 1)
        self.assertIn("Exactly one", result["samples"][0]["reason"])
        self.assertEqual(
            sorted(p.name for p in self.output.iterdir()), ["index.json", "index.md"]
        )

    def test_identical_and_gzipped_duplicates_are_recorded_once(self):
        (self.inputs / "static.json.gz").write_bytes(
            gzip.compress((self.inputs / "static.json").read_bytes())
        )
        shutil.copy2(self.inputs / "dynamic.json", self.inputs / "repeat.json")
        result = analyze_directory(self.inputs, self.output)
        self.assertEqual(result["summary"]["completed"], 1)
        self.assertEqual(len(result["duplicates"]), 2)
        self.assertEqual(result["samples"][0]["run_count"], 1)

    def test_recursive_discovery_and_stable_labels(self):
        nested = self.inputs / "more"
        nested.mkdir()
        raw = rich_document("dynamic")
        raw["meta"]["timestamp"] = "another run"
        write_document(nested, raw, "dynamic.json")
        result = analyze_directory(
            self.inputs, self.output, recursive=True, strict=True
        )
        self.assertEqual(
            result["samples"][0]["run_labels"], ["dynamic.json", "more/dynamic.json"]
        )
        self.assertEqual(result["samples"][0]["status"], "completed")

    def test_nonrecursive_does_not_follow_subdirectories(self):
        nested = self.inputs / "nested"
        nested.mkdir()
        (nested / "broken.json").write_text("invalid")
        result = analyze_directory(self.inputs, self.output)
        self.assertEqual(result["rejected_inputs"], [])

    def test_bad_json_and_unpaired_samples_are_visible(self):
        (self.inputs / "broken.json").write_text("not JSON", encoding="utf-8")
        raw = rich_document("dynamic")
        raw["meta"]["sample"]["sha256"] = "c" * 64
        write_document(self.inputs, raw, "orphan.json")
        result = analyze_directory(self.inputs, self.output)
        self.assertEqual(
            result["summary"],
            {"completed": 1, "failed": 1, "rejected_inputs": 1, "duplicate_inputs": 0},
        )

    def test_output_and_discovery_limits_do_not_modify_inputs(self):
        before = (self.inputs / "static.json").read_bytes()
        for destination in (self.inputs, self.inputs / "reports"):
            with self.assertRaises(BatchError):
                analyze_directory(self.inputs, destination)
        with patch("capagap.batch.MAX_INPUTS", 1), self.assertRaises(BatchError):
            analyze_directory(self.inputs, self.output)
        self.assertFalse(self.output.exists())
        self.assertEqual((self.inputs / "static.json").read_bytes(), before)

    def test_capture_race_is_rejected(self):
        def changed(*args, **kwargs):
            path = self.inputs / "static.json"
            path.write_bytes(path.read_bytes() + b"\n")
            return create_case(*args, **kwargs)

        with patch("capagap.batch.create_case", side_effect=changed):
            result = analyze_directory(self.inputs, self.output)
        self.assertEqual(result["summary"]["failed"], 1)
        self.assertIn("changed after discovery", result["samples"][0]["reason"])

    def test_feature_threshold_is_retained_in_reports(self):
        result = analyze_directory(self.inputs, self.output, minimum_features=100000)
        report = json.loads(
            (self.output / result["samples"][0]["json_report"]).read_text()
        )
        self.assertTrue(
            any(d["code"] == "sparse-features" for d in report["diagnostics"])
        )

    def test_strict_threshold_marks_sample_failed(self):
        result = analyze_directory(
            self.inputs, self.output, minimum_features=100000, strict=True
        )
        self.assertEqual(result["summary"]["failed"], 1)

    def test_failed_index_write_leaves_no_output(self):
        with patch("capagap.batch.write_text", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                analyze_directory(self.inputs, self.output)
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.glob(".capagap-batch-*")), [])

    def test_cli_exit_codes_formats_and_existing_output(self):
        for fmt in ("html", "json", "markdown", "text"):
            target = self.root / fmt
            code, _, error = self.cli(
                "batch", self.inputs, "--output", target, "--format", fmt
            )
            self.assertEqual(code, 0, error)
        self.assertEqual(
            self.cli("batch", self.inputs, "--output", self.root / "html")[0], 2
        )
        (self.inputs / "bad.json").write_text("bad")
        self.assertEqual(self.cli("batch", self.inputs, "--output", self.output)[0], 4)
