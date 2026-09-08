from __future__ import annotations

import copy
import gzip
import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from pathlib import Path

from capagap.analysis import compare_documents
from capagap.cases import CaseError, _identity, create_case, load_case
from capagap.cli import main
from capagap.contributions import analyze_contributions, render_contributions
from capagap.diff import DiffError, compare_reports, load_report
from capagap.io import load_document
from capagap.manifest import RuleManifest, RuleManifestEntry, _fingerprint
from capagap.matrix import compare_matrix
from tests.test_evidence import HTTP, ROOT, rich_document, write_document


class WorkflowTestCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.static_path = write_document(self.root, rich_document(), "static.json")
        self.dynamic_path = write_document(
            self.root, rich_document("dynamic"), "dynamic.json"
        )
        self.static = load_document(self.static_path)
        self.dynamic = load_document(self.dynamic_path)

    def case(self, *, single=False, **kwargs):
        runs = [("baseline", self.dynamic_path)]
        if not single:
            runs.append(("interactive", ROOT / "examples/dynamic-interactive.json"))
        return create_case(self.static_path, runs, self.root / "case", **kwargs)

    def cli(self, *args):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            try:
                code = main(list(map(str, args)))
            except SystemExit as exc:
                code = exc.code
        return code, output.getvalue(), errors.getvalue()


class CaseTests(WorkflowTestCase):
    def test_gzip_input_is_captured_as_plain_json(self):
        compressed = self.root / "static.gz"
        compressed.write_bytes(gzip.compress(self.static_path.read_bytes()))
        manifest = create_case(
            compressed, [("baseline", self.dynamic_path)], self.root / "case"
        )
        case, comparison = load_case(manifest)
        self.assertTrue(
            (manifest.parent / case["static"]["path"]).read_bytes().startswith(b"{")
        )
        self.assertEqual(
            comparison.static.provenance["content_sha256"], case["static"]["sha256"]
        )

    def test_portable_roundtrip_and_notes(self):
        self.case(
            name="Demo",
            notes="Reviewed <one>\nSecond line",
            conditions=[
                ("baseline", "network", "off"),
                ("interactive", "network", "on"),
            ],
        )
        moved = self.root / "moved"
        shutil.copytree(self.root / "case", moved)
        case, comparison = load_case(moved)
        self.assertEqual(comparison.summary.union_coverage, 0.75)
        self.assertEqual(comparison.metadata["case"]["id"], case["id"])
        self.assertTrue(comparison.metadata["case"]["inputs_verified"])
        self.assertEqual(dict(comparison.runs[1].conditions), {"network": "on"})
        self.assertTrue(comparison.static.path.is_relative_to(moved.resolve()))
        self.assertEqual(
            sorted(path.name for path in moved.iterdir()), ["case.json", "inputs"]
        )

    def test_notes_edit_preserves_identity(self):
        manifest = self.case(single=True)
        case = json.loads(manifest.read_text())
        case["notes"] = "Updated review"
        manifest.write_text(json.dumps(case), encoding="utf-8")
        verified, comparison = load_case(manifest)
        self.assertEqual(verified["id"], case["id"])
        self.assertEqual(comparison.metadata["case"]["notes"], "Updated review")

    def test_rejects_modified_input(self):
        manifest = self.case()
        target = manifest.parent / "inputs/run-001.json"
        target.write_text(target.read_text() + "\n", encoding="utf-8")
        with self.assertRaisesRegex(CaseError, "input changed"):
            load_case(manifest)

    def test_rejects_modified_configuration(self):
        manifest = self.case()
        case = json.loads(manifest.read_text())
        case["runs"][0]["conditions"]["network"] = "changed"
        manifest.write_text(json.dumps(case), encoding="utf-8")
        with self.assertRaisesRegex(CaseError, "configuration differs"):
            load_case(manifest)

    def test_rejects_unsafe_relative_paths_even_with_new_identity(self):
        manifest = self.case()
        original = json.loads(manifest.read_text())
        for path in (
            "../static.json",
            "/absolute.json",
            "C:/static.json",
            "inputs\\static.json",
            "inputs/static.json:stream",
        ):
            case = copy.deepcopy(original)
            case["static"]["path"] = path
            case["id"] = _identity(case)
            manifest.write_text(json.dumps(case), encoding="utf-8")
            with self.subTest(path=path), self.assertRaises(CaseError):
                load_case(manifest)

    def test_cannot_replace_existing_case(self):
        manifest = self.case()
        original = manifest.read_bytes()
        with self.assertRaisesRegex(CaseError, "already exists"):
            self.case()
        self.assertEqual(manifest.read_bytes(), original)

    def test_invalid_case_capture_leaves_no_partial_case(self):
        with self.assertRaises(CaseError):
            self.case(conditions=[("unknown", "network", "off")])
        self.assertFalse((self.root / "case").exists())
        self.assertEqual(list(self.root.glob(".capagap-case-*")), [])

    def test_pins_optional_ruleset(self):
        path = self.root / "ruleset.json"
        rules = {
            name: RuleManifestEntry(
                name,
                rule.namespace,
                rule.static_scope,
                rule.dynamic_scope,
                rule.library,
                rule.source_digest,
                f"rule-{index}.yml",
            )
            for index, (name, rule) in enumerate(
                (self.static.rules | self.dynamic.rules).items()
            )
        }
        path.write_text(
            json.dumps(
                RuleManifest(path, "test", rules, _fingerprint(rules)).to_dict()
            ),
            encoding="utf-8",
        )
        manifest = self.case(single=True, ruleset_path=path)
        case, comparison = load_case(manifest)
        self.assertEqual(
            case["ruleset"]["fingerprint"],
            comparison.metadata["ruleset_manifest"]["fingerprint"],
        )

    def test_case_cli_end_to_end(self):
        folder = self.root / "case"
        self.assertEqual(
            self.cli(
                "case",
                "init",
                self.static_path,
                "--run",
                f"baseline={self.dynamic_path}",
                "--output",
                folder,
                "--notes",
                "Case review",
            )[0],
            0,
        )
        code, output, error = self.cli(
            "case", "verify", folder, "--strict", "--format", "json"
        )
        self.assertEqual(code, 0, error)
        self.assertTrue(json.loads(output)["inputs_verified"])
        for format_name in ("json", "html", "markdown", "text"):
            code, output, error = self.cli(
                "case", "report", folder, "--format", format_name
            )
            self.assertEqual(code, 0, error)
            self.assertIn("Case review", output)
        handoff = self.root / "handoff"
        self.assertEqual(
            self.cli("case", "handoff", folder, "--tool", "json", "--output", handoff)[
                0
            ],
            0,
        )
        bundle = json.loads((handoff / "capagap-handoff.json").read_text())
        self.assertEqual(bundle["analysis"]["case"]["notes"], "Case review")

    def test_case_output_cannot_replace_pinned_files_or_custom_manifest(self):
        manifest = self.case()
        custom = manifest.with_name("custom.json")
        manifest.rename(custom)
        for output in (custom, custom.parent / "inputs/static.json"):
            original = output.read_bytes()
            self.assertEqual(
                self.cli("case", "report", custom, "--output", output)[0], 2
            )
            self.assertEqual(output.read_bytes(), original)
        self.assertEqual(
            self.cli(
                "case",
                "handoff",
                custom,
                "--output",
                custom.parent / "inputs",
                "--force",
            )[0],
            2,
        )


class DiffTests(WorkflowTestCase):
    def test_reordered_shared_runs_change_context_not_observations(self):
        runs = [("a", self.dynamic), ("b", self.dynamic), ("c", self.dynamic)]
        before = compare_matrix(self.static, runs).to_dict()
        for reordered in ([runs[1], runs[0], runs[2]], [runs[0], runs[2], runs[1]]):
            after = compare_matrix(self.static, reordered).to_dict()
            result = compare_reports(before, after)
            self.assertTrue(result["changed"])
            self.assertEqual(result["changes"], [])
            self.assertIn(
                "shared_run_order",
                {change["field"] for change in result["context_changes"]},
            )
            self.assertEqual(
                "experiment_baseline"
                in {change["field"] for change in result["context_changes"]},
                reordered[0] != runs[0],
            )
            old_path, new_path = self.root / "before.json", self.root / "after.json"
            old_path.write_text(json.dumps(before), encoding="utf-8")
            new_path.write_text(json.dumps(after), encoding="utf-8")
            self.assertEqual(
                self.cli("diff", old_path, new_path, "--fail-on-change")[0], 3
            )

    def test_changed_image_base_is_context_even_with_identical_va_evidence(self):
        before = self.single()
        after = self.single(
            static=replace(self.static, base_address=self.static.base_address + 4096)
        )
        result = compare_reports(before, after)
        self.assertTrue(result["changed"])
        self.assertIn(
            "static:base_address",
            {change["field"] for change in result["context_changes"]},
        )
        self.assertEqual(result["changes"], [])
        self.assertNotEqual(
            before["evidence_hotspots"][0]["rva"], after["evidence_hotspots"][0]["rva"]
        )

    def test_legacy_image_base_is_unverified_not_equivalent_to_absent_base(self):
        before = self.single(static=replace(self.static, base_address=None))
        legacy = copy.deepcopy(before)
        legacy["provenance"]["static"].pop("base_address")
        result = compare_reports(legacy, before)
        self.assertTrue(result["changed"])
        self.assertIn(
            "static:base_address_recorded",
            {change["field"] for change in result["context_changes"]},
        )
        self.assertTrue(
            any("image-base provenance" in warning for warning in result["warnings"])
        )
        self.assertFalse(compare_reports(legacy, legacy)["changed"])

    def test_invalid_base_and_baseline_are_rejected(self):
        for value in ([], True, -1, "0x400000"):
            report = self.single()
            report["provenance"]["static"]["base_address"] = value
            with self.subTest(value=value), self.assertRaises(DiffError):
                compare_reports(report, report)
        matrix = compare_matrix(
            self.static, [("a", self.dynamic), ("b", self.dynamic)]
        ).to_dict()
        matrix["matrix"]["experiment_baseline"] = "unknown"
        with self.assertRaisesRegex(DiffError, "baseline"):
            compare_reports(matrix, matrix)

    def test_malformed_source_identity_and_analysis_type_fail_cleanly(self):
        report = self.single()
        for key, value in (("source_digest", 123), ("source_available", "yes")):
            malformed = copy.deepcopy(report)
            malformed["observed"][0][key] = value
            with self.assertRaises(DiffError):
                compare_reports(malformed, report)
        report["analysis_type"] = []
        with self.assertRaises(DiffError):
            compare_reports(report, report)

    def single(self, dynamic=None, static=None):
        return compare_documents(
            static or self.static, dynamic or self.dynamic
        ).to_dict()

    def without_http(self):
        return replace(
            self.dynamic,
            rules={
                name: rule for name, rule in self.dynamic.rules.items() if name != HTTP
            },
        )

    def test_identical_report_has_no_changes(self):
        report = self.single()
        result = compare_reports(report, copy.deepcopy(report))
        self.assertFalse(result["changed"])
        self.assertEqual(result["warnings"], [])

    def test_observation_added_and_removed(self):
        before, after = self.single(self.without_http()), self.single()
        added = compare_reports(before, after)["changes"]
        self.assertEqual(added[0]["name"], HTTP)
        self.assertEqual(added[0]["kind"], "observation-changed")
        self.assertEqual(added[0]["gained_in"], ["dynamic"])
        self.assertEqual(
            compare_reports(after, before)["changes"][0]["lost_from"], ["dynamic"]
        )

    def test_changed_rule_source_not_attributed_to_observation(self):
        rules = dict(self.static.rules)
        rules[HTTP] = replace(rules[HTTP], source_digest="b" * 64)
        changed = self.single(static=replace(self.static, rules=rules))
        self.assertEqual(
            compare_reports(self.single(), changed)["changes"][0]["kind"],
            "rule-changed",
        )

    def test_dynamic_source_drift_is_rule_change(self):
        rules = dict(self.dynamic.rules)
        rules[HTTP] = replace(rules[HTTP], source_digest="b" * 64)
        result = compare_reports(
            self.single(), self.single(replace(self.dynamic, rules=rules))
        )
        self.assertEqual(
            next(item for item in result["changes"] if item["name"] == HTTP)["kind"],
            "rule-changed",
        )

    def test_context_change_precedes_observation_change(self):
        before = self.single(self.without_http())
        after = self.single(replace(self.dynamic, extractor="different"))
        result = compare_reports(before, after)
        self.assertTrue(
            any(
                item["field"] == "run:dynamic:extractor"
                for item in result["context_changes"]
            )
        )
        self.assertEqual(result["changes"][0]["kind"], "analysis-context-changed")

    def test_conditions_and_review_notes_are_separate(self):
        report = compare_matrix(
            self.static,
            [("a", self.dynamic), ("b", self.dynamic)],
            experiment_conditions=[("a", "network", "off"), ("b", "network", "on")],
        ).to_dict()
        after = copy.deepcopy(report)
        after["runs"][1]["conditions"]["network"] = "simulated"
        after["metadata"]["case"] = {"name": "Review", "notes": "Checked"}
        result = compare_reports(report, after)
        self.assertEqual(result["context_changes"][0]["field"], "run:b:conditions")
        self.assertEqual(len(result["review_changes"]), 2)
        self.assertEqual(result["changes"], [])

    def test_added_run_not_treated_as_changed_existing_run(self):
        before = compare_matrix(
            self.static, [("a", self.dynamic), ("b", self.dynamic)]
        ).to_dict()
        after = compare_matrix(
            self.static, [("a", self.dynamic), ("b", self.dynamic), ("c", self.dynamic)]
        ).to_dict()
        result = compare_reports(before, after)
        self.assertEqual(result["runs"]["added"], ["c"])
        self.assertTrue(
            all(item["kind"] == "run-set-changed" for item in result["changes"])
        )
        self.assertTrue(all(not item["gained_in"] for item in result["changes"]))

    def test_legacy_report_is_accepted_with_unverified_provenance(self):
        old, after = self.single(self.without_http()), self.single()
        old.pop("evidence")
        old.pop("provenance")
        result = compare_reports(old, after)
        self.assertTrue(result["warnings"])
        self.assertEqual(result["changes"][0]["kind"], "analysis-context-changed")

    def test_sample_and_report_type_mismatch_are_rejected(self):
        before = self.single()
        after = copy.deepcopy(before)
        after["comparison"]["sample_sha256"] = "f" * 64
        with self.assertRaises(DiffError):
            compare_reports(before, after)
        self.assertFalse(
            compare_reports(before, after, allow_mismatch=True)["same_sample_verified"]
        )
        with self.assertRaises(DiffError):
            compare_reports(
                before,
                compare_matrix(
                    self.static, [("a", self.dynamic), ("b", self.dynamic)]
                ).to_dict(),
            )

    def test_rejects_tampered_evidence_even_for_new_finding(self):
        before, after = self.single(), self.single()
        after["evidence"]["static"][HTTP]["matches"][0]["tree"]["label"] = "tampered"
        with self.assertRaisesRegex(DiffError, "fingerprint"):
            compare_reports(before, after)

    def test_rejects_duplicate_findings_and_unknown_labels(self):
        report = self.single()
        report["observed"].append(report["observed"][0])
        with self.assertRaises(DiffError):
            compare_reports(report, self.single())
        matrix = compare_matrix(
            self.static, [("a", self.dynamic), ("b", self.dynamic)]
        ).to_dict()
        matrix["findings"][0]["observed_in"] = ["missing"]
        with self.assertRaises(DiffError):
            compare_reports(matrix, matrix)

    def test_load_report_rejects_raw_capa(self):
        with self.assertRaises(DiffError):
            load_report(self.static_path)

    def test_static_run_label_does_not_overwrite_static_evidence(self):
        before = compare_matrix(
            self.static, [("static", self.dynamic), ("other", self.dynamic)]
        ).to_dict()
        after = compare_matrix(
            self.static, [("static", self.without_http()), ("other", self.dynamic)]
        ).to_dict()
        self.assertEqual(
            compare_reports(before, after)["changes"][0]["lost_from"], ["static"]
        )


class ContributionTests(WorkflowTestCase):
    def test_matrix_provenance_does_not_inherit_only_baseline_identity(self):
        matrix = compare_matrix(
            self.static,
            [
                ("a", self.dynamic),
                ("b", replace(self.dynamic, sample_sha256="f" * 64, extractor="other")),
            ],
            allow_mismatch=True,
        )
        self.assertFalse(matrix.metadata["sample_hashes_match"])
        self.assertEqual(matrix.metadata["dynamic_extractors"]["b"], "other")

    def test_advisory_diagnostics_are_not_lost(self):
        result = analyze_contributions(
            compare_matrix(self.static, [("a", self.dynamic), ("b", self.dynamic)])
        )
        self.assertTrue(result["diagnostics"])
        self.assertIn("Input quality:", render_contributions(result))

    def with_names(self, names):
        return replace(
            self.dynamic,
            rules={
                name: replace(self.static.rules[name], matches=()) for name in names
            },
        )

    def test_individually_redundant_runs_cannot_all_be_removed(self):
        names = sorted(
            rule.name
            for rule in self.static.rules.values()
            if rule.dynamically_comparable and not rule.library
        )[:3]
        a, b, c = names
        matrix = compare_matrix(
            self.static,
            [
                ("ab", self.with_names([a, b])),
                ("bc", self.with_names([b, c])),
                ("ac", self.with_names([a, c])),
            ],
        )
        result = analyze_contributions(matrix)
        self.assertTrue(all(run["individually_redundant"] for run in result["runs"]))
        self.assertEqual(result["representative_set"]["labels"], ["ab", "bc"])
        self.assertFalse(result["representative_set"]["minimum_guaranteed"])
        self.assertAlmostEqual(result["pairwise_overlap"][0]["jaccard"], 1 / 3)

    def test_unique_baseline_and_incremental_coverage(self):
        result = analyze_contributions(
            compare_matrix(
                self.static,
                [
                    ("baseline", self.dynamic),
                    (
                        "interactive",
                        load_document(ROOT / "examples/dynamic-interactive.json"),
                    ),
                ],
            )
        )
        self.assertEqual(result["union_count"], 3)
        self.assertEqual(
            result["runs"][1]["unique_capabilities"], ["create scheduled task"]
        )
        self.assertEqual(
            result["runs"][1]["added_vs_baseline"], ["create scheduled task"]
        )
        self.assertEqual(
            result["runs"][1]["missing_vs_baseline"],
            ["check for sandbox process names"],
        )

    def test_empty_union_is_not_perfect_overlap(self):
        empty = self.with_names([])
        result = analyze_contributions(
            compare_matrix(self.static, [("a", empty), ("b", empty)])
        )
        self.assertEqual(result["representative_set"]["labels"], [])
        self.assertIsNone(result["pairwise_overlap"][0]["jaccard"])

    def test_markdown_escapes_untrusted_labels(self):
        result = analyze_contributions(
            compare_matrix(
                self.static, [("<script>x</script>", self.dynamic), ("b", self.dynamic)]
            )
        )
        self.assertNotIn("<script>", render_contributions(result, markdown=True))


class CommandTests(WorkflowTestCase):
    def test_validation_exit_codes(self):
        self.assertEqual(
            self.cli("validate", self.static_path, self.dynamic_path)[0], 0
        )
        self.assertEqual(
            self.cli("validate", self.static_path, "--minimum-features", "1000000")[0],
            4,
        )
        self.assertEqual(self.cli("validate", self.root / "missing.json")[0], 2)
        self.assertEqual(
            self.cli("validate", self.static_path, "--minimum-features", "0")[0], 2
        )

    def test_strict_stops_before_creating_report(self):
        output = self.root / "report.html"
        code, _, error = self.cli(
            "compare",
            ROOT / "examples/static.json",
            ROOT / "examples/dynamic.json",
            "--strict",
            "--output",
            output,
        )
        self.assertEqual(code, 4, error)
        self.assertFalse(output.exists())

    def test_diff_exit_flag_and_input_overwrite_guard(self):
        before = self.root / "before.json"
        after = self.root / "after.json"
        before.write_text(
            json.dumps(compare_documents(self.static, self.dynamic).to_dict()),
            encoding="utf-8",
        )
        changed = replace(self.dynamic, rules={})
        after.write_text(
            json.dumps(compare_documents(self.static, changed).to_dict()),
            encoding="utf-8",
        )
        self.assertEqual(self.cli("diff", before, after, "--fail-on-change")[0], 3)
        self.assertEqual(self.cli("diff", before, before, "--fail-on-change")[0], 0)
        original = before.read_bytes()
        self.assertEqual(self.cli("diff", before, after, "--output", before)[0], 2)
        self.assertEqual(before.read_bytes(), original)

    def test_contributions_formats_and_strict(self):
        args = (
            "contributions",
            self.static_path,
            "--run",
            f"a={self.dynamic_path}",
            "--run",
            f"b={self.dynamic_path}",
            "--condition",
            "a:network=off",
            "--condition",
            "b:network=on",
        )
        for format_name in ("text", "markdown", "json", "html"):
            code, output, error = self.cli(*args, "--strict", "--format", format_name)
            self.assertEqual(code, 0, error)
            self.assertIn(
                "contributions" if format_name != "json" else "representative_set",
                output,
            )
        self.assertEqual(self.cli(*args, "--minimum-features", "0")[0], 2)

    def test_reports_cannot_overwrite_inputs(self):
        original = self.static_path.read_bytes()
        self.assertEqual(
            self.cli(
                "compare",
                self.static_path,
                self.dynamic_path,
                "--output",
                self.static_path,
            )[0],
            2,
        )
        self.assertEqual(
            self.cli("validate", self.static_path, "--output", self.static_path)[0], 2
        )
        self.assertEqual(self.static_path.read_bytes(), original)
