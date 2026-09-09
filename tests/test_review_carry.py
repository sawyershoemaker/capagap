from __future__ import annotations

import copy
import json
from unittest.mock import patch

from capagap.analysis import compare_documents
from capagap.evidence import fingerprint
from capagap.handoff import build_single_handoff
from capagap.triage import (
    TriageError,
    apply_triage,
    build_triage_worksheet,
    carry_triage,
    render_triage_report,
    write_json,
)
from tests.test_workflows import WorkflowTestCase


class ReviewCarryTests(WorkflowTestCase):
    def setUp(self):
        super().setUp()
        self.before = build_single_handoff(
            compare_documents(self.static, self.dynamic), run_label="baseline"
        )
        self.worksheet = build_triage_worksheet(self.before)
        self.worksheet["reviews"][0].update(
            disposition="confirmed",
            analyst_notes="Breakpoint reached",
            evidence="Recorded trace",
            reviewer="Analyst",
            reviewed_at="2026-01-01",
        )

    def test_retains_unchanged_reviews_and_ignores_paths_and_generator(self):
        after = copy.deepcopy(self.before)
        after["generator"]["version"] = "later"
        after["analysis"]["provenance"]["static"]["input"] = "/moved/static.json"
        result = carry_triage(self.before, self.worksheet, after)
        self.assertEqual(result["reviews"][0]["disposition"], "confirmed")
        self.assertEqual(result["migration"]["needs_review"], [])
        self.assertEqual(len(result["migration"]["retained"]), len(after["findings"]))
        apply_triage(after, result)

    def test_evidence_changes_preserve_notes_but_reset_judgment(self):
        after = copy.deepcopy(self.before)
        evidence = after["findings"][0]["match_evidence"]
        evidence["matches"][0]["tree"]["success"] = False
        evidence["fingerprint"] = fingerprint(evidence["matches"])
        result = carry_triage(self.before, self.worksheet, after)
        review = result["reviews"][0]
        self.assertEqual(review["disposition"], "unreviewed")
        self.assertEqual(review["analyst_notes"], "Breakpoint reached")
        self.assertEqual(review["reviewer"], "")
        record = result["migration"]["needs_review"][0]
        self.assertIn("evidence-changed", record["reasons"])
        self.assertEqual(record["previous_review"]["disposition"], "confirmed")
        self.assertIn("Awaiting reassessment: 1", render_triage_report(after, result))
        review["disposition"] = "confirmed"
        self.assertIn("Awaiting reassessment: 0", render_triage_report(after, result))

    def test_context_changes_reset_reviews_even_when_rule_ids_match(self):
        for key, value in (
            ("content_sha256", "e" * 64),
            ("extractor", "ChangedExtractor"),
        ):
            after = copy.deepcopy(self.before)
            after["analysis"]["provenance"]["runs"]["baseline"][key] = value
            result = carry_triage(self.before, self.worksheet, after)
            self.assertEqual(result["reviews"][0]["disposition"], "unreviewed")
            self.assertIn(
                "context-changed", result["migration"]["needs_review"][0]["reasons"]
            )

    def test_rule_changes_use_name_only_to_recover_notes(self):
        after = copy.deepcopy(self.before)
        after["findings"][0]["id"] = "changed-id"
        after["findings"][0]["source_digest"] = "d" * 64
        result = carry_triage(self.before, self.worksheet, after)
        self.assertEqual(result["reviews"][0]["id"], "changed-id")
        self.assertEqual(result["reviews"][0]["analyst_notes"], "Breakpoint reached")
        self.assertEqual(result["reviews"][0]["disposition"], "unreviewed")
        self.assertIn("rule-changed", result["migration"]["needs_review"][0]["reasons"])

    def test_new_and_removed_findings_are_not_lost(self):
        after = copy.deepcopy(self.before)
        after["findings"][0].update(id="new-id", name="new capability")
        result = carry_triage(self.before, self.worksheet, after)
        self.assertEqual(result["migration"]["new"], ["new-id"])
        removed = result["migration"]["removed_reviews"][0]
        self.assertEqual(removed["analyst_notes"], "Breakpoint reached")
        self.assertEqual(removed["disposition"], "confirmed")

    def test_new_worksheets_reject_silent_reuse_after_context_change(self):
        after = copy.deepcopy(self.before)
        after["analysis"]["source_image_base"] += 4096
        with self.assertRaisesRegex(TriageError, "context changed"):
            apply_triage(after, self.worksheet)
        with self.assertRaisesRegex(TriageError, "context changed"):
            carry_triage(after, self.worksheet, after)

    def test_applied_reviews_retain_their_evidence_basis(self):
        reviewed = apply_triage(self.before, self.worksheet)
        for finding, review in zip(reviewed["findings"], self.worksheet["reviews"]):
            self.assertEqual(finding["triage"]["basis"], review["basis"])
        self.assertNotIn("triage", self.before["findings"][0])

    def test_unchanged_applied_review_survives_a_partial_worksheet(self):
        reviewed = apply_triage(self.before, self.worksheet)
        partial = build_triage_worksheet(reviewed)
        partial["reviews"] = []
        result = carry_triage(reviewed, partial, reviewed)
        self.assertEqual(result["reviews"][0]["disposition"], "confirmed")
        self.assertEqual(result["migration"]["needs_review"], [])
        self.assertEqual(
            apply_triage(reviewed, partial)["findings"][0]["triage"],
            reviewed["findings"][0]["triage"],
        )

    def test_stale_applied_review_is_reassessed_with_a_partial_worksheet(self):
        changed = apply_triage(self.before, self.worksheet)
        changed["analysis"]["source_image_base"] += 4096
        partial = build_triage_worksheet(changed)
        partial["reviews"] = []
        result = carry_triage(changed, partial, changed)
        self.assertEqual(result["reviews"][0]["disposition"], "unreviewed")
        self.assertEqual(result["reviews"][0]["analyst_notes"], "Breakpoint reached")
        record = result["migration"]["needs_review"][0]
        self.assertIn("applied-basis-unverified", record["reasons"])
        self.assertEqual(record["previous_review"]["disposition"], "confirmed")
        self.assertEqual(
            record["previous_review"]["basis"], self.worksheet["reviews"][0]["basis"]
        )
        apply_triage(changed, result)

    def test_apply_and_report_reject_stale_inherited_review_bases(self):
        changed = apply_triage(self.before, self.worksheet)
        changed["analysis"]["source_image_base"] += 4096
        for schema_version in (1, 2):
            partial = build_triage_worksheet(changed)
            partial.update(schema_version=schema_version, reviews=[])
            for operation in (apply_triage, render_triage_report):
                with self.subTest(schema=schema_version, operation=operation.__name__):
                    with self.assertRaisesRegex(TriageError, "applied review"):
                        operation(changed, partial)

    def test_legacy_applied_reviews_remain_readable_but_cannot_be_verified(self):
        reviewed = apply_triage(self.before, self.worksheet)
        for finding in reviewed["findings"]:
            finding["triage"].pop("basis")
        partial = build_triage_worksheet(reviewed)
        partial["reviews"] = []
        applied = apply_triage(reviewed, partial)
        self.assertEqual(applied["findings"][0]["triage"]["disposition"], "confirmed")
        result = carry_triage(reviewed, partial, reviewed)
        self.assertEqual(result["reviews"][0]["disposition"], "unreviewed")
        self.assertIn(
            "applied-basis-unverified",
            result["migration"]["needs_review"][0]["reasons"],
        )

    def test_invalid_applied_basis_is_rejected(self):
        for basis in (None, "", "not-a-digest", 123):
            reviewed = apply_triage(self.before, self.worksheet)
            reviewed["findings"][0]["triage"]["basis"] = basis
            with (
                self.subTest(basis=basis),
                self.assertRaisesRegex(TriageError, "basis"),
            ):
                build_triage_worksheet(reviewed)

    def test_rejects_incorrect_evidence_fingerprints(self):
        after = copy.deepcopy(self.before)
        after["findings"][0]["match_evidence"]["fingerprint"] = "f" * 64
        with self.assertRaisesRegex(TriageError, "fingerprint"):
            carry_triage(self.before, self.worksheet, after)

    def test_legacy_worksheets_remain_usable_but_require_reassessment(self):
        legacy = copy.deepcopy(self.worksheet)
        legacy["schema_version"] = 1
        legacy.pop("handoff_context")
        for row in legacy["reviews"]:
            row.pop("basis")
        apply_triage(self.before, legacy)
        result = carry_triage(self.before, legacy, self.before)
        self.assertEqual(result["reviews"][0]["disposition"], "unreviewed")
        self.assertIn(
            "prior-basis-unverified", result["migration"]["needs_review"][0]["reasons"]
        )

    def test_missing_context_is_not_assumed_equivalent(self):
        before = copy.deepcopy(self.before)
        before["analysis"].pop("provenance")
        worksheet = build_triage_worksheet(before)
        worksheet["reviews"][0]["disposition"] = "confirmed"
        result = carry_triage(before, worksheet, before)
        self.assertEqual(result["reviews"][0]["disposition"], "unreviewed")

    def test_sample_mismatch_and_duplicate_names_are_rejected(self):
        for sample in ("", "f" * 64):
            after = copy.deepcopy(self.before)
            after["analysis"]["sample"]["sha256"] = sample
            with self.subTest(sample=sample), self.assertRaises(TriageError):
                carry_triage(self.before, self.worksheet, after)
        after = copy.deepcopy(self.before)
        after["findings"][1]["name"] = after["findings"][0]["name"]
        with self.assertRaisesRegex(TriageError, "unique"):
            carry_triage(self.before, self.worksheet, after)

    def test_carry_does_not_mutate_inputs(self):
        original = copy.deepcopy([self.before, self.worksheet])
        carry_triage(self.before, self.worksheet, self.before)
        self.assertEqual([self.before, self.worksheet], original)

    def test_malformed_migration_and_changed_basis_are_rejected(self):
        for migration in (None, [], {}, {"retained": None}):
            worksheet = copy.deepcopy(self.worksheet)
            worksheet["migration"] = migration
            with self.subTest(migration=migration), self.assertRaises(TriageError):
                apply_triage(self.before, worksheet)
        worksheet = copy.deepcopy(self.worksheet)
        worksheet["reviews"][0]["basis"] = "e" * 64
        with self.assertRaisesRegex(TriageError, "basis"):
            apply_triage(self.before, worksheet)

    def test_case_name_and_notes_do_not_invalidate_review(self):
        before = copy.deepcopy(self.before)
        before["analysis"]["case"] = {
            "name": "First",
            "notes": "old",
            "conditions": {"baseline": {"network": "off"}},
        }
        worksheet = build_triage_worksheet(before)
        worksheet["reviews"][0]["disposition"] = "confirmed"
        after = copy.deepcopy(before)
        after["analysis"]["case"].update(name="Renamed", notes="New note")
        result = carry_triage(before, worksheet, after)
        self.assertEqual(result["reviews"][0]["disposition"], "confirmed")

    def test_atomic_write_and_output_size_limit(self):
        output = self.root / "worksheet.json"
        output.write_text("preserve")
        with (
            patch("capagap.output.os.replace", side_effect=OSError("blocked")),
            self.assertRaises(TriageError),
        ):
            write_json(self.worksheet, output, force=True)
        self.assertEqual(output.read_text(), "preserve")
        with patch("capagap.triage.MAX_JSON_BYTES", 2), self.assertRaises(TriageError):
            write_json(self.worksheet, output, force=True)
        self.assertEqual(output.read_text(), "preserve")

    def test_cli_carry_output_and_input_protection(self):
        before, worksheet, after = [
            self.root / name for name in ("before.json", "worksheet.json", "after.json")
        ]
        for path, payload in (
            (before, self.before),
            (worksheet, self.worksheet),
            (after, self.before),
        ):
            path.write_text(json.dumps(payload), encoding="utf-8")
        output = self.root / "next-worksheet.json"
        code, _, errors = self.cli(
            "triage", "carry", before, worksheet, after, "--output", output
        )
        self.assertEqual(code, 0, errors)
        self.assertEqual(
            json.loads(output.read_text())["reviews"][0]["disposition"], "confirmed"
        )
        for path in (before, worksheet, after):
            original = path.read_bytes()
            self.assertEqual(
                self.cli(
                    "triage",
                    "carry",
                    before,
                    worksheet,
                    after,
                    "--output",
                    path,
                    "--force",
                )[0],
                2,
            )
            self.assertEqual(path.read_bytes(), original)
