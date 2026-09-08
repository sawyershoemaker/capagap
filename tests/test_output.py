from __future__ import annotations

import json
import os
from unittest.mock import patch

from capagap.analysis import compare_documents
from capagap.cases import _identity, load_case
from capagap.handoff import build_single_handoff, write_handoff
from capagap.manifest import RuleManifest, RuleManifestEntry, _fingerprint
from capagap.output import write_text
from tests.test_workflows import WorkflowTestCase


class OutputTests(WorkflowTestCase):
    def link(self, source, alias):
        try:
            os.link(source, alias)
        except OSError as error:
            self.skipTest(f"hard links unavailable: {error}")

    def test_triage_report_preserves_both_inputs_in_each_format(self):
        bundle = build_single_handoff(
            compare_documents(self.static, self.dynamic), run_label="baseline"
        )
        folder = self.root / "handoff"
        write_handoff(bundle, folder, tool="json")
        handoff, worksheet = (
            folder / "capagap-handoff.json",
            folder / "capagap-triage.json",
        )
        for format_name in ("text", "markdown"):
            for source in (handoff, worksheet):
                for linked in (False, True):
                    with self.subTest(
                        format=format_name, input=source.name, hardlink=linked
                    ):
                        destination = source
                        if linked:
                            destination = self.root / f"{format_name}-{source.name}"
                            self.link(source, destination)
                        before = source.read_bytes()
                        code, _, error = self.cli(
                            "triage",
                            "report",
                            handoff,
                            worksheet,
                            "--format",
                            format_name,
                            "--output",
                            destination,
                        )
                        self.assertEqual(code, 2, error)
                        self.assertIn("overwrite an input", error)
                        self.assertEqual(source.read_bytes(), before)

    def test_report_commands_reject_hard_links_to_inputs(self):
        run_args = (
            "--run",
            f"a={self.dynamic_path}",
            "--run",
            f"b={self.dynamic_path}",
        )
        report = self.root / "saved.json"
        report.write_text(
            json.dumps(compare_documents(self.static, self.dynamic).to_dict()),
            encoding="utf-8",
        )
        case = self.case()
        commands = [
            (("compare", self.static_path, self.dynamic_path), self.static_path),
            (("matrix", self.static_path, *run_args), self.dynamic_path),
            (("contributions", self.static_path, *run_args), self.static_path),
            (("validate", self.static_path, self.dynamic_path), self.dynamic_path),
            (("diff", report, report), report),
            (("case", "report", case), case.parent / "inputs/static.json"),
            (("case", "verify", case), case),
        ]
        for index, (command, source) in enumerate(commands):
            with self.subTest(command=command[:2]):
                alias = self.root / f"alias-{index}.json"
                self.link(source, alias)
                before = source.read_bytes()
                code, _, error = self.cli(*command, "--output", alias)
                self.assertEqual(code, 2, error)
                self.assertIn("overwrite an input", error)
                self.assertEqual(source.read_bytes(), before)

    def test_custom_case_input_blocks_entire_handoff_before_writes(self):
        manifest = self.case(single=True)
        payload = json.loads(manifest.read_text())
        output = manifest.parent / "custom"
        output.mkdir()
        original = manifest.parent / payload["static"]["path"]
        pinned = output / "capagap-handoff.json"
        original.rename(pinned)
        payload["static"]["path"] = "custom/capagap-handoff.json"
        payload["id"] = _identity(payload)
        manifest.write_text(json.dumps(payload), encoding="utf-8")
        before = pinned.read_bytes()
        code, _, error = self.cli(
            "case", "handoff", manifest, "--output", output, "--force"
        )
        self.assertEqual(code, 2, error)
        self.assertEqual(pinned.read_bytes(), before)
        self.assertEqual(list(output.iterdir()), [pinned])
        load_case(manifest)

    def test_handoff_force_preserves_a_hardlinked_raw_input(self):
        output = self.root / "handoff"
        output.mkdir()
        self.link(self.static_path, output / "capagap-handoff.json")
        before = self.static_path.read_bytes()
        code, _, error = self.cli(
            "handoff",
            self.static_path,
            "--run",
            f"a={self.dynamic_path}",
            "--output",
            output,
            "--force",
        )
        self.assertEqual(code, 2, error)
        self.assertEqual(self.static_path.read_bytes(), before)
        self.assertFalse((output / "capagap-triage.json").exists())

    def test_case_handoff_protects_every_pin_and_renamed_manifest(self):
        ruleset_path = self.root / "ruleset.json"
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
        ruleset_path.write_text(
            json.dumps(
                RuleManifest(ruleset_path, "test", rules, _fingerprint(rules)).to_dict()
            ),
            encoding="utf-8",
        )
        manifest = self.case(single=True, ruleset_path=ruleset_path)
        manifest = manifest.rename(manifest.with_name("review-case.json"))
        payload = json.loads(manifest.read_text())
        for index, entry in enumerate(
            (payload["static"], payload["runs"][0], payload["ruleset"])
        ):
            with self.subTest(pin=index):
                output = manifest.parent / f"custom-{index}"
                output.mkdir()
                pinned = output / "capagap-triage.json"
                (manifest.parent / entry["path"]).rename(pinned)
                entry["path"] = f"custom-{index}/capagap-triage.json"
                payload["id"] = _identity(payload)
                manifest.write_text(json.dumps(payload), encoding="utf-8")
                before = pinned.read_bytes()
                code, _, error = self.cli(
                    "case", "handoff", manifest, "--output", output, "--force"
                )
                self.assertEqual(code, 2, error)
                self.assertEqual(pinned.read_bytes(), before)
                self.assertEqual(list(output.iterdir()), [pinned])
                load_case(manifest)
        sources = [
            manifest,
            *(
                manifest.parent / entry["path"]
                for entry in (payload["static"], payload["runs"][0], payload["ruleset"])
            ),
        ]
        for index, source in enumerate(sources):
            with self.subTest(alias=index):
                output = self.root / f"alias-handoff-{index}"
                output.mkdir()
                alias = output / "capagap-triage.json"
                self.link(source, alias)
                before = source.read_bytes()
                code, _, error = self.cli(
                    "case", "handoff", manifest, "--output", output, "--force"
                )
                self.assertEqual(code, 2, error)
                self.assertEqual(source.read_bytes(), before)
                self.assertEqual(list(output.iterdir()), [alias])
                load_case(manifest)

    def test_failed_replacement_preserves_existing_report_and_cleans_temporary(self):
        report = self.root / "report.txt"
        report.write_text("preserve me", encoding="utf-8")
        with patch("capagap.output.os.replace", side_effect=OSError("blocked")):
            with self.assertRaisesRegex(OSError, "blocked"):
                write_text(report, "replacement")
        self.assertEqual(report.read_text(), "preserve me")
        self.assertEqual(list(self.root.glob(".capagap-*.tmp")), [])

    def test_completed_report_replaces_existing_output(self):
        report = self.root / "report.txt"
        report.write_text("old", encoding="utf-8")
        write_text(report, "new\n")
        self.assertEqual(report.read_bytes(), b"new\n")
        self.assertEqual(list(self.root.glob(".capagap-*.tmp")), [])
