from __future__ import annotations

import json
from unittest.mock import patch

from capagap.analysis import compare_documents
from capagap.handoff import build_single_handoff
from capagap.io import DocumentError, load_document
from capagap.jsonio import decode_json
from capagap.manifest import (
    ManifestError,
    build_ruleset_manifest,
    load_ruleset_manifest,
)
from capagap.triage import (
    TriageError,
    build_triage_worksheet,
    load_handoff,
    load_triage,
)
from tests.test_evidence import HTTP, ROOT, rich_document
from tests.test_workflows import WorkflowTestCase


class InputErrorTests(WorkflowTestCase):
    def setUp(self):
        super().setUp()
        self.bundle = build_single_handoff(
            compare_documents(self.static, self.dynamic), run_label="baseline"
        )
        self.handoff = self.root / "handoff.json"
        self.handoff.write_text(json.dumps(self.bundle), encoding="utf-8")
        self.worksheet = build_triage_worksheet(self.bundle)

    def test_invalid_deflate_uses_document_error_and_validation_exit_code(self):
        path = self.root / "invalid.gz"
        path.write_bytes(b"\x1f\x8b\x08\x00" + b"\x00" * 6 + b"\x07" + b"\x00" * 8)
        with self.assertRaisesRegex(DocumentError, "invalid gzip"):
            load_document(path)
        code, output, error = self.cli("validate", path, "--format", "json")
        self.assertEqual(code, 2, error)
        self.assertEqual(json.loads(output)["diagnostics"][0]["code"], "invalid-input")
        self.assertNotIn("Traceback", output + error)

    def test_unpaired_surrogate_is_rejected_in_source_and_other_fields(self):
        for field in ("source", "name", "feature"):
            payload = rich_document()
            rule = payload["rules"][HTTP]
            if field == "source":
                rule["source"] += "\ud800"
            elif field == "name":
                rule["meta"]["name"] = "\ud800"
            else:
                rule["matches"][0][1]["children"][0]["node"]["feature"]["api"] = (
                    "\ud800"
                )
            path = self.root / "surrogate.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(DocumentError, "Unicode"),
            ):
                load_document(path)
            code, _, _ = self.cli("compare", path, self.dynamic_path)
            self.assertEqual(code, 2)
        self.assertEqual(decode_json(b'"\\ud83d\\ude00"'), "😀")
        self.assertEqual(decode_json(b'"\\\\ud800"'), r"\ud800")

    def test_external_json_loaders_reject_invalid_utf8_and_duplicate_keys(self):
        manifest = build_ruleset_manifest(ROOT / "examples/demo-rules").to_dict()
        for payload, loader, error_type in (
            (self.bundle, load_handoff, TriageError),
            (self.worksheet, load_triage, TriageError),
            (manifest, load_ruleset_manifest, ManifestError),
        ):
            for raw in (
                b"\xff",
                json.dumps(payload)
                .replace(
                    '"schema_version": 1', '"schema_version": 1, "schema_version": 1'
                )
                .encode(),
                json.dumps(payload)
                .replace('"schema_version": 1', '"schema_version": NaN')
                .encode(),
            ):
                with self.subTest(loader=loader.__name__, raw=raw[:20]):
                    path = self.root / "invalid.json"
                    path.write_bytes(raw)
                    with self.assertRaises(error_type):
                        loader(path)

    def test_conflicting_dispositions_are_not_silently_resolved(self):
        raw = json.dumps(self.worksheet).replace(
            '"disposition": "unreviewed"',
            '"disposition": "false-positive", "disposition": "confirmed"',
            1,
        )
        path = self.root / "review.json"
        path.write_text(raw, encoding="utf-8")
        code, _, error = self.cli("triage", "report", self.handoff, path)
        self.assertEqual(code, 2)
        self.assertIn("duplicate JSON key", error)

    def test_bad_disposition_types_fail_without_traceback(self):
        path = self.root / "review.json"
        for value in ([], {}, None, True, 2):
            self.worksheet["reviews"][0]["disposition"] = value
            path.write_text(json.dumps(self.worksheet), encoding="utf-8")
            with self.subTest(value=value):
                code, _, error = self.cli("triage", "report", self.handoff, path)
                self.assertEqual(code, 2)
                self.assertIn("invalid disposition", error)

    def test_invalid_yaml_unicode_has_a_friendly_cli_error(self):
        folder = self.root / "rules"
        folder.mkdir()
        for content in (b"\xff", b'rule:\n  meta:\n    name: "\\ud800"\n'):
            (folder / "rule.yml").write_bytes(content)
            code, _, error = self.cli(
                "manifest", folder, "--output", self.root / "manifest.json"
            )
            self.assertEqual(code, 2)
            self.assertNotIn("Traceback", error)

    def test_auxiliary_read_limits_are_applied_to_actual_bytes(self):
        path = self.root / "too-large.json"
        path.write_text(json.dumps(self.worksheet), encoding="utf-8")
        with patch("capagap.triage.MAX_JSON_BYTES", 10):
            with self.assertRaisesRegex(TriageError, "exceeds"):
                load_triage(path)
        with patch("capagap.manifest.MAX_MANIFEST_BYTES", 10):
            with self.assertRaisesRegex(ManifestError, "exceeds"):
                load_ruleset_manifest(path)

    def test_schema_version_must_be_an_integer_not_a_boolean(self):
        for payload, loader, error_type in (
            (self.worksheet, load_triage, TriageError),
            (self.bundle, load_handoff, TriageError),
            (
                build_ruleset_manifest(ROOT / "examples/demo-rules").to_dict(),
                load_ruleset_manifest,
                ManifestError,
            ),
        ):
            payload["schema_version"] = True
            path = self.root / "boolean-version.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.subTest(loader=loader.__name__), self.assertRaises(error_type):
                loader(path)
