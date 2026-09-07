from __future__ import annotations

import gzip
import tempfile
import unittest
from pathlib import Path

from capagap.io import DocumentError, load_document

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "examples" / "static.json"
DYNAMIC = ROOT / "examples" / "dynamic.json"


class LoadDocumentTests(unittest.TestCase):
    def test_loads_static_document(self):
        document = load_document(STATIC, expected_flavor="static")
        self.assertEqual(document.flavor, "static")
        self.assertEqual(document.arch, "amd64")
        self.assertEqual(document.base_address, 0x400000)
        self.assertEqual(len(document.rules), 6)

    def test_normalizes_rule_metadata(self):
        rule = load_document(STATIC).rules["inject shellcode into remote process"]
        self.assertEqual(rule.dynamic_scope, "thread")
        self.assertEqual(rule.attack_ids, ("T1055",))
        self.assertEqual(rule.evidence, ("0x404000", "0x404100"))
        self.assertEqual(
            tuple(address.rva(0x400000) for address in rule.evidence_addresses),
            (0x4000, 0x4100),
        )

    def test_missing_dynamic_scope_is_not_comparable(self):
        rule = load_document(STATIC).rules["encrypt data using AES"]
        self.assertIsNone(rule.dynamic_scope)
        self.assertFalse(rule.dynamically_comparable)

    def test_detects_gzip_by_magic_not_extension(self):
        with tempfile.TemporaryDirectory() as directory:
            compressed = Path(directory) / "result.data"
            with STATIC.open("rb") as source, gzip.open(compressed, "wb") as target:
                target.write(source.read())
            document = load_document(compressed)
        self.assertEqual(document.flavor, "static")

    def test_rejects_wrong_expected_flavor(self):
        with self.assertRaisesRegex(DocumentError, "expected a static result"):
            load_document(DYNAMIC, expected_flavor="static")

    def test_rejects_non_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text("not-json", encoding="utf-8")
            with self.assertRaisesRegex(DocumentError, "invalid JSON"):
                load_document(path)

    def test_rejects_non_capa_shape(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "other.json"
            path.write_text('{"hello": "world"}', encoding="utf-8")
            with self.assertRaisesRegex(DocumentError, "does not look like a capa"):
                load_document(path)

    def test_rejects_directory_input_cleanly(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            self.assertRaisesRegex(DocumentError, "(cannot|could not) read input"),
        ):
            load_document(directory)


if __name__ == "__main__":
    unittest.main()
