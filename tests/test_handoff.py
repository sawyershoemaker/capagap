from __future__ import annotations

import ast
import json
import sys
import tempfile
import types
import unittest
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from capagap.analysis import compare_documents
from capagap.cli import main
from capagap.handoff import (
    HandoffError,
    build_matrix_handoff,
    build_single_handoff,
    write_handoff,
)
from capagap.io import load_document
from capagap.matrix import compare_matrix

ROOT = Path(__file__).resolve().parents[1]
STATIC_PATH = ROOT / "examples" / "static.json"
BASELINE_PATH = ROOT / "examples" / "dynamic.json"
INTERACTIVE_PATH = ROOT / "examples" / "dynamic-interactive.json"
STATIC = load_document(STATIC_PATH)
BASELINE = load_document(BASELINE_PATH)
INTERACTIVE = load_document(INTERACTIVE_PATH)
SINGLE = compare_documents(STATIC, BASELINE)
MATRIX = compare_matrix(STATIC, (("baseline", BASELINE), ("interactive", INTERACTIVE)))


class HandoffBundleTests(unittest.TestCase):
    def test_single_run_bundle_has_rebased_locations(self):
        bundle = build_single_handoff(SINGLE, run_label="baseline")

        self.assertEqual(bundle["schema"], "capagap-handoff")
        self.assertEqual(bundle["schema_version"], 1)
        self.assertEqual(bundle["analysis"]["static_input"], "static.json")
        self.assertEqual(bundle["analysis"]["sample"]["path"], "demo.exe")
        self.assertEqual(bundle["analysis"]["source_image_base"], 0x400000)
        self.assertEqual(bundle["summary"]["selected_findings"], 2)
        self.assertEqual(bundle["summary"]["addressable_locations"], 3)
        self.assertEqual(
            {
                location["rva"]
                for finding in bundle["findings"]
                for location in finding["locations"]
            },
            {0x4000, 0x4100, 0x5000},
        )

    def test_matrix_bundle_includes_never_and_environment_sensitive(self):
        bundle = build_matrix_handoff(MATRIX)

        self.assertEqual(bundle["analysis"]["type"], "multi-run-matrix")
        self.assertEqual(bundle["summary"]["selected_findings"], 3)
        self.assertEqual(bundle["summary"]["addressable_locations"], 4)
        self.assertEqual(
            {finding["status"] for finding in bundle["findings"]},
            {"never-observed", "environment-sensitive"},
        )

    def test_matrix_bundle_can_export_only_never_observed(self):
        bundle = build_matrix_handoff(MATRIX, never_only=True)

        self.assertEqual(bundle["summary"]["selected_findings"], 1)
        self.assertEqual(bundle["findings"][0]["status"], "never-observed")

    def test_requires_a_static_image_base(self):
        without_base = replace(SINGLE, static=replace(STATIC, base_address=None))
        with self.assertRaisesRegex(HandoffError, "base_address"):
            build_single_handoff(without_base, run_label="baseline")

    def test_empty_selection_does_not_require_an_image_base(self):
        without_base = replace(SINGLE, static=replace(STATIC, base_address=None))
        bundle = build_single_handoff(
            without_base,
            run_label="baseline",
            minimum_priority="critical",
        )
        self.assertEqual(bundle["summary"]["selected_findings"], 0)
        self.assertIsNone(bundle["analysis"]["source_image_base"])


class HandoffWriterTests(unittest.TestCase):
    def test_writes_bundle_and_all_native_importers(self):
        bundle = build_single_handoff(SINGLE, run_label="baseline")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "handoff"
            written = write_handoff(bundle, output)

            self.assertEqual(len(written), 6)
            payload = json.loads((output / "capagap-handoff.json").read_text())
            self.assertEqual(payload["summary"]["addressable_locations"], 3)
            self.assertTrue((output / "CapaGapImport_Ghidra.py").is_file())
            self.assertTrue((output / "capagap_import_ida.py").is_file())
            self.assertTrue((output / "capagap_import_binja.py").is_file())
            self.assertTrue((output / "capagap-triage.json").is_file())
            ast.parse((output / "CapaGapImport_Ghidra.py").read_text())
            ast.parse((output / "capagap_import_ida.py").read_text())
            ast.parse((output / "capagap_import_binja.py").read_text())

    def test_refuses_overwrite_without_force(self):
        bundle = build_single_handoff(SINGLE, run_label="baseline")
        with tempfile.TemporaryDirectory() as directory:
            write_handoff(bundle, directory, tool="json")
            with self.assertRaisesRegex(HandoffError, "refusing to overwrite"):
                write_handoff(bundle, directory, tool="json")
            write_handoff(bundle, directory, tool="json", force=True)

    def test_cli_writes_single_run_handoff(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "handoff"
            exit_code = main(
                [
                    "handoff",
                    str(STATIC_PATH),
                    "--run",
                    f"baseline={BASELINE_PATH}",
                    "--output",
                    str(output),
                    "--tool",
                    "json",
                ]
            )

            self.assertEqual(exit_code, 0)
            self.assertTrue((output / "capagap-handoff.json").is_file())
            self.assertFalse((output / "CapaGapImport_Ghidra.py").exists())


class ImporterContractTests(unittest.TestCase):
    def _write_bundle(self, directory: str, *, include_hash: bool = True) -> Path:
        bundle = deepcopy(build_single_handoff(SINGLE, run_label="baseline"))
        if not include_hash:
            bundle["analysis"]["sample"]["sha256"] = ""
        path = Path(directory) / "capagap-handoff.json"
        path.write_text(json.dumps(bundle), encoding="utf-8")
        return path

    def test_ghidra_importer_rebases_and_creates_bookmarks(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle_path = self._write_bundle(directory)
            script_path = Path(directory) / "handoff" / "CapaGapImport_Ghidra.py"
            write_handoff(
                build_single_handoff(SINGLE, run_label="baseline"),
                script_path.parent,
                tool="ghidra",
            )
            calls = []

            class BookmarkManager:
                def setBookmark(self, address, bookmark_type, category, comment):
                    calls.append((address, bookmark_type, category, comment))

            class Program:
                def getExecutableSHA256(self):
                    return "a" * 64

                def getImageBase(self):
                    return SimpleNamespace(add=lambda rva: 0x700000 + rva)

                def getMemory(self):
                    return SimpleNamespace(contains=lambda address: True)

                def getBookmarkManager(self):
                    return BookmarkManager()

            listing = types.ModuleType("ghidra.program.model.listing")
            listing.BookmarkType = SimpleNamespace(ANALYSIS="analysis")
            modules = {
                "ghidra": types.ModuleType("ghidra"),
                "ghidra.program": types.ModuleType("ghidra.program"),
                "ghidra.program.model": types.ModuleType("ghidra.program.model"),
                "ghidra.program.model.listing": listing,
            }
            script_globals = {
                "askFile": lambda prompt, action: SimpleNamespace(
                    getAbsolutePath=lambda: str(bundle_path)
                ),
                "currentProgram": Program(),
                "println": lambda message: None,
                "printerr": lambda message: None,
            }
            with patch.dict(sys.modules, modules):
                exec(  # noqa: S102 - execute the generated importer against API mocks
                    compile(script_path.read_text(), str(script_path), "exec"),
                    script_globals,
                )

            self.assertEqual(
                {address for address, _, _, _ in calls},
                {0x704000, 0x704100, 0x705000},
            )
            self.assertTrue(all(category == "CapaGap" for _, _, category, _ in calls))

    def test_ida_importer_preserves_comments_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle_path = self._write_bundle(directory)
            output = Path(directory) / "handoff"
            write_handoff(
                build_single_handoff(SINGLE, run_label="baseline"),
                output,
                tool="ida",
            )
            comments = {0x804000: "analyst note"}
            ida_bytes = types.ModuleType("ida_bytes")
            ida_bytes.is_loaded = lambda address: True
            ida_bytes.get_cmt = lambda address, repeatable: comments.get(address)
            ida_bytes.set_cmt = lambda address, comment, repeatable: (
                comments.__setitem__(address, comment)
            )
            ida_kernwin = types.ModuleType("ida_kernwin")
            ida_kernwin.ask_file = lambda saving, mask, prompt: str(bundle_path)
            ida_kernwin.warning = lambda message: None
            ida_kernwin.refresh_idaview_anyway = lambda: None
            ida_kernwin.msg = lambda message: None
            ida_nalt = types.ModuleType("ida_nalt")
            ida_nalt.retrieve_input_file_sha256 = lambda: bytes.fromhex("aa" * 32)
            ida_nalt.get_imagebase = lambda: 0x800000
            modules = {
                "ida_bytes": ida_bytes,
                "ida_kernwin": ida_kernwin,
                "ida_nalt": ida_nalt,
            }
            script = (output / "capagap_import_ida.py").read_text()
            with patch.dict(sys.modules, modules):
                exec(  # noqa: S102 - execute the generated importer against API mocks
                    compile(script, "capagap_import_ida.py", "exec"), {}
                )
                reviewed = json.loads(bundle_path.read_text(encoding="utf-8"))
                reviewed["findings"][0]["comment"] += " | triage: confirmed"
                bundle_path.write_text(json.dumps(reviewed), encoding="utf-8")
                exec(  # noqa: S102 - repeat to verify idempotency
                    compile(script, "capagap_import_ida.py", "exec"), {}
                )

            self.assertIn("analyst note\n[CapaGap:", comments[0x804000])
            self.assertEqual(comments[0x804000].count("[CapaGap:"), 1)
            self.assertIn("triage: confirmed", comments[0x804000])
            self.assertEqual(set(comments), {0x804000, 0x804100, 0x805000})

    def test_binary_ninja_importer_registers_and_preserves_comments(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle_path = self._write_bundle(directory, include_hash=False)
            output = Path(directory) / "handoff"
            write_handoff(
                build_single_handoff(SINGLE, run_label="baseline"),
                output,
                tool="binary-ninja",
            )
            registered = {}

            def register(name, description, callback):
                registered[name] = callback

            binaryninja = types.ModuleType("binaryninja")
            binaryninja.PluginCommand = SimpleNamespace(register=register)
            binaryninja.log_error = lambda message: None
            binaryninja.log_info = lambda message: None
            binaryninja.log_warn = lambda message: None
            interaction = types.ModuleType("binaryninja.interaction")
            interaction.get_open_filename_input = lambda prompt, extension: str(
                bundle_path
            )
            interaction.show_message_box = lambda title, message: None
            modules = {
                "binaryninja": binaryninja,
                "binaryninja.interaction": interaction,
            }
            script_path = output / "capagap_import_binja.py"
            with patch.dict(sys.modules, modules):
                exec(  # noqa: S102 - execute the generated importer against API mocks
                    compile(script_path.read_text(), str(script_path), "exec"), {}
                )

            comments = {0x904000: "analyst note"}
            view = SimpleNamespace(
                start=0x900000,
                file=SimpleNamespace(
                    original_filename=str(Path(directory) / "missing.bin")
                ),
                get_segment_at=lambda address: object(),
                get_comment_at=lambda address: comments.get(address),
                set_comment_at=lambda address, comment: comments.__setitem__(
                    address, comment
                ),
            )
            callback = registered[r"CapaGap\Import handoff"]
            callback(view)
            reviewed = json.loads(bundle_path.read_text(encoding="utf-8"))
            reviewed["findings"][0]["comment"] += " | triage: likely"
            bundle_path.write_text(json.dumps(reviewed), encoding="utf-8")
            callback(view)

            self.assertIn("analyst note\n[CapaGap:", comments[0x904000])
            self.assertEqual(comments[0x904000].count("[CapaGap:"), 1)
            self.assertIn("triage: likely", comments[0x904000])
            self.assertEqual(set(comments), {0x904000, 0x904100, 0x905000})


if __name__ == "__main__":
    unittest.main()
