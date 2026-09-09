from __future__ import annotations

import copy
import json
import shutil
from unittest.mock import patch

from capagap.cases import CaseError, _identity, add_case_runs, case_history, load_case
from tests.test_evidence import ROOT
from tests.test_workflows import WorkflowTestCase


class CaseRevisionTests(WorkflowTestCase):
    def revise(self, parent, **kwargs):
        return add_case_runs(
            parent,
            [("interactive", ROOT / "examples/dynamic-interactive.json")],
            self.root / "revision",
            **kwargs,
        )

    def test_single_to_matrix_preserves_parent_and_reports_delta(self):
        parent = self.case(single=True, name="Investigation", notes="Keep this")
        original = {
            p.relative_to(parent.parent): p.read_bytes()
            for p in parent.parent.rglob("*")
            if p.is_file()
        }
        path, delta = self.revise(parent, conditions=[("interactive", "network", "on")])
        case, comparison = load_case(path)
        self.assertEqual(case["schema_version"], 2)
        self.assertEqual(case["name"], "Investigation")
        self.assertEqual(case["notes"], "Keep this")
        self.assertEqual(case["history"][0]["id"], load_case(parent)[0]["id"])
        self.assertEqual(comparison.metadata["case"]["revision"], 2)
        self.assertEqual(delta["newly_observed"], ["create scheduled task"])
        self.assertEqual(len(delta["still_unobserved"]), 1)
        for relative, content in original.items():
            self.assertEqual((parent.parent / relative).read_bytes(), content)

    def test_history_is_portable_and_supports_multiple_revisions(self):
        first, _ = self.revise(self.case(single=True))
        second, _ = add_case_runs(
            first, [("repeat", self.dynamic_path)], self.root / "second"
        )
        moved = self.root / "moved"
        shutil.copytree(second.parent, moved)
        result = case_history(load_case(moved)[0])
        self.assertEqual([r["revision"] for r in result["revisions"]], [1, 2, 3])
        self.assertEqual([len(r["run_labels"]) for r in result["revisions"]], [1, 2, 3])

    def test_history_tampering_requires_new_identity(self):
        path, _ = self.revise(self.case(single=True))
        case = json.loads(path.read_text())
        case["history"][0]["id"] = "f" * 64
        path.write_text(json.dumps(case), encoding="utf-8")
        with self.assertRaisesRegex(CaseError, "configuration differs"):
            load_case(path)

    def test_malformed_history_is_rejected_even_with_recomputed_identity(self):
        path, _ = self.revise(self.case(single=True))
        original = json.loads(path.read_text())
        bad_histories = [
            None,
            {},
            [],
            [None],
            [{"id": [], "run_labels": []}],
            [{"id": "f" * 64, "run_labels": ["unknown"]}],
            [{"id": "f" * 64, "run_labels": ["baseline", "interactive"]}],
        ]
        for history in bad_histories:
            case = copy.deepcopy(original)
            case["history"] = history
            case["id"] = _identity(case)
            path.write_text(json.dumps(case), encoding="utf-8")
            with self.subTest(history=history), self.assertRaises(CaseError):
                load_case(path)

    def test_rejects_existing_labels_empty_runs_and_existing_destination(self):
        parent = self.case(single=True)
        for runs, destination in [
            ([], self.root / "new"),
            ([("baseline", self.dynamic_path)], self.root / "new"),
            ([("new", self.dynamic_path)], parent.parent),
        ]:
            with self.subTest(runs=runs), self.assertRaises(CaseError):
                add_case_runs(parent, runs, destination)

    def test_rejects_nested_destination_and_old_condition_edits(self):
        parent = self.case(single=True)
        with self.assertRaisesRegex(CaseError, "outside"):
            add_case_runs(
                parent, [("new", self.dynamic_path)], parent.parent / "nested"
            )
        with self.assertRaisesRegex(CaseError, "only describe new"):
            self.revise(parent, conditions=[("baseline", "network", "on")])
        self.assertFalse((self.root / "revision").exists())

    def test_failed_capture_leaves_no_revision(self):
        parent = self.case(single=True)
        with patch("capagap.cases.create_case", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.revise(parent)
        self.assertFalse((self.root / "revision").exists())
        self.assertEqual(list(self.root.glob(".capagap-revision-*")), [])
        load_case(parent)

    def test_cli_add_history_and_input_protection(self):
        parent = self.case(single=True)
        code, output, errors = self.cli(
            "case",
            "add-run",
            parent,
            "--run",
            f"interactive={ROOT / 'examples/dynamic-interactive.json'}",
            "--output",
            self.root / "revision",
            "--format",
            "json",
        )
        self.assertEqual(code, 0, errors)
        self.assertEqual(json.loads(output)["revision"], 2)
        code, output, errors = self.cli(
            "case", "history", self.root / "revision", "--format", "json"
        )
        self.assertEqual(code, 0, errors)
        self.assertEqual(len(json.loads(output)["revisions"]), 2)
        self.assertEqual(self.cli("case", "history", parent, "--output", parent)[0], 2)
