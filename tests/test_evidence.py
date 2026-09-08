from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from capagap.analysis import compare_documents
from capagap.diagnostics import ValidationError, inspect_document
from capagap.evidence import MAX_DEPTH, EvidenceBudget, parse_matches
from capagap.html_report import _match_trees, render_html
from capagap.io import DocumentError, _normalize_address, _normalize_rule, load_document

ROOT = Path(__file__).resolve().parents[1]
HTTP = "communicate over HTTP"


def rich_document(flavor="static"):
    payload = json.loads(
        (ROOT / "examples" / f"{flavor}.json").read_text(encoding="utf-8")
    )
    layout = {"functions": []} if flavor == "static" else {"processes": []}
    count_key = "functions" if flavor == "static" else "processes"
    counts = {"file": 4, count_key: []}
    for index, (name, rule) in enumerate(payload["rules"].items()):
        for match_index, match in enumerate(rule["matches"]):
            if flavor == "static":
                address = match[0]
                location = {"type": "absolute", "value": address["value"] + 16}
                layout["functions"].append(
                    {
                        "address": address,
                        "matched_basic_blocks": [{"address": location}],
                    }
                )
            else:
                pid, tid = 1000 + index, 2000 + match_index
                address = {"type": "thread", "value": [4, pid, tid]}
                location = {"type": "call", "value": [4, pid, tid, 1]}
                match[0] = address
                layout["processes"].append(
                    {
                        "address": {"type": "process", "value": [4, pid]},
                        "name": "demo.exe",
                        "matched_threads": [
                            {
                                "address": address,
                                "matched_calls": [
                                    {
                                        "address": location,
                                        "name": "HttpSendRequestA"
                                        if name == HTTP
                                        else "SyntheticCall",
                                    }
                                ],
                            }
                        ],
                    }
                )
            counts[count_key].append({"address": address, "count": 5})
            feature = (
                {"type": "api", "api": "wininet.HttpSendRequestA"}
                if name == HTTP
                else {"type": "string", "string": "synthetic evidence: " + name}
            )
            match[1] = {
                "success": True,
                "node": {"type": "statement", "statement": {"type": "or"}},
                "children": [
                    {
                        "success": True,
                        "node": {"type": "feature", "feature": feature},
                        "children": [],
                        "locations": [location],
                        "captures": {},
                    },
                    {
                        "success": False,
                        "node": {
                            "type": "feature",
                            "feature": {"type": "string", "string": "not selected"},
                        },
                        "children": [],
                        "locations": [],
                        "captures": {},
                    },
                ],
                "locations": [],
                "captures": {},
            }
    payload["meta"]["analysis"]["layout"] = layout
    payload["meta"]["analysis"]["feature_counts"] = counts
    return payload


def write_document(root: Path, payload: dict, name="result.json") -> Path:
    path = root / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


class DocumentTestCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def load(self, payload):
        return load_document(write_document(self.root, payload))


class EvidenceTests(DocumentTestCase):
    def test_rule_completeness_does_not_inherit_another_rules_errors(self):
        payload = rich_document()
        bad, also_bad, healthy = list(payload["rules"])[:3]
        for name in (bad, also_bad):
            payload["rules"][name]["matches"][0][1]["node"]["type"] = []
        forward = self.load(payload)
        payload["rules"] = dict(reversed(list(payload["rules"].items())))
        backward = self.load(payload)
        self.assertEqual(
            forward.rules[healthy].evidence_dict(),
            backward.rules[healthy].evidence_dict(),
        )
        self.assertTrue(forward.rules[healthy].evidence_dict()["complete"])
        for document in (forward, backward):
            self.assertTrue(document.provenance["evidence_malformed"])
            for name in (bad, also_bad):
                self.assertTrue(document.rules[name].evidence_malformed)

    def test_per_rule_flags_keep_the_document_wide_node_limit(self):
        budget = EvidenceBudget(remaining=4)
        raw = rich_document()["rules"][HTTP]
        first = _normalize_rule(HTTP, raw, budget=budget)
        second = _normalize_rule(HTTP, raw, budget=budget)
        self.assertFalse(first.evidence_truncated)
        self.assertTrue(second.evidence_truncated)
        self.assertTrue(budget.truncated)
        self.assertEqual(budget.remaining, 0)

    def test_threshold_statements_show_their_counts(self):
        for count, label in (
            (0, "optional (0 or more)"),
            (1, "some: at least 1"),
            (2, "some: at least 2"),
        ):
            raw = rich_document()
            raw["rules"][HTTP]["matches"][0][1]["node"] = {
                "type": "statement",
                "statement": {"type": "some", "count": count},
            }
            rule = self.load(raw).rules[HTTP]
            self.assertEqual(rule.matches[0]["tree"]["label"], label)
            self.assertIn(label, _match_trees(rule))

    def test_invalid_threshold_is_labeled_unknown_and_malformed(self):
        for count in (None, [], -1, True, "2"):
            raw = rich_document()
            raw["rules"][HTTP]["matches"][0][1]["node"] = {
                "type": "statement",
                "statement": {"type": "some", "count": count},
            }
            rule = self.load(raw).rules[HTTP]
            self.assertTrue(rule.evidence_malformed)
            self.assertIn("threshold not recorded", _match_trees(rule))

    def test_each_compact_location_and_capture_limit_has_an_omission_notice(self):
        for kind in ("locations", "capture-keys", "capture-locations"):
            raw = rich_document()
            node = raw["rules"][HTTP]["matches"][0][1]
            addresses = [
                {"type": "absolute", "value": 0x407000 + index} for index in range(9)
            ]
            if kind == "locations":
                node["locations"] = addresses
            elif kind == "capture-keys":
                node["captures"] = {
                    f"capture {index}": [addresses[index]] for index in range(9)
                }
            else:
                node["captures"] = {"capture": addresses}
            rule = self.load(raw).rules[HTTP]
            self.assertTrue(rule.evidence_dict()["complete"])
            self.assertIn("omits detail", _match_trees(rule))
            self.assertNotIn("0x407008", _match_trees(rule))
            self.assertIn("0x407008", json.dumps(rule.evidence_dict()))

    def test_preserves_feature_and_branch_states(self):
        document = self.load(rich_document())
        tree = document.rules[HTTP].matches[0]["tree"]
        self.assertTrue(tree["children"][0]["success"])
        self.assertFalse(tree["children"][1]["success"])
        self.assertEqual(tree["children"][0]["label"], "api: wininet.HttpSendRequestA")
        self.assertEqual(
            tree["children"][0]["locations"][0]["context"]["function"], "0x402000"
        )

    def test_resolves_dynamic_process_thread_and_call(self):
        document = self.load(rich_document("dynamic"))
        match = document.rules[HTTP].matches[0]
        self.assertEqual(match["address"]["context"]["process_name"], "demo.exe")
        location = match["tree"]["children"][0]["locations"][0]
        self.assertEqual(location["context"]["call_name"], "HttpSendRequestA")
        self.assertIn("tid:", location["context"]["thread"])

    def test_captures_and_source_identity_are_retained(self):
        payload = rich_document()
        payload["rules"][HTTP]["matches"][0][1]["children"][0]["captures"] = {
            "captured value": [{"type": "absolute", "value": 0x402010}]
        }
        rule = self.load(payload).rules[HTTP]
        self.assertEqual(
            rule.matches[0]["tree"]["children"][0]["captures"]["captured value"][0][
                "display"
            ],
            "0x402010",
        )
        self.assertEqual(len(rule.evidence_dict()["fingerprint"]), 64)
        self.assertTrue(rule.source_available)

    def test_missing_tree_is_not_a_failed_branch(self):
        document = load_document(ROOT / "examples/static.json")
        self.assertIsNone(document.rules[HTTP].matches[0]["tree"])
        self.assertIn(
            "match-trees-unavailable", {item.code for item in document.diagnostics}
        )

    def test_deep_tree_is_bounded_and_disclosed(self):
        payload = rich_document()
        node = payload["rules"][HTTP]["matches"][0][1]
        for _ in range(MAX_DEPTH + 8):
            node["children"] = [
                {
                    "success": True,
                    "node": {"type": "statement", "statement": {"type": "and"}},
                    "children": [],
                }
            ]
            node = node["children"][0]
        document = self.load(payload)
        self.assertTrue(document.rules[HTTP].evidence_truncated)
        self.assertIn(
            "evidence-truncated", {item.code for item in document.diagnostics}
        )

    def test_global_node_budget(self):
        raw = rich_document()["rules"][HTTP]["matches"]
        budget = EvidenceBudget(remaining=1)
        result = parse_matches(raw, _normalize_address, {}, budget)
        self.assertTrue(budget.truncated)
        self.assertEqual(result[0]["tree"]["children"][0]["kind"], "omitted")

    def test_malformed_node_does_not_crash(self):
        payload = rich_document()
        payload["rules"][HTTP]["matches"][0][1]["node"]["type"] = []
        document = self.load(payload)
        self.assertIn(
            "malformed-evidence", {item.code for item in document.diagnostics}
        )

    def test_hostile_feature_text_remains_data(self):
        payload = rich_document()
        attack = '</script><svg onload="window.compromised=true">'
        payload["rules"][HTTP]["matches"][0][1]["children"][0]["node"]["feature"][
            "api"
        ] = attack
        static = self.load(payload)
        dynamic = load_document(
            write_document(self.root, rich_document("dynamic"), "dynamic.json")
        )
        html = render_html(compare_documents(static, dynamic))
        self.assertNotIn(attack, html)
        self.assertIn("&lt;/script&gt;", html)
        self.assertIn("Runtime evidence", html)
        self.assertIn("Input diagnostics", html)

    def test_long_feature_text_has_a_reported_bound(self):
        payload = rich_document()
        payload["rules"][HTTP]["matches"][0][1]["children"][0]["node"]["feature"][
            "api"
        ] = "A" * 20_000
        document = self.load(payload)
        self.assertTrue(document.provenance["evidence_truncated"])
        self.assertLess(
            len(document.rules[HTTP].matches[0]["tree"]["children"][0]["label"]), 9000
        )

    def test_result_hash_changes_with_content(self):
        payload = rich_document()
        before = self.load(payload)
        payload["meta"]["timestamp"] = "2026-09-08T00:00:00Z"
        after = self.load(payload)
        self.assertNotEqual(
            before.provenance["content_sha256"], after.provenance["content_sha256"]
        )
        self.assertEqual(
            before.rules[HTTP].evidence_dict()["fingerprint"],
            after.rules[HTTP].evidence_dict()["fingerprint"],
        )


class DiagnosticTests(DocumentTestCase):
    def test_matching_malformed_hashes_are_not_high_confidence(self):
        from dataclasses import replace

        static = replace(self.load(rich_document()), sample_sha256="invalid")
        dynamic = replace(self.load(rich_document("dynamic")), sample_sha256="invalid")
        self.assertEqual(compare_documents(static, dynamic).confidence, "medium")

    def test_restricted_analysis(self):
        for flag in (
            "-t",
            "--tag=communication",
            "--restrict-to-functions=0x402000",
            "-tcommunication",
        ):
            payload = rich_document()
            payload["meta"]["argv"].append(flag)
            self.assertIn(
                "restricted-analysis",
                {item.code for item in self.load(payload).diagnostics},
            )

    def test_feature_threshold_is_explicit(self):
        document = self.load(rich_document())
        self.assertNotIn(
            "sparse-features", {item.code for item in document.diagnostics}
        )
        self.assertIn(
            "sparse-features",
            {item.code for item in inspect_document(document, minimum_features=1000)},
        )

    def test_invalid_feature_counts_are_not_treated_as_zero(self):
        payload = rich_document()
        payload["meta"]["analysis"]["feature_counts"]["file"] = True
        document = self.load(payload)
        self.assertIsNone(document.provenance["feature_counts"]["total"])
        self.assertIn(
            "invalid-feature-counts", {item.code for item in document.diagnostics}
        )

    def test_empty_results_and_unknown_scope(self):
        payload = rich_document()
        payload["rules"][HTTP]["meta"]["scopes"]["dynamic"] = "future-scope"
        document = self.load(payload)
        self.assertFalse(document.rules[HTTP].dynamically_comparable)
        self.assertIn(
            "unsupported-dynamic-scope", {item.code for item in document.diagnostics}
        )
        payload["rules"] = {}
        self.assertIn(
            "no-rule-matches", {item.code for item in self.load(payload).diagnostics}
        )

    def test_missing_rule_source_and_metadata(self):
        payload = rich_document()
        payload["rules"][HTTP].pop("source")
        payload["meta"]["sample"]["sha256"] = "not-a-hash"
        payload["meta"]["analysis"].pop("extractor")
        codes = {item.code for item in self.load(payload).diagnostics}
        self.assertTrue(
            {"rule-source-unavailable", "sample-identity", "missing-metadata"} <= codes
        )

    def test_strict_comparison_rejects_warnings(self):
        static = load_document(ROOT / "examples/static.json")
        dynamic = load_document(ROOT / "examples/dynamic.json")
        with self.assertRaises(ValidationError):
            compare_documents(static, dynamic, strict=True)

    def test_strict_comparison_accepts_complete_inputs(self):
        static = self.load(rich_document())
        dynamic = load_document(
            write_document(self.root, rich_document("dynamic"), "dynamic.json")
        )
        self.assertEqual(
            compare_documents(static, dynamic, strict=True).confidence, "high"
        )

    def test_duplicate_keys_and_nonfinite_json_are_rejected(self):
        for raw in (
            '{"meta": {}, "meta": {}, "rules": {}}',
            '{"x": NaN}',
            '{"x": Infinity}',
            '{"x": 1e999}',
        ):
            path = self.root / "invalid.json"
            path.write_text(raw, encoding="utf-8")
            with self.assertRaises(DocumentError):
                load_document(path)

    def test_rule_name_collision_is_rejected(self):
        payload = rich_document()
        payload["rules"][HTTP]["meta"]["name"] = "another rule"
        with self.assertRaisesRegex(DocumentError, "mapping keys"):
            self.load(payload)
