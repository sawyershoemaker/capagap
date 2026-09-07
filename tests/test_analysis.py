from __future__ import annotations

import unittest
from dataclasses import replace
from pathlib import Path

from capagap.analysis import ComparisonError, compare_documents
from capagap.io import load_document

ROOT = Path(__file__).resolve().parents[1]
STATIC = load_document(ROOT / "examples" / "static.json")
DYNAMIC = load_document(ROOT / "examples" / "dynamic.json")


class ComparisonTests(unittest.TestCase):
    def test_classifies_capabilities(self):
        result = compare_documents(STATIC, DYNAMIC)
        self.assertEqual(result.summary.static_rules, 5)
        self.assertEqual(result.summary.dynamic_rules, 3)
        self.assertEqual(result.summary.comparable_static_rules, 4)
        self.assertEqual(result.summary.observed_rules, 2)
        self.assertEqual(result.summary.unobserved_rules, 2)
        self.assertEqual(result.summary.static_only_rules, 1)
        self.assertEqual(result.summary.dynamic_only_rules, 1)
        self.assertEqual(result.summary.observed_coverage, 0.5)

    def test_library_rules_are_optional(self):
        result = compare_documents(STATIC, DYNAMIC, include_library=True)
        self.assertEqual(result.summary.static_rules, 6)
        self.assertEqual(result.summary.static_only_rules, 2)

    def test_unobserved_rules_are_ranked(self):
        result = compare_documents(STATIC, DYNAMIC)
        self.assertEqual(
            result.unobserved[0].rule.name, "inject shellcode into remote process"
        )
        self.assertGreaterEqual(
            result.unobserved[0].priority, result.unobserved[1].priority
        )
        self.assertEqual(result.unobserved[0].priority_label, "high")

    def test_observed_anti_analysis_creates_gate_context(self):
        result = compare_documents(STATIC, DYNAMIC)
        self.assertEqual(result.gate_signals, ("check for sandbox process names",))
        self.assertIn(
            "anti-analysis capability", " ".join(result.unobserved[0].reasons)
        )

    def test_dynamic_only_is_reported(self):
        result = compare_documents(STATIC, DYNAMIC)
        self.assertEqual(result.dynamic_only[0].rule.name, "execute shell command")

    def test_rejects_sample_mismatch_by_default(self):
        other = replace(DYNAMIC, sample_sha256="b" * 64)
        with self.assertRaisesRegex(ComparisonError, "SHA-256 values differ"):
            compare_documents(STATIC, other)

    def test_allows_sample_mismatch_with_low_confidence(self):
        other = replace(DYNAMIC, sample_sha256="b" * 64)
        result = compare_documents(STATIC, other, allow_mismatch=True)
        self.assertEqual(result.confidence, "low")
        self.assertTrue(result.warnings)

    def test_missing_hash_lowers_confidence(self):
        other = replace(DYNAMIC, sample_sha256="")
        result = compare_documents(STATIC, other)
        self.assertEqual(result.confidence, "medium")

    def test_architecture_mismatch_lowers_confidence(self):
        other = replace(DYNAMIC, arch="i386")
        result = compare_documents(STATIC, other)
        self.assertEqual(result.confidence, "medium")
        self.assertIn("architecture differs", result.warnings[0])

    def test_source_drift_is_visible(self):
        rules = dict(DYNAMIC.rules)
        rules["communicate over HTTP"] = replace(
            rules["communicate over HTTP"], source_digest="different"
        )
        result = compare_documents(STATIC, replace(DYNAMIC, rules=rules))
        self.assertIn("communicate over HTTP", result.source_drift)
        self.assertTrue(any("rule-set drift" in warning for warning in result.warnings))

    def test_maps_gap_evidence_into_ranked_hotspots(self):
        result = compare_documents(STATIC, DYNAMIC)
        self.assertEqual(
            {hotspot.rva for hotspot in result.evidence_hotspots},
            {0x4000, 0x4100, 0x5000},
        )
        self.assertTrue(all(hotspot.rule_names for hotspot in result.evidence_hotspots))


if __name__ == "__main__":
    unittest.main()
