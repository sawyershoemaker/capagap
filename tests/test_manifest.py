from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from capagap.analysis import ComparisonError, compare_documents
from capagap.cli import main
from capagap.io import load_document
from capagap.manifest import (
    ManifestError,
    RuleManifest,
    RuleManifestEntry,
    build_ruleset_manifest,
    load_ruleset_manifest,
    write_ruleset_manifest,
)

ROOT = Path(__file__).resolve().parents[1]
STATIC = load_document(ROOT / "examples" / "static.json")
DYNAMIC = load_document(ROOT / "examples" / "dynamic.json")


def _rule(name: str, *, dynamic: str = "process", library: bool = False) -> str:
    return f"""rule:
  meta:
    name: {name}
    namespace: test/example
    scopes:
      static: function
      dynamic: {dynamic}
    lib: {"true" if library else "false"}
  features:
    - api: kernel32.CreateFileA
"""


def _manifest_for_documents() -> RuleManifest:
    rules = {}
    for rule in [*STATIC.rules.values(), *DYNAMIC.rules.values()]:
        rules[rule.name] = RuleManifestEntry(
            name=rule.name,
            namespace=rule.namespace,
            static_scope=rule.static_scope,
            dynamic_scope=rule.dynamic_scope,
            library=rule.library,
            source_digest=rule.source_digest,
            relative_path=f"{rule.name}.yml",
        )
    # The comparison engine intentionally only relies on entry digests; manifests
    # built/loaded from disk validate the aggregate fingerprint separately.
    return RuleManifest(
        path=Path("test-manifest.json"),
        source_name="test",
        rules=rules,
        fingerprint="0" * 64,
    )


class ManifestTests(unittest.TestCase):
    def test_builds_and_round_trips_ruleset(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "one.yml").write_text(_rule("one"), encoding="utf-8")
            (root / "quoted.yaml").write_text(
                _rule('"two: quoted"', dynamic="unsupported", library=True),
                encoding="utf-8",
            )
            (root / "config.yml").write_text("settings:\n  enabled: true\n")
            manifest = build_ruleset_manifest(root)
            self.assertEqual(set(manifest.rules), {"one", "two: quoted"})
            self.assertEqual(manifest.skipped_files, ("config.yml",))
            self.assertTrue(manifest.rules["two: quoted"].library)
            self.assertIsNone(manifest.rules["two: quoted"].dynamic_scope)

            output = root / "manifest.json"
            write_ruleset_manifest(manifest, output)
            loaded = load_ruleset_manifest(output)
            self.assertEqual(loaded.fingerprint, manifest.fingerprint)
            self.assertEqual(set(loaded.rules), set(manifest.rules))

    def test_rejects_duplicate_rule_names(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "one.yml").write_text(_rule("same"), encoding="utf-8")
            (root / "two.yml").write_text(_rule("same"), encoding="utf-8")
            with self.assertRaisesRegex(ManifestError, "duplicate capa rule"):
                build_ruleset_manifest(root)

    def test_rejects_tab_indentation_and_bad_fingerprint(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bad.yml").write_text("rule:\n\tmeta:\n", encoding="utf-8")
            with self.assertRaisesRegex(ManifestError, "tabs"):
                build_ruleset_manifest(root)

            payload = {
                "schema": "capagap-ruleset-manifest",
                "schema_version": 1,
                "fingerprint": "0" * 64,
                "rules": [
                    {
                        "name": "one",
                        "namespace": "test",
                        "static_scope": "function",
                        "dynamic_scope": "process",
                        "library": False,
                        "source_digest": "f" * 64,
                        "path": "one.yml",
                    }
                ],
            }
            path = root / "bad.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ManifestError, "fingerprint"):
                load_ruleset_manifest(path)

    def test_refuses_overwrite_and_cli_generates_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "one.yml").write_text(_rule("one"), encoding="utf-8")
            output = root / "manifest.json"
            self.assertEqual(main(["manifest", str(root), "--output", str(output)]), 0)
            self.assertEqual(main(["manifest", str(root), "--output", str(output)]), 2)


class VerifiedComparisonTests(unittest.TestCase):
    def test_manifest_verified_comparison_preserves_coverage(self):
        result = compare_documents(
            STATIC, DYNAMIC, ruleset_manifest=_manifest_for_documents()
        )
        self.assertEqual(result.summary.comparable_static_rules, 4)
        self.assertEqual(result.summary.ruleset_unverified_rules, 0)
        self.assertIn("ruleset_manifest", result.metadata)

    def test_unverified_static_rule_is_excluded_from_denominator(self):
        manifest = _manifest_for_documents()
        rules = dict(manifest.rules)
        target = "inject shellcode into remote process"
        rules[target] = replace(rules[target], source_digest="f" * 64)
        result = compare_documents(
            STATIC,
            DYNAMIC,
            ruleset_manifest=replace(manifest, rules=rules),
        )
        self.assertEqual(result.summary.comparable_static_rules, 3)
        self.assertEqual(result.summary.ruleset_unverified_rules, 1)
        self.assertEqual(result.ruleset_unverified[0].rule.name, target)

    def test_manifest_must_match_every_dynamic_rule(self):
        manifest = _manifest_for_documents()
        rules = dict(manifest.rules)
        rules.pop("execute shell command")
        with self.assertRaisesRegex(ComparisonError, "absent"):
            compare_documents(
                STATIC,
                DYNAMIC,
                ruleset_manifest=replace(manifest, rules=rules),
            )


if __name__ == "__main__":
    unittest.main()
