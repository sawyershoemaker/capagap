# Comparison model

## Rule sets and coverage

For a static result `S` and a dynamic result `D`, let `C` contain the static matches whose metadata declares a supported dynamic scope. Library rules are excluded unless explicitly requested.

```text
observed     = C ∩ D
unobserved   = C - D
static-only  = S - C
dynamic-only = D - S
coverage     = |observed| / |C|
```

The unit is a matched capa rule, not a function, instruction, execution path, or percentage of code executed. An empty denominator is reported as `n/a`.

Rules are matched by name. Shared rules with different source SHA-256 digests are flagged as drift. Source digests normalize CRLF to LF before hashing.

## Ruleset manifests

A capa result contains matched rules, not a complete inventory of loaded rules. An absent result therefore does not establish that the rule was available to that run.

A supplied manifest adds a source-consistency check:

1. Every included dynamic match must exist in the manifest with the same source digest, or comparison fails.
2. Comparable static matches without an exact manifest source match are classified as `ruleset-unverified`.
3. Unverified rules are excluded from both observed and unobserved coverage counts.

The manifest stores rule names, source digests, scopes, library flags, and relative paths. Its aggregate fingerprint covers sorted rule names and source digests. The metadata reader handles the indented capa rule format without executing YAML tags.

A manifest does not attest to the command, extractor configuration, or full ruleset actually used in a historical run. Preserve those details with the case.

## Input confidence

Matching valid sample hashes start a comparison at high confidence. Missing or malformed hashes lower it to medium. OS, architecture, and capa major-version differences each lower it by one level. Different valid hashes are rejected unless `--allow-mismatch` is set, in which case confidence is low.

This label describes input consistency, not the reliability of a particular behavioral conclusion.

## Finding priority

The score is deterministic and capped at 100. It combines a baseline with:

- the highest applicable namespace category weight;
- ATT&CK and MBC mappings;
- repeated static match locations;
- a supported process, thread, or call scope; and
- anti-analysis context from observed matches.

Each factor is included in the finding's reasons. The implementation is in [scoring.py](../src/capagap/scoring.py).

An observed anti-analysis rule gives other gaps a small priority boost. That records a possible lead; it does not establish that the check caused missing behavior.

## Multiple runs

For dynamic results `D₁ … Dₙ`, each comparable static rule has an observation vector:

```text
observed-in-all       = present in every Dᵢ
environment-sensitive = present in some, but not all, Dᵢ
never-observed        = absent from every Dᵢ
union coverage        = |C ∩ (D₁ ∪ … ∪ Dₙ)| / |C|
```

The first labeled run is the baseline. Conditions supplied with `--condition` are compared by key and value. Zero or multiple changed keys produce warnings; missing condition declarations also produce warnings. Nothing in the result document proves those declarations are complete.

Runtime-only matches and anti-analysis signals retain the labels of the runs that observed them.

## Address handling

Only unambiguous virtual addresses become portable RVAs:

```text
absolute match -> address - static image base
relative match -> address
other kinds    -> unmappable evidence
```

Handoff rejects a selection containing absolute matches when the static image base is missing. Importers add RVAs to the current database base, check mapped memory, and reject a known sample-hash mismatch.

Evidence hotspots group findings at the same exact RVA. They are sorted by finding count, aggregate priority, and RVA. The maximum priority is included for reference. No function boundary or control-flow edge is inferred.

## Analyst review

Finding IDs are derived from the rule name and source digest. A separate triage worksheet holds analyst dispositions and notes. Its identity hashes the sample SHA-256 and sorted finding IDs to catch accidental mismatches; it is not a digital signature or a complete case identity.

Applying a worksheet creates a reviewed handoff. IDA and Binary Ninja replace comment lines carrying the corresponding CapaGap marker. Ghidra updates only the Analysis bookmark in the CapaGap category at each location.

## Input handling

Detailed match evidence is a bounded projection of the result document: statements, features, success states, captures, locations, and explicitly recorded layout containment. It is not a re-evaluation of a capa rule. Absent rules have no result tree to inspect. JSON stores each retained view's SHA-256 fingerprint and availability separately from the original rule-source digest and input-content digest.

Cases pin decompressed input bytes, run labels/settings, an optional ruleset, and comparison options. Their identity excludes editable case names and notes. All references must resolve inside the case directory. The identity detects accidental mixing and changes, but does not authenticate the author.

Saved-report diffs compare rule names and shared run labels. Source drift and changed extraction context take precedence over an observation-only classification. Added runs do not become gained observations in old runs. Missing provenance prevents a claim of equivalent context. Input timestamps and paths are deliberately not behavioral change signals.

Run contributions operate on each run's intersection with comparable static capabilities. Unique coverage counts capabilities seen in exactly one run. Incremental coverage depends on input order. Greedy set cover retains the observed union, breaking ties by input order; it does not guarantee the smallest subset or equivalent behavior outside the measured rules.

Structured diagnostics are independent of coverage and input-consistency confidence. Strict mode blocks on warnings and errors; normal mode retains them as advisory context. Missing counts remain unknown. A caller-selected feature-count threshold does not imply execution coverage.

CapaGap never executes sample content or embedded rule source. JSON inputs are limited to 256 MiB after decompression and reject duplicate keys/non-finite numbers. Results support at most 50,000 rule records. Detailed evidence retains at most 2,048 matches per rule, 50,000 tree nodes per document, 32 tree levels, 128 items per node list, and 8,192 characters per evidence string. Layout indexing is separately bounded at 50,000 records. HTML uses a smaller compact tree view and points to JSON for additional retained detail. Manifest, worksheet, and case-manifest inputs have separate size limits.

Native importer scripts are fixed package resources. Report-controlled text is loaded as JSON data, not inserted into executable source. Manifest, handoff, and triage writes require explicit overwrite flags; ordinary report output replaces an existing destination.

Generated reports can contain sensitive paths, indicators, and analyst notes. They are not redacted automatically.
