# Command reference

Run `capagap COMMAND --help` for the accepted options. Commands below assume the current directory is the project root. Output goes under `reports/`, which is ignored by git.

## compare

```sh
capagap compare STATIC DYNAMIC [options]
```

Both inputs must be capa result documents. The first must have `meta.flavor` set to `static`, the second to `dynamic`. Gzip is detected by its file signature.

| Option | Effect |
|---|---|
| `--format text\|markdown\|json\|html` | Choose a report format. Default: `text`. |
| `--output PATH` | Write a report instead of printing it. An existing report is overwritten. |
| `--minimum-priority low\|medium\|high\|critical` | Filter gap findings in text and Markdown output. Default: `low`. |
| `--limit N` | Limit rows in human-readable sections. Default: `25`; minimum: `1`. |
| `--include-library` | Include capa helper/library rules, which are excluded by default. |
| `--allow-mismatch` | Permit different sample SHA-256 values and mark the comparison low-confidence. |
| `--ruleset-manifest PATH` | Compare rule source digests against a manifest. |
| `--strict` | Stop on validation warnings before generating output. |
| `--minimum-features N` | Warn below this extracted-feature count. Default/minimum: `1`. |
| `--fail-on-unobserved` | Return `3` if any comparable static capability is unobserved. |

JSON and HTML reports retain all findings. Priority filters do not change summary counts or exit-code checks.

## matrix

```sh
capagap matrix STATIC --run LABEL=PATH --run LABEL=PATH [options]
```

A matrix needs two to 128 dynamic results with unique, nonempty labels of at most 256 characters. It accepts the report options above, except that `--fail-on-never-observed` replaces `--fail-on-unobserved`.

The report separates capabilities seen in all runs, seen in only some runs (`environment-sensitive`), and absent from every run (`never-observed`). Coverage is also calculated for the union of all supplied runs.

Repeat `--condition LABEL:KEY=VALUE` to record run settings. The first run is the baseline. Each other run is checked for the number of changed keys; zero or multiple changes produce warnings. Unknown labels and duplicate keys within a run are errors. These are checks of declared metadata, not measurements of the sandbox configuration.

See [experiment setup](EXPERIMENTS.md) for a worked example.

## HTML reports

Both comparison commands accept `--format html --output REPORT.html`. Open the file in a modern browser; no web server or internet connection is needed.

The matrix starts with comparable capabilities. Use the Runtime-only and Excluded controls to inspect other findings without changing coverage. Expand a row to see its evidence, scopes, identifiers, and follow-up. Runtime evidence is labeled by run and retains its original address type. Static addresses show a portable RVA when one can be calculated; unmapped locations remain visible.

Matched feature trees are a second disclosure within each evidence block. They preserve statement/feature labels, branch outcomes, locations, captured strings, and recorded function or process/thread/call context. No call graph or failed tree for an unmatched rule is inferred. Missing trees, parser retention limits, and compact-display omissions are labeled separately. Export JSON contains the full retained view; it cannot recover data omitted during parsing.

Search is case-insensitive and matches every space-separated term within a finding's name, namespace, state, identifiers, evidence locations, APIs, strings, or process/call labels. The state filter combines with search. Switching views clears the state filter but preserves search. Run conditions, contributions, exact-RVA hotspots, diagnostics, input metadata, and case notes sit below the matrix. Input warnings are expanded by default.

| Control | Keyboard behavior |
|---|---|
| Search | `/` focuses search when not typing in another control. |
| Row disclosure | Enter or Space toggles evidence; Right opens it; Left closes it. |
| Row navigation | Up and Down move between visible row disclosure buttons. |
| Evidence | Escape closes the row and returns focus to its disclosure button. |
| Copy dialog | If automatic copying is blocked, select the text and copy manually. Escape closes the dialog. |

Export JSON downloads the complete report, not just the filtered view. Copy controls are available for evidence addresses, mapped RVAs, image bases, and sample hashes. Printing includes all findings and evidence, including filtered-out rows. With JavaScript disabled, all rows and evidence remain visible; filtering, copying, and export controls are unavailable.

The HTML file embeds the report data. Paths and strings are not redacted; check them before sharing the file or its JSON export.

## manifest

```sh
capagap manifest RULE_DIRECTORY --output reports/ruleset.json
```

Scans `.yml` and `.yaml` files recursively. The manifest stores names, scopes, library flags, relative paths, and SHA-256 digests of rule source text with CRLF normalized to LF. Rule names must be unique. Unrelated YAML files are listed as skipped.

The metadata reader supports the indented capa rule format, not arbitrary YAML. It does not execute tags or resolve anchors. This command is not a replacement for capa's rule validation.

Supply the resulting file with `--ruleset-manifest` on `compare`, `matrix`, or `handoff`. Matched dynamic rules must agree with the manifest. Comparable static rules without an exact source match are excluded from coverage and listed separately as `ruleset-unverified`.

Existing manifests require `--force` to overwrite. A supplied manifest is a consistency check, not evidence of which rules were loaded in an earlier analysis.

## handoff

```sh
capagap handoff STATIC --run LABEL=PATH --output DIRECTORY [options]
```

One run exports unobserved findings. Two or more runs export never-observed and environment-sensitive findings. Multi-run handoffs accept the same `--condition` syntax as `matrix`.

| Option | Effect |
|---|---|
| `--tool all\|json\|ghidra\|ida\|binary-ninja` | Choose import scripts. Default: `all`. |
| `--minimum-priority low\|medium\|high\|critical` | Select findings by score. Default: `low`. |
| `--never-only` | Exclude environment-sensitive findings. Requires at least two runs. |
| `--ruleset-manifest PATH` | Verify rule sources before exporting findings. |
| `--include-library` | Include helper/library rules in the analysis. |
| `--allow-mismatch` | Permit mismatched report hashes. Importers still reject a known database hash mismatch. |
| `--strict` | Stop on input-quality or comparison warnings. |
| `--minimum-features N` | Set the input feature-count warning threshold. |
| `--force` | Overwrite existing output files, including the triage worksheet. |

The output includes:

| File | Purpose |
|---|---|
| `capagap-handoff.json` | Selected findings, evidence locations, and comments. |
| `capagap-triage.json` | Editable analyst reviews. |
| `README.txt` | Import instructions. |
| `CapaGapImport_Ghidra.py` | Ghidra Analysis bookmarks in the CapaGap category. |
| `capagap_import_ida.py` | IDA repeatable comments. |
| `capagap_import_binja.py` | Binary Ninja address comments. |

Script selection does not affect the JSON bundle. `--tool json` writes only the two JSON files and instructions.

Absolute match addresses are converted to RVAs using `meta.analysis.base_address`. Export fails if that base is missing and the selection contains absolute evidence. File offsets, .NET tokens, and dynamic coordinates are retained as unmappable evidence rather than converted to virtual addresses. Importers skip unmapped addresses and reject a known sample-hash mismatch.

Handoff JSON also retains per-finding match trees and per-run runtime evidence. Annotation placement still uses static top-level match addresses.

## validate

```sh
capagap validate INPUT [INPUT ...] --minimum-features 1 --format json
```

Accepts text, Markdown, or JSON output and `--output PATH`. Each diagnostic has a stable `code`, `severity`, `input`, and `message`. With exactly one static input, validation also checks its compatibility with every supplied dynamic input. Multiple static inputs are validated individually.

Warnings include invalid/missing sample identity or extraction metadata, restricted capa invocations, no matches, feature counts below the requested threshold, invalid counts, missing source text, unsupported dynamic scopes, and malformed/truncated evidence. Missing invocation arguments, counts, or detailed trees are informational: absence is not treated as a zero count. The feature threshold is an analyst choice, not a malware classification.

Exit `0` means no warnings/errors; `4` means warnings; `2` means an invalid input or incompatible comparison. The diagnostics report is still written. `--strict` on comparison/export commands instead stops before writing any output when warnings exist. A strict matrix checks declared experimental conditions as well as document quality.

## case

```sh
capagap case init STATIC --run LABEL=PATH [--run LABEL=PATH ...] \
  --name "Case name" --notes "Analyst notes" --output NEW_DIRECTORY
capagap case verify CASE --format json
capagap case report CASE --format html --output reports/case.html
capagap case handoff CASE --tool all --output reports/handoff
```

`CASE` can be a directory or its manifest file. `init` accepts one to 128 runs, `--condition LABEL:KEY=VALUE`, `--ruleset-manifest`, `--include-library`, and `--allow-mismatch`. It never replaces an existing destination. Inputs are copied as decompressed JSON under `inputs/`; the optional ruleset is copied too. No sample files are copied or executed.

The manifest pins SHA-256 hashes, relative paths, labels, conditions, and comparison options in a case identity. A changed file, unsafe path, or changed configuration stops verification. The identity is a mix-up/tamper-detection aid, not a signature: someone who can edit the manifest can recompute it. `name` and `notes` deliberately remain editable. Preserve earlier cases and capture new snapshots when adding runs or changing settings.

`verify` verifies integrity and displays quality diagnostics. Integrity success returns `0` even if quality warnings exist; add `--strict` to return `4` for warnings. `report` accepts all four output formats, `--minimum-priority`, and `--limit`. `handoff` accepts `--tool`, `--minimum-priority`, `--never-only` (multiple runs), and `--force`. All three accept `--strict`. Reports and handoffs retain case identity, notes, conditions, and provenance. Report output cannot overwrite the case manifest or pinned inputs.

## diff

```sh
capagap diff BEFORE AFTER --format json --output reports/diff.json --fail-on-change
```

Both inputs must be saved CapaGap JSON comparisons of the same type: single-run or matrix. HTML's JSON export is accepted. Raw capa JSON is not. Known sample-hash mismatches are rejected unless `--allow-mismatch` is explicitly set.

Shared run labels align observations. Added/removed labels are run-set changes, not newly observed behavior in an existing run. Findings are matched by rule name; retained source and evidence digests qualify the result. Changes are classified as `finding-added`, `finding-removed`, `rule-changed`, `source-unverified`, `analysis-context-changed`, `observation-changed`, `run-set-changed`, `classification-changed`, or `evidence-changed`. Analysis context includes sample, capa/extractor/platform, restrictions, ruleset manifest, library inclusion, confidence, and declared conditions. Case name/note edits have their own `review_changes` list.

Legacy 0.1 reports are accepted, but missing source/provenance is not assumed equivalent. Evidence fingerprints are verified before comparison. A changed or missing evidence tree is not proof of changed execution. Input file paths, timestamps, and JSON formatting alone do not count as observation changes.

Output formats are text, Markdown, and JSON. Normal exit is `0`; `--fail-on-change` returns `3` after writing a changed result. Invalid reports return `2`. Diff output cannot overwrite either input.

## contributions

```sh
capagap contributions STATIC --run LABEL=PATH --run LABEL=PATH --format json
```

Accepts matrix input and report options, including `--condition`, `--ruleset-manifest`, `--strict`, and `--minimum-features`. Text/Markdown show each run's unique coverage and a representative set. JSON also includes baseline additions/missing capabilities, order-dependent incremental coverage, pairwise intersection/union counts, and Jaccard overlap. When both sets are empty, Jaccard is `null`, not perfect agreement. HTML produces the full matrix with its contributions disclosure.

Only comparable static capabilities enter this calculation. The greedy representative set repeatedly chooses the run covering the most remaining capabilities, breaking ties by input order. It preserves the supplied union but is not guaranteed minimal. A run can be individually redundant while still being needed if another redundant run is removed. Do not delete traces based solely on this result.

## triage

Handoff generation creates a worksheet automatically. For an existing bundle:

```sh
capagap triage init HANDOFF --output WORKSHEET
capagap triage report HANDOFF WORKSHEET --format markdown --output reports/review.md
capagap triage apply HANDOFF WORKSHEET --output reports/reviewed-handoff.json
```

Each review contains a stable finding ID, disposition, analyst notes, evidence, reviewer, and review date. The text fields are free-form. Do not change the finding ID or `handoff_identity` field.

Accepted dispositions: `unreviewed`, `confirmed`, `likely`, `benign`, `false-positive`, `needs-data`, and `deferred`. CapaGap records these as analyst judgments; it does not verify them.

The worksheet identity is a hash of the sample SHA-256 and sorted finding IDs. A mismatch stops `report` or `apply`. This is an accidental-mixup check, not a signature or a complete record of run provenance.

`init` and `apply` require `--force` to replace an existing output. `report` accepts `text` or `markdown` and overwrites its output path if one is supplied. Applying a worksheet writes a new handoff; it does not modify the original unless explicitly given the same path with `--force`.

IDA and Binary Ninja imports replace comment lines with matching CapaGap markers. Ghidra updates the CapaGap bookmark at each location. Keep a database backup before importing annotations.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Command completed. |
| `2` | Invalid arguments, input, comparison, or output path. |
| `3` | A requested gap or diff check found changes after writing the report. |
| `4` | Validation warnings, or strict mode stopped on quality warnings. |

The `3` exit code is opt-in through `--fail-on-unobserved`, `--fail-on-never-observed`, or `diff --fail-on-change`. It is based on the complete comparison, not the displayed priority threshold. Ordinary reports may replace an existing output, but cannot replace their input documents.
