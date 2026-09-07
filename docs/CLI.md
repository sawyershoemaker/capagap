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
| `--fail-on-unobserved` | Return `3` if any comparable static capability is unobserved. |

JSON and HTML reports retain all findings. Priority filters do not change summary counts or exit-code checks.

## matrix

```sh
capagap matrix STATIC --run LABEL=PATH --run LABEL=PATH [options]
```

A matrix needs at least two dynamic results with unique, nonempty labels. It accepts the report options above, except that `--fail-on-never-observed` replaces `--fail-on-unobserved`.

The report separates capabilities seen in all runs, seen in only some runs (`environment-sensitive`), and absent from every run (`never-observed`). Coverage is also calculated for the union of all supplied runs.

Repeat `--condition LABEL:KEY=VALUE` to record run settings. The first run is the baseline. Each other run is checked for the number of changed keys; zero or multiple changes produce warnings. Unknown labels and duplicate keys within a run are errors. These are checks of declared metadata, not measurements of the sandbox configuration.

See [experiment setup](EXPERIMENTS.md) for a worked example.

## HTML reports

Both comparison commands accept `--format html --output REPORT.html`. Open the file in a modern browser; no web server or internet connection is needed.

The matrix starts with comparable capabilities. Use the Runtime-only and Excluded controls to inspect other findings without changing coverage. Expand a row to see its evidence, scopes, identifiers, and follow-up. Runtime-only evidence is labeled by run and retains its original address type. Static addresses show a portable RVA when one can be calculated; unmapped locations remain visible.

Search is case-insensitive and matches every space-separated term within a finding's name, namespace, state, identifiers, or evidence locations. The state filter combines with search. Switching views clears the state filter but preserves search. Run conditions, exact-RVA hotspots, input metadata, and analysis context sit below the matrix. Input warnings are expanded by default.

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
| `3` | A requested gap check failed after the report was written. |

The `3` exit code is opt-in through `--fail-on-unobserved` or `--fail-on-never-observed`. It is based on the complete comparison, not the displayed priority threshold.
