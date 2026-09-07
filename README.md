# CapaGap

Compare static [capa](https://github.com/mandiant/capa) matches with dynamic runs of the same sample. CapaGap reports which capabilities were observed, which were missing, and which appeared in only some runs.

Rules without a supported dynamic scope are excluded from coverage. Results include ranked findings, static match locations, and optional Ghidra, IDA Pro, and Binary Ninja annotations. CapaGap reads result documents; it does not run samples or contact a sandbox.

## Install

Python 3.10 or newer. No runtime dependencies.

Install from PyPI:

```sh
python -m pip install capagap
capagap --help
```

Or install from a source checkout:

```sh
python -m pip install .
```

If your shell cannot find `capagap`, use `python -m capagap` instead.

## Try it

The examples below use files from the [source repository](https://github.com/sawyershoemaker/capagap). Download the source and run these commands from its root directory; `pip install` does not copy the examples into your working directory.

The inputs are synthetic. You do not need capa or a malware sample to run them.

```sh
capagap compare examples/static.json examples/dynamic.json
```

Excerpt from the result:

```text
Confidence:  high
Coverage:    50.0% (2/4 comparable static capabilities observed)
Unobserved:  2
Static-only: 1 (excluded from coverage)
```

For your own inputs, export the static and dynamic results with `capa -j`. Use the same sample and ruleset for both analyses. Plain JSON and gzip-compressed JSON are accepted.

### Compare runs

```sh
capagap matrix examples/static.json \
  --run baseline=examples/dynamic.json \
  --run interactive=examples/dynamic-interactive.json \
  --condition baseline:interaction=off \
  --condition interactive:interaction=on \
  --format html --output reports/matrix.html
```

The first run is the baseline. Conditions are supplied by the analyst, not inferred from the reports. CapaGap warns when a comparison changes zero or multiple declared conditions.

The example has 75% combined coverage: three of four comparable static capabilities appeared in at least one run. Open `reports/matrix.html` locally to compare runs, expand evidence, and copy addresses. Search covers rule names, namespaces, ATT&CK IDs, and locations. Runtime-only and excluded matches have separate views.

HTML reports are self-contained: no server, external assets, or network requests. They include JSON export and remain readable with JavaScript disabled. Text, Markdown, and JSON output are also available.

Multiline examples use POSIX shell continuations. In PowerShell, put the command on one line or replace each trailing `\` with a backtick.

### Check the ruleset

```sh
capagap manifest path/to/capa-rules --output reports/ruleset.json
capagap compare static.json dynamic.json --ruleset-manifest reports/ruleset.json
```

Build the manifest from the rule directory used for analysis. Comparable static rules with missing or different source definitions are reported as `ruleset-unverified` and removed from the coverage denominator. A dynamic match that disagrees with the manifest stops the comparison.

### Export annotations

```sh
capagap handoff examples/static.json \
  --run baseline=examples/dynamic.json \
  --output reports/handoff
```

The output directory contains the findings, an editable triage worksheet, import scripts, and tool-specific instructions. Static match locations are exported as RVAs and rebased against the open database.

After editing `reports/handoff/capagap-triage.json`, create a reviewed copy:

```sh
capagap triage apply reports/handoff/capagap-handoff.json \
  reports/handoff/capagap-triage.json \
  --output reports/handoff/reviewed.json
```

Re-importing updates the corresponding CapaGap annotations. See the [command reference](https://github.com/sawyershoemaker/capagap/blob/main/docs/CLI.md) for selection options, review fields, and exit codes.

## Limits

- A missing dynamic match is not proof that code did not execute. Trace loss, absent stimuli, packing, and extractor differences can all affect coverage.
- A ruleset manifest checks source consistency. It cannot prove that every listed rule was loaded during a historical run.
- Scores set an investigation order; they are not probabilities or severity ratings. Evidence hotspots group exact RVAs, not functions or call-graph edges.
- Absolute addresses require the static report's image base for handoff. Other address types remain in the bundle as unmappable evidence.

Analysis reports can contain sensitive paths and strings. There is no automatic redaction; review them before sharing.

## Development

```sh
python -m pip install -e ".[dev]"
python -m unittest discover -s tests -v
python scripts/release_check.py
```

The release check runs lint, formatting checks, tests, package builds, metadata validation, and a clean-environment install test. It does not publish anything. The output directory must be empty; use `--outdir path/to/empty-directory` to keep an existing build.

The version is defined in `src/capagap/__init__.py`. Release tags use `v` followed by that version.

More detail: [command reference](https://github.com/sawyershoemaker/capagap/blob/main/docs/CLI.md), [comparison model](https://github.com/sawyershoemaker/capagap/blob/main/docs/DESIGN.md), [experiment setup](https://github.com/sawyershoemaker/capagap/blob/main/docs/EXPERIMENTS.md), and [example data](https://github.com/sawyershoemaker/capagap/blob/main/examples/README.md).

## License

[MIT](https://github.com/sawyershoemaker/capagap/blob/main/LICENSE). Copyright 2026 Sawyer Shoemaker.
