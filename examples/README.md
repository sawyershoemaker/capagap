# Example data

All inputs here are synthetic fixtures. The sample hash, paths, matches, and run settings are placeholders. No binary or live malware is included.

Each JSON fixture explicitly sets `meta.capagap.synthetic` to `true`. HTML reports display the synthetic label only when every input carries this marker; the label is not inferred from a filename or sample hash.

| File | Contents |
|---|---|
| `static.json` | Six static rule records, including one library rule. |
| `dynamic.json` | Baseline dynamic matches. |
| `dynamic-interactive.json` | A second run with different observed matches. |
| `evidence/` | The same rule-presence scenarios with synthetic feature trees, locations, layout context, and feature counts. |
| `demo-report.md` | Single-run comparison output. |
| `matrix-report.md` | Two-run comparison output. |
| `single-run-dashboard.html` | Offline single-run HTML report. |
| `matrix-dashboard.html` | Offline multi-run HTML report. |
| `re-handoff/` | Exported findings, worksheet, and import scripts. |
| `demo-rules/` | A separate YAML fixture for the manifest command. |

The JSON documents use a minimized capa 9.4-style result structure, but were not produced by running capa. Their `source` fields are synthetic identifiers, not complete capa rules. The rule in `demo-rules/` is therefore only a manifest-generation example and must not be used to verify these JSON fixtures.

The baseline observes two of four comparable static capabilities. The two-run union observes three. Library rules are excluded by default; the remaining static-only rule does not enter the coverage denominator.

The checked-in HTML, Markdown, and handoff examples use `evidence/`. The three top-level JSON files retain their minimal shape to demonstrate missing-detail diagnostics. To regenerate the richer fixtures and reports after an editable install, run `python scripts/generate_examples.py`. This replaces generated examples, including the unreviewed example triage worksheet; do not use that directory for real case notes.

To try manifest generation independently:

```sh
capagap manifest examples/demo-rules --output reports/demo-manifest.json
```

The HTML files need to be opened locally. GitHub displays their source rather than running the report UI.
