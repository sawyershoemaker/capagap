# Running controlled sandbox experiments

CapaGap can show that behavior changed between runs. A useful experiment design is what lets an analyst explain why.

## Start with a baseline

Run the sample using the sandbox's standard image and settings. Keep the duration, network policy, locale, privilege level, and user interaction policy in your notes.

```bash
capa -j baseline-cape-report.json > baseline.json
```

## Change one condition

Choose a hypothesis suggested by the static gaps. Examples:

| Hypothesis | Controlled change | Keep constant |
|---|---|---|
| Behavior waits for user activity | Add scripted mouse/keyboard activity | Image, network, duration, privilege |
| C2 requires a successful connection | Enable controlled DNS/Internet simulation | Image, duration, interaction, privilege |
| Persistence requires elevation | Run with an elevated token | Image, network, duration, interaction |
| Sample fingerprints the VM | Change one exposed VM artifact | All other VM artifacts and run settings |
| Delayed execution exceeds detonation time | Extend the run duration | Image, network, interaction, privilege |

Generate a capa dynamic result for each changed condition.

## Label runs by the changed variable

```bash
capagap matrix static.json \
  --run baseline=baseline.json \
  --run user-activity=user-activity.json \
  --run simulated-internet=simulated-internet.json \
  --condition baseline:interaction=off \
  --condition baseline:network=off \
  --condition user-activity:interaction=on \
  --condition user-activity:network=off \
  --condition simulated-internet:interaction=off \
  --condition simulated-internet:network=on \
  --format html \
  --output experiment-matrix.html
```

Prefer `user-activity` over labels such as `run2`. The label and declared `KEY=VALUE` conditions are carried into text, Markdown, JSON, HTML, and handoff output. The first run is the baseline. CapaGap warns when a non-baseline run differs in zero or more than one declared condition.

## Interpret the matrix

- **Observed in all:** stable behavior under the tested conditions.
- **Environment-sensitive:** observed in some runs and absent from others. This is evidence for a follow-up experiment, not proof of causality.
- **Never observed:** statically present and dynamically comparable, but absent from the union. Prioritize these for debugging, targeted stimuli, or memory-dump analysis.
- **Runtime-only:** absent from the static result and present in one or more traces. Packing, runtime resolution, and extractor differences are common explanations.

## Avoid false conclusions

Before interpreting coverage, run `capagap validate static.json baseline.json`. Check restrictions, feature counts, sample identity, and extractor metadata. Quality diagnostics remain separate from capability counts.

Capture the result documents with `capagap case init` to preserve hashes and condition declarations. Generate later reports with `capagap case report`; keep a new snapshot for each changed set of inputs. To compare saved JSON reports, use `capagap diff before.json after.json`. Keep labels consistent for the same experimental role so changes align correctly.

Use `capagap contributions` to see which runs add comparable capabilities and which overlap. The suggested representative subset preserves the measured union only. Preserve the original traces: apparently redundant runs may differ in arguments, timing, or behavior that the selected rules do not measure.

Do not attribute a delta to a setting when several settings changed together. Keep capa major versions, rule bundles, sample hashes, and analysis architecture consistent. CapaGap detects some of these mismatches, but it cannot reconstruct undocumented sandbox changes.
