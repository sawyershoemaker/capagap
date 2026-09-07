# CapaGap multi-environment report

- Sample SHA-256: `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`
- Comparison confidence: **high**
- Dynamic runs: **2**
- Union coverage: **75.0%** (3/4)
- Never observed: **1**
- Environment-sensitive: **2**
- Rules excluded from verified coverage: 0

## Coverage by run

| Run | Coverage | Observed | Runtime-only | Confidence |
|---|---:|---:|---:|---|
| baseline | 50.0% | 2/4 | 1 | high |
| interactive | 50.0% | 2/4 | 1 | high |

## Declared experiment conditions (baseline: baseline)

| Run | Conditions | Changed vs baseline |
|---|---|---|
| baseline | interaction=off | none |
| interactive | interaction=on | interaction |

## Capability matrix

| Capability | Priority | baseline | interactive | ATT&CK |
|---|---|---|---|---|
| inject shellcode into remote process | high | · | · | T1055 |
| create scheduled task | high | · | ✓ | T1053.005 |
| check for sandbox process names | high | ✓ | · | T1497.001 |
| communicate over HTTP | info | ✓ | ✓ | T1071.001 |

## Never observed

- **inject shellcode into remote process** (high, 69): Capture child-process memory and break on the supporting allocation/write/thread APIs near the static match.

## Environment-sensitive deltas

- **create scheduled task** — seen in interactive; missing from baseline.
- **check for sandbox process names** — seen in baseline; missing from interactive.

## Runtime-only capabilities

- capture screenshot — interactive
- execute shell command — baseline

## Evidence hotspots

Exact mapped RVAs shared by findings; no control-flow relationship is inferred.

- `0x4000` — 1 finding(s), max priority 69: inject shellcode into remote process
- `0x4100` — 1 finding(s), max priority 69: inject shellcode into remote process
- `0x5000` — 1 finding(s), max priority 67: create scheduled task
- `0x3000` — 1 finding(s), max priority 57: check for sandbox process names

## Interpretation boundary

A capability that changes across runs is environment-sensitive evidence, not proof that any one setting caused the behavior. Use controlled experiments that change one condition at a time.
