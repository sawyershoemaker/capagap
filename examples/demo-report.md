# CapaGap analysis report

- Sample SHA-256: `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`
- Comparison confidence: **high**
- Observed coverage: **50.0%** (2/4)
- Unobserved comparable capabilities: **2**
- Static-only capabilities excluded from coverage: 1
- Rules excluded from verified coverage: 0
- Dynamic-only capabilities: 1

> Evasion context: the dynamic run observed `check for sandbox process names`. This boosts related triage priority, but does not prove behavior gating.

## Prioritized unobserved capabilities

| Priority | Score | Capability | Namespace | ATT&CK | Static evidence |
|---|---:|---|---|---|---|
| high | 69 | inject shellcode into remote process | `load-code/inject/process` | T1055 | `0x404000`, `0x404100` |
| high | 61 | create scheduled task | `persistence/scheduled-task` | T1053.005 | `0x405000` |

## Suggested next moves

1. **inject shellcode into remote process:** Capture child-process memory and break on the supporting allocation/write/thread APIs near the static match.
2. **create scheduled task:** Repeat with the required privilege and longer runtime; inspect registry, service, task, and startup artifacts.

## Dynamic-only capabilities

These may represent runtime-resolved, unpacked, or extractor-specific behavior.

- execute shell command (`load-code/execute`)

## Evidence hotspots

Exact mapped RVAs shared by findings; these are not inferred functions or call-graph edges.

| RVA | Findings | Max priority | Capabilities |
|---|---:|---:|---|
| `0x4000` | 1 | 69 | inject shellcode into remote process |
| `0x4100` | 1 | 69 | inject shellcode into remote process |
| `0x5000` | 1 | 61 | create scheduled task |

## Interpretation boundary

An **unobserved** rule was statically matched, supports a dynamic scope, and was absent from this dynamic result. It is a triage lead—not proof that code never executed or that sandbox evasion occurred. Missing stimuli, incomplete tracing, packing, extractor differences, and rule-set drift are alternative explanations.
