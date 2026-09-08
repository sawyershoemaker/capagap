"""Explain the measured value of each run without inferring execution coverage."""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING, Any

from capagap.diagnostics import comparison_diagnostics

if TYPE_CHECKING:
    from capagap.models import MatrixComparison


def analyze_contributions(comparison: MatrixComparison) -> dict[str, Any]:
    labels = [run.label for run in comparison.runs]
    sets = {
        label: {
            finding.rule.name
            for finding in comparison.findings
            if label in finding.observed_in
        }
        for label in labels
    }
    union = set().union(*sets.values())
    frequency = Counter(name for names in sets.values() for name in names)
    baseline = sets[labels[0]]
    seen: set[str] = set()
    rows = []
    for label in labels:
        names = sets[label]
        unique = sorted(name for name in names if frequency[name] == 1)
        rows.append(
            {
                "label": label,
                "observed_count": len(names),
                "unique_capabilities": unique,
                "unique_count": len(unique),
                "added_vs_baseline": sorted(names - baseline),
                "missing_vs_baseline": sorted(baseline - names),
                "incremental_capabilities": sorted(names - seen),
                "individually_redundant": not unique,
            }
        )
        seen.update(names)
    remaining = set(union)
    selected = []
    candidates = list(labels)
    while remaining:
        # Input order breaks ties, keeping the baseline first when equally useful.
        best = max(candidates, key=lambda label: len(sets[label] & remaining))
        gain = sets[best] & remaining
        selected.append({"label": best, "added_capabilities": sorted(gain)})
        remaining.difference_update(gain)
        candidates.remove(best)
    overlaps = []
    for index, left in enumerate(labels):
        for right in labels[index + 1 :]:
            combined = sets[left] | sets[right]
            common = sets[left] & sets[right]
            overlaps.append(
                {
                    "left": left,
                    "right": right,
                    "shared_count": len(common),
                    "union_count": len(combined),
                    "jaccard": len(common) / len(combined) if combined else None,
                }
            )
    warnings = []
    if comparison.confidence != "high" or any(
        run.comparison.source_drift for run in comparison.runs
    ):
        warnings.append(
            "Input or ruleset differences limit interpretation of run contributions."
        )
    return {
        "schema": "capagap-run-contributions",
        "schema_version": 1,
        "baseline": labels[0],
        "scope": "comparable-static-capabilities",
        "union_count": len(union),
        "runs": rows,
        "pairwise_overlap": overlaps,
        "representative_set": {
            "method": "greedy-set-cover",
            "minimum_guaranteed": False,
            "labels": [item["label"] for item in selected],
            "steps": selected,
            "preserves_union": True,
        },
        "warnings": warnings,
        "diagnostics": [item.to_dict() for item in comparison_diagnostics(comparison)],
        "interpretation": "This covers matched comparable capabilities, not execution paths or all behavior. Individually redundant runs cannot necessarily all be removed together. The greedy representative set is not guaranteed to be the smallest.",
    }


def render_contributions(result: dict[str, Any], *, markdown: bool = False) -> str:
    def clean(value: str) -> str:
        value = " ".join(value.split())
        return (
            value.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("|", "\\|")
            if markdown
            else value
        )

    prefix = "## " if markdown else ""
    lines = [prefix + "Run contributions", "", "Baseline: " + clean(result["baseline"])]
    for run in result["runs"]:
        lines.append(
            f"- {clean(run['label'])}: {run['observed_count']} observed; {run['unique_count']} unique; {len(run['added_vs_baseline'])} added vs baseline"
        )
        if run["unique_capabilities"]:
            lines.append(
                "  Unique: " + ", ".join(map(clean, run["unique_capabilities"]))
            )
    selected = result["representative_set"]["labels"]
    lines.extend(
        [
            "",
            "Representative set (greedy): "
            + (", ".join(map(clean, selected)) or "none; empty union"),
            result["interpretation"],
        ]
    )
    lines.extend(result["warnings"])
    warning_count = sum(
        item["severity"] in {"warning", "error"}
        for item in result.get("diagnostics", [])
    )
    if warning_count:
        lines.append(
            f"Input quality: {warning_count} warning(s). Inspect JSON diagnostics or run capagap validate before interpreting coverage."
        )
    return "\n".join(lines) + "\n"
