"""Descriptive observation counts for repeated, explicitly declared conditions."""

from __future__ import annotations

import re
from collections import Counter
from typing import TYPE_CHECKING, Any

from capagap.diagnostics import comparison_diagnostics

if TYPE_CHECKING:
    from capagap.models import MatrixComparison

MAX_DETAIL_ROWS = 2048
CONTEXT_FIELDS = ("capa_version", "extractor", "format", "arch", "os")


def analyze_repeatability(comparison: MatrixComparison) -> dict[str, Any]:
    """Group comparable input contexts; counts do not establish independent trials."""
    required_keys = {key for run in comparison.runs for key, _ in run.conditions}
    groups: dict[tuple, list] = {}
    seen: dict[str, str] = {}
    declarations: dict[str, set[tuple]] = {}
    for run in comparison.runs:
        digest = run.comparison.dynamic.provenance.get("content_sha256")
        if digest:
            declarations.setdefault(digest, set()).add(run.conditions)
    conflicting = {
        digest for digest, conditions in declarations.items() if len(conditions) > 1
    }
    duplicates, unassessed, warnings = [], [], []
    for run in comparison.runs:
        document = run.comparison.dynamic
        digest = document.provenance.get("content_sha256")
        duplicate = digest in seen
        if duplicate:
            duplicates.append({"label": run.label, "duplicate_of": seen[digest]})
        elif digest:
            seen[digest] = run.label
        if digest in conflicting:
            unassessed.append(
                {
                    "label": run.label,
                    "reason": "Copies of this input have conflicting condition declarations.",
                }
            )
            continue
        if duplicate:
            continue
        reason = None
        if not run.conditions:
            reason = "No conditions declared."
        elif {key for key, _ in run.conditions} != required_keys:
            reason = "Condition declarations omit keys supplied for other runs."
        elif (
            not re.fullmatch(r"[0-9a-f]{64}", document.sample_sha256)
            or document.sample_sha256 != comparison.static.sample_sha256
        ):
            reason = "Sample identity is missing or differs from the static result."
        elif not digest:
            reason = "Input-content identity is unavailable."
        elif any(
            getattr(document, field) in ("", "unknown") for field in CONTEXT_FIELDS
        ):
            reason = "Extraction context is incomplete."
        elif any(item.code == "restricted-analysis" for item in document.diagnostics):
            reason = "Restricted analysis is not pooled with repeated full results."
        if reason:
            unassessed.append({"label": run.label, "reason": reason})
            continue
        context = tuple(getattr(document, field) for field in CONTEXT_FIELDS)
        groups.setdefault((run.conditions, context), []).append(run)
    if duplicates:
        warnings.append(
            "Byte-identical input documents are counted at most once, even under different labels."
        )
    if conflicting:
        warnings.append(
            "Copies with conflicting condition declarations are left unassessed."
        )
    if unassessed:
        warnings.append("Some runs cannot be assigned to a comparable condition group.")
    rows = []
    remaining = MAX_DETAIL_ROWS
    for index, ((conditions, context), runs) in enumerate(groups.items(), 1):
        capabilities = []
        counts: Counter = Counter()
        if len(runs) > 1:
            for finding in comparison.findings:
                observed = [
                    run.label for run in runs if run.label in finding.observed_in
                ]
                verified = finding.rule.source_available and all(
                    rule.source_available
                    and rule.source_digest == finding.rule.source_digest
                    for run in runs
                    if (rule := run.comparison.dynamic.rules.get(finding.rule.name))
                    is not None
                )
                state = (
                    "source-unverified"
                    if not verified
                    else "never-observed"
                    if not observed
                    else "observed-in-all"
                    if len(observed) == len(runs)
                    else "intermittent"
                )
                counts[state] += 1
                capabilities.append(
                    {
                        "name": finding.rule.name,
                        "state": state,
                        "observed_count": len(observed),
                        "run_count": len(runs),
                        "observed_in": observed,
                    }
                )
        order = {
            "intermittent": 0,
            "source-unverified": 1,
            "never-observed": 2,
            "observed-in-all": 3,
        }
        capabilities.sort(key=lambda row: (order[row["state"]], row["name"]))
        retained = capabilities[:remaining]
        remaining -= len(retained)
        rows.append(
            {
                "id": f"group-{index}",
                "conditions": dict(conditions),
                "context": dict(zip(CONTEXT_FIELDS, context)),
                "run_labels": [run.label for run in runs],
                "run_count": len(runs),
                "assessed": len(runs) > 1,
                "counts": {state: counts[state] for state in order},
                "capabilities": retained,
                "omitted_capabilities": len(capabilities) - len(retained),
            }
        )
    if not any(group["assessed"] for group in rows):
        warnings.append(
            "No condition group contains at least two distinct input documents."
        )
    if any(group["counts"]["source-unverified"] for group in rows):
        warnings.append(
            "Capabilities with missing or conflicting rule sources are not classified for repeatability."
        )
    return {
        "schema": "capagap-repeatability",
        "schema_version": 1,
        "scope": "comparable-static-capabilities",
        "groups": rows,
        "duplicates": duplicates,
        "unassessed_runs": unassessed,
        "warnings": warnings,
        "diagnostics": [
            item.to_dict()
            for item in comparison_diagnostics(comparison)
            if item.code != "experiment-context"
        ],
        "interpretation": "Counts describe supplied observations, not probabilities, independent trials, or causes. Groups require identical declared conditions and extraction metadata; undeclared settings and historical rule availability remain unverified.",
    }


def render_repeatability(result: dict[str, Any], *, markdown: bool = False) -> str:
    def clean(value):
        value = " ".join(str(value).split())
        return (
            value.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("|", "\\|")
            if markdown
            else value
        )

    lines = [("## " if markdown else "") + "Run repeatability", ""]
    for group in result["groups"]:
        settings = ", ".join(
            f"{clean(k)}={clean(v)}" for k, v in group["conditions"].items()
        )
        lines.append(
            f"{group['id']}: {settings} ({group['run_count']} distinct documents)"
        )
        lines.append("Runs: " + ", ".join(map(clean, group["run_labels"])))
        if not group["assessed"]:
            lines.append(
                "  Not assessed: at least two distinct documents are required."
            )
        for capability in group["capabilities"]:
            lines.append(
                f"  {clean(capability['name'])}: {capability['observed_count']}/{capability['run_count']} observed ({capability['state']})"
            )
        if group["omitted_capabilities"]:
            lines.append(
                f"  {group['omitted_capabilities']} detail rows omitted; summary counts remain complete."
            )
    lines.extend(
        f"Not assessed: {clean(r['label'])}: {r['reason']}"
        for r in result["unassessed_runs"]
    )
    lines.extend(
        f"Duplicate: {clean(r['label'])} = {clean(r['duplicate_of'])}"
        for r in result["duplicates"]
    )
    lines.extend(result["warnings"])
    lines.extend(
        f"Input quality: {clean(d['input'])}: {clean(d['message'])}"
        for d in result["diagnostics"]
        if d["severity"] in ("warning", "error")
    )
    lines.extend(["", result["interpretation"]])
    return "\n".join(lines) + "\n"
