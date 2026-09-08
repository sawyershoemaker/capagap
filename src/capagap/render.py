"""Human and machine renderers for comparison results."""

from __future__ import annotations

import json
import textwrap
from collections.abc import Iterable

from capagap.contributions import analyze_contributions, render_contributions
from capagap.diagnostics import comparison_diagnostics, render_validation
from capagap.models import Comparison, Finding, MatrixComparison, MatrixFinding

PRIORITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _supplement(
    comparison: Comparison | MatrixComparison, *, markdown: bool = False
) -> str:
    sections = []
    case = comparison.metadata.get("case")
    if isinstance(case, dict):
        clean = _md_escape if markdown else str
        sections.append(
            f"{'## ' if markdown else ''}Case: {clean(case['name'])}\nID: {case['id']}\n{clean(case['notes'])}\n"
        )
    if isinstance(comparison, MatrixComparison):
        sections.append(
            render_contributions(analyze_contributions(comparison), markdown=markdown)
        )
    issues = [item.to_dict() for item in comparison_diagnostics(comparison)]
    if issues:
        sections.append(render_validation({"diagnostics": issues}, markdown=markdown))
    return "\n" + "\n".join(sections) if sections else ""


def _visible(
    findings: Iterable[Finding | MatrixFinding], minimum: str
) -> list[Finding | MatrixFinding]:
    threshold = PRIORITY_ORDER[minimum]
    return [
        item
        for item in findings
        if PRIORITY_ORDER.get(item.priority_label, 0) >= threshold
    ]


def _coverage(comparison: Comparison) -> str:
    value = comparison.summary.observed_coverage
    return "n/a" if value is None else f"{value:.1%}"


def _empty_never_observed(comparison: MatrixComparison) -> str:
    if not comparison.findings:
        return "No comparable static capabilities."
    if comparison.never_observed:
        return "No never-observed capabilities meet this priority threshold."
    return "The union of runs observed every comparable static capability."


def _short_hash(value: str) -> str:
    return value if len(value) <= 20 else value[:16] + "..."


def _table(
    headers: tuple[str, ...], rows: list[tuple[str, ...]], widths: tuple[int, ...]
) -> list[str]:
    def border(char: str = "-") -> str:
        return "+" + "+".join(char * (width + 2) for width in widths) + "+"

    def line(values: tuple[str, ...]) -> str:
        return (
            "| "
            + " | ".join(value.ljust(width) for value, width in zip(values, widths))
            + " |"
        )

    output = [border(), line(headers), border("=")]
    for row in rows:
        cells = [
            textwrap.wrap(str(value), width=width) or [""]
            for value, width in zip(row, widths)
        ]
        height = max(len(cell) for cell in cells)
        for row_line in range(height):
            values = tuple(
                cell[row_line] if row_line < len(cell) else "" for cell in cells
            )
            output.append(line(values))
        output.append(border())
    return output


def render_text(
    comparison: Comparison, *, minimum_priority: str = "low", limit: int = 25
) -> str:
    findings = _visible(comparison.unobserved, minimum_priority)[:limit]
    lines = [
        "CapaGap - static potential vs. observed behavior",
        "",
        f"Sample:      {_short_hash(comparison.static.sample_sha256 or comparison.dynamic.sample_sha256 or 'unverified')}",
        f"Confidence:  {comparison.confidence}",
        f"Coverage:    {_coverage(comparison)} ({comparison.summary.observed_rules}/{comparison.summary.comparable_static_rules} comparable static capabilities observed)",
        f"Unobserved:  {comparison.summary.unobserved_rules}",
        f"Static-only: {comparison.summary.static_only_rules} (excluded from coverage)",
        f"Unverified:  {comparison.summary.ruleset_unverified_rules} (excluded from verified coverage)",
        f"Dynamic-only:{comparison.summary.dynamic_only_rules:>3}",
    ]

    if comparison.gate_signals:
        lines.extend(
            [
                "",
                "Evasion context: the run observed "
                + ", ".join(comparison.gate_signals)
                + ".",
                "Other unobserved capabilities receive a small triage boost; this is a lead, not proof of gating.",
            ]
        )

    lines.extend(["", f"Prioritized unobserved capabilities ({minimum_priority}+)"])
    if not findings:
        lines.append("  None at this threshold.")
    else:
        rows = []
        for item in findings:
            attack = ", ".join(item.rule.attack_ids) or "-"
            evidence = ", ".join(item.rule.evidence[:3]) or "-"
            rows.append(
                (
                    item.priority_label.upper(),
                    str(item.priority),
                    item.rule.name,
                    item.rule.namespace,
                    attack,
                    evidence,
                )
            )
        lines.extend(
            _table(
                (
                    "Priority",
                    "Score",
                    "Capability",
                    "Namespace",
                    "ATT&CK",
                    "Static evidence",
                ),
                rows,
                (8, 5, 28, 25, 11, 18),
            )
        )

        lines.extend(["", "Suggested next moves"])
        for index, item in enumerate(findings, 1):
            lines.append(f"  {index}. {item.rule.name}: {item.action}")

    if comparison.dynamic_only:
        lines.extend(
            ["", "Dynamic-only capabilities (possible runtime/unpacked behavior)"]
        )
        for item in comparison.dynamic_only[:limit]:
            lines.append(f"  - {item.rule.name} [{item.rule.namespace}]")

    if comparison.evidence_hotspots:
        lines.extend(
            ["", "Evidence hotspots (exact mapped RVAs; no call-graph inference)"]
        )
        for hotspot in comparison.evidence_hotspots[:limit]:
            lines.append(
                f"  - {hotspot.display}: {len(hotspot.rule_names)} finding(s), "
                f"max priority {hotspot.maximum_priority} — {', '.join(hotspot.rule_names)}"
            )

    if comparison.ruleset_unverified:
        lines.extend(["", "Rules excluded from verified coverage"])
        for item in comparison.ruleset_unverified[:limit]:
            lines.append(f"  - {item.rule.name}: {item.reasons[0]}")

    if comparison.warnings:
        lines.extend(["", "Comparison warnings"])
        lines.extend(f"  - {warning}" for warning in comparison.warnings)

    lines.extend(
        [
            "",
            "Interpretation: 'unobserved' means absent from this capa dynamic result. It does not prove",
            "the code never executed; missing stimuli, trace loss, packing, or rule drift can also explain a gap.",
        ]
    )
    return "\n".join(lines) + "\n" + _supplement(comparison)


def _md_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("|", "\\|")
        .replace("\n", " ")
    )


def render_markdown(
    comparison: Comparison, *, minimum_priority: str = "low", limit: int = 100
) -> str:
    findings = _visible(comparison.unobserved, minimum_priority)[:limit]
    sample = (
        comparison.static.sample_sha256
        or comparison.dynamic.sample_sha256
        or "unverified"
    )
    lines = [
        "# CapaGap analysis report",
        "",
        f"- Sample SHA-256: `{sample}`",
        f"- Comparison confidence: **{comparison.confidence}**",
        f"- Observed coverage: **{_coverage(comparison)}** ({comparison.summary.observed_rules}/{comparison.summary.comparable_static_rules})",
        f"- Unobserved comparable capabilities: **{comparison.summary.unobserved_rules}**",
        f"- Static-only capabilities excluded from coverage: {comparison.summary.static_only_rules}",
        f"- Rules excluded from verified coverage: {comparison.summary.ruleset_unverified_rules}",
        f"- Dynamic-only capabilities: {comparison.summary.dynamic_only_rules}",
    ]

    if comparison.gate_signals:
        signals = ", ".join(f"`{value}`" for value in comparison.gate_signals)
        lines.extend(
            [
                "",
                f"> Evasion context: the dynamic run observed {signals}. This boosts related triage priority, but does not prove behavior gating.",
            ]
        )

    lines.extend(
        [
            "",
            "## Prioritized unobserved capabilities",
            "",
            "| Priority | Score | Capability | Namespace | ATT&CK | Static evidence |",
            "|---|---:|---|---|---|---|",
        ]
    )
    if findings:
        for item in findings:
            lines.append(
                "| "
                + " | ".join(
                    (
                        item.priority_label,
                        str(item.priority),
                        _md_escape(item.rule.name),
                        f"`{_md_escape(item.rule.namespace)}`",
                        ", ".join(item.rule.attack_ids) or "-",
                        ", ".join(f"`{value}`" for value in item.rule.evidence[:5])
                        or "-",
                    )
                )
                + " |"
            )
    else:
        lines.append("| - | - | None at this threshold | - | - | - |")

    if findings:
        lines.extend(["", "## Suggested next moves", ""])
        for index, item in enumerate(findings, 1):
            lines.append(
                f"{index}. **{_md_escape(item.rule.name)}:** {_md_escape(item.action)}"
            )

    if comparison.dynamic_only:
        lines.extend(["", "## Dynamic-only capabilities", ""])
        lines.append(
            "These may represent runtime-resolved, unpacked, or extractor-specific behavior."
        )
        lines.append("")
        for item in comparison.dynamic_only[:limit]:
            lines.append(
                f"- {_md_escape(item.rule.name)} (`{_md_escape(item.rule.namespace)}`)"
            )

    if comparison.evidence_hotspots:
        lines.extend(
            [
                "",
                "## Evidence hotspots",
                "",
                "Exact mapped RVAs shared by findings; these are not inferred functions or call-graph edges.",
                "",
                "| RVA | Findings | Max priority | Capabilities |",
                "|---|---:|---:|---|",
            ]
        )
        for hotspot in comparison.evidence_hotspots[:limit]:
            names = ", ".join(map(_md_escape, hotspot.rule_names))
            lines.append(
                f"| `{hotspot.display}` | {len(hotspot.rule_names)} | {hotspot.maximum_priority} | {names} |"
            )

    if comparison.ruleset_unverified:
        lines.extend(["", "## Rules excluded from verified coverage", ""])
        for item in comparison.ruleset_unverified[:limit]:
            lines.append(
                f"- **{_md_escape(item.rule.name)}:** {_md_escape(item.reasons[0])}"
            )

    if comparison.warnings:
        lines.extend(["", "## Warnings", ""])
        lines.extend(f"- {_md_escape(warning)}" for warning in comparison.warnings)

    lines.extend(
        [
            "",
            "## Interpretation boundary",
            "",
            "An **unobserved** rule was statically matched, supports a dynamic scope, and was absent from this dynamic result. It is a triage lead—not proof that code never executed or that sandbox evasion occurred. Missing stimuli, incomplete tracing, packing, extractor differences, and rule-set drift are alternative explanations.",
            "",
        ]
    )
    return "\n".join(lines) + _supplement(comparison, markdown=True)


def render_json(comparison: Comparison) -> str:
    return json.dumps(comparison.to_dict(), indent=2, sort_keys=True) + "\n"


def _matrix_coverage(comparison: MatrixComparison) -> str:
    value = comparison.summary.union_coverage
    return "n/a" if value is None else f"{value:.1%}"


def render_matrix_text(
    comparison: MatrixComparison, *, minimum_priority: str = "low", limit: int = 25
) -> str:
    never = _visible(comparison.never_observed, minimum_priority)[:limit]
    lines = [
        "CapaGap Lab - multi-environment capability matrix",
        "",
        f"Sample:          {_short_hash(comparison.static.sample_sha256 or 'unverified')}",
        f"Confidence:      {comparison.confidence}",
        f"Dynamic runs:    {comparison.summary.run_count}",
        f"Union coverage:  {_matrix_coverage(comparison)} ({comparison.summary.union_observed_rules}/{comparison.summary.comparable_static_rules})",
        f"Never observed:  {comparison.summary.never_observed_rules}",
        f"Environment-sensitive: {comparison.summary.environment_sensitive_rules}",
        f"Ruleset-unverified: {comparison.summary.ruleset_unverified_rules}",
        "",
        "Coverage by run",
    ]

    run_rows = []
    for run in comparison.runs:
        coverage = run.comparison.summary.observed_coverage
        run_rows.append(
            (
                run.label,
                "n/a" if coverage is None else f"{coverage:.1%}",
                f"{run.comparison.summary.observed_rules}/{run.comparison.summary.comparable_static_rules}",
                str(run.comparison.summary.dynamic_only_rules),
                run.comparison.confidence,
            )
        )
    lines.extend(
        _table(
            ("Run", "Coverage", "Observed", "Runtime-only", "Confidence"),
            run_rows,
            (20, 10, 10, 12, 10),
        )
    )

    if any(run.conditions for run in comparison.runs):
        lines.extend(
            [
                "",
                f"Declared experiment conditions (baseline: {comparison.experiment_baseline})",
            ]
        )
        for run in comparison.runs:
            conditions = (
                ", ".join(f"{key}={value}" for key, value in run.conditions) or "<none>"
            )
            changed = ", ".join(run.changed_conditions) or "none"
            lines.append(
                f"  - {run.label}: {conditions}; changed vs baseline: {changed}"
            )

    lines.extend(["", f"Never observed in any run ({minimum_priority}+)"])
    if never:
        rows = [
            (
                item.priority_label.upper(),
                str(item.priority),
                item.rule.name,
                ", ".join(item.rule.attack_ids) or "-",
                ", ".join(item.rule.evidence[:3]) or "-",
            )
            for item in never
        ]
        lines.extend(
            _table(
                ("Priority", "Score", "Capability", "ATT&CK", "Static evidence"),
                rows,
                (8, 5, 34, 12, 20),
            )
        )
        lines.extend(["", "Suggested experiments"])
        for index, item in enumerate(never, 1):
            lines.append(f"  {index}. {item.rule.name}: {item.action}")
    else:
        lines.append("  " + _empty_never_observed(comparison))

    if comparison.environment_sensitive:
        lines.extend(["", "Environment-sensitive behavior deltas"])
        delta_rows = [
            (
                item.rule.name,
                ", ".join(item.observed_in),
                ", ".join(item.unobserved_in),
            )
            for item in comparison.environment_sensitive[:limit]
        ]
        lines.extend(
            _table(
                ("Capability", "Observed in", "Missing from"),
                delta_rows,
                (36, 24, 24),
            )
        )

    if comparison.dynamic_only:
        lines.extend(["", "Runtime-only capabilities"])
        for name, labels in sorted(comparison.dynamic_only.items())[:limit]:
            lines.append(f"  - {name}: {', '.join(labels)}")

    if comparison.evidence_hotspots:
        lines.extend(
            ["", "Evidence hotspots (exact mapped RVAs; no call-graph inference)"]
        )
        for hotspot in comparison.evidence_hotspots[:limit]:
            lines.append(
                f"  - {hotspot.display}: {len(hotspot.rule_names)} finding(s), "
                f"max priority {hotspot.maximum_priority} — {', '.join(hotspot.rule_names)}"
            )

    if comparison.experiment_warnings:
        lines.extend(["", "Experiment design warnings"])
        lines.extend(f"  - {warning}" for warning in comparison.experiment_warnings)

    if comparison.warnings:
        lines.extend(["", "Comparison warnings"])
        lines.extend(f"  - {warning}" for warning in comparison.warnings)

    lines.extend(
        [
            "",
            "Interpretation: a behavior delta is evidence that run conditions changed observation coverage;",
            "it does not by itself identify which condition caused the change.",
        ]
    )
    return "\n".join(lines) + "\n" + _supplement(comparison)


def render_matrix_markdown(
    comparison: MatrixComparison, *, minimum_priority: str = "low", limit: int = 100
) -> str:
    labels = [run.label for run in comparison.runs]
    never = _visible(comparison.never_observed, minimum_priority)[:limit]
    lines = [
        "# CapaGap multi-environment report",
        "",
        f"- Sample SHA-256: `{comparison.static.sample_sha256 or 'unverified'}`",
        f"- Comparison confidence: **{comparison.confidence}**",
        f"- Dynamic runs: **{comparison.summary.run_count}**",
        f"- Union coverage: **{_matrix_coverage(comparison)}** ({comparison.summary.union_observed_rules}/{comparison.summary.comparable_static_rules})",
        f"- Never observed: **{comparison.summary.never_observed_rules}**",
        f"- Environment-sensitive: **{comparison.summary.environment_sensitive_rules}**",
        f"- Rules excluded from verified coverage: {comparison.summary.ruleset_unverified_rules}",
        "",
        "## Coverage by run",
        "",
        "| Run | Coverage | Observed | Runtime-only | Confidence |",
        "|---|---:|---:|---:|---|",
    ]
    for run in comparison.runs:
        coverage = run.comparison.summary.observed_coverage
        lines.append(
            f"| {_md_escape(run.label)} | {'n/a' if coverage is None else f'{coverage:.1%}'} | "
            f"{run.comparison.summary.observed_rules}/{run.comparison.summary.comparable_static_rules} | "
            f"{run.comparison.summary.dynamic_only_rules} | {run.comparison.confidence} |"
        )

    if any(run.conditions for run in comparison.runs):
        lines.extend(
            [
                "",
                f"## Declared experiment conditions (baseline: {_md_escape(comparison.experiment_baseline)})",
                "",
                "| Run | Conditions | Changed vs baseline |",
                "|---|---|---|",
            ]
        )
        for run in comparison.runs:
            conditions = (
                ", ".join(
                    f"{_md_escape(key)}={_md_escape(value)}"
                    for key, value in run.conditions
                )
                or "-"
            )
            changed = ", ".join(map(_md_escape, run.changed_conditions)) or "none"
            lines.append(f"| {_md_escape(run.label)} | {conditions} | {changed} |")

    lines.extend(
        [
            "",
            "## Capability matrix",
            "",
            "| Capability | Priority | "
            + " | ".join(_md_escape(label) for label in labels)
            + " | ATT&CK |",
            "|---|---|" + "---|" * len(labels) + "---|",
        ]
    )
    for item in comparison.findings[:limit]:
        cells = ["✓" if label in item.observed_in else "·" for label in labels]
        priority = item.priority_label if item.priority else "info"
        lines.append(
            f"| {_md_escape(item.rule.name)} | {priority} | "
            + " | ".join(cells)
            + f" | {', '.join(item.rule.attack_ids) or '-'} |"
        )

    lines.extend(["", "## Never observed", ""])
    if never:
        for item in never:
            lines.append(
                f"- **{_md_escape(item.rule.name)}** ({item.priority_label}, {item.priority}): {_md_escape(item.action)}"
            )
    else:
        lines.append(_empty_never_observed(comparison))

    if comparison.environment_sensitive:
        lines.extend(["", "## Environment-sensitive deltas", ""])
        for item in comparison.environment_sensitive[:limit]:
            lines.append(
                f"- **{_md_escape(item.rule.name)}** — seen in {', '.join(map(_md_escape, item.observed_in))}; "
                f"missing from {', '.join(map(_md_escape, item.unobserved_in))}."
            )

    if comparison.dynamic_only:
        lines.extend(["", "## Runtime-only capabilities", ""])
        for name, run_labels in sorted(comparison.dynamic_only.items())[:limit]:
            lines.append(
                f"- {_md_escape(name)} — {', '.join(map(_md_escape, run_labels))}"
            )

    if comparison.evidence_hotspots:
        lines.extend(
            [
                "",
                "## Evidence hotspots",
                "",
                "Exact mapped RVAs shared by findings; no control-flow relationship is inferred.",
                "",
            ]
        )
        for hotspot in comparison.evidence_hotspots[:limit]:
            lines.append(
                f"- `{hotspot.display}` — {len(hotspot.rule_names)} finding(s), "
                f"max priority {hotspot.maximum_priority}: {', '.join(map(_md_escape, hotspot.rule_names))}"
            )

    if comparison.experiment_warnings:
        lines.extend(["", "## Experiment design warnings", ""])
        lines.extend(
            f"- {_md_escape(warning)}" for warning in comparison.experiment_warnings
        )

    if comparison.warnings:
        lines.extend(["", "## Warnings", ""])
        lines.extend(f"- {_md_escape(warning)}" for warning in comparison.warnings)

    lines.extend(
        [
            "",
            "## Interpretation boundary",
            "",
            "A capability that changes across runs is environment-sensitive evidence, not proof that any one setting caused the behavior. Use controlled experiments that change one condition at a time.",
            "",
        ]
    )
    return "\n".join(lines) + _supplement(comparison, markdown=True)


def render_matrix_json(comparison: MatrixComparison) -> str:
    return json.dumps(comparison.to_dict(), indent=2, sort_keys=True) + "\n"
