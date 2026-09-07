"""Multi-environment capability coverage analysis."""

from __future__ import annotations

from collections.abc import Iterable

from capagap.analysis import ComparisonError, compare_documents
from capagap.hotspots import build_evidence_hotspots
from capagap.manifest import RuleManifest
from capagap.models import (
    CapaDocument,
    Finding,
    MatrixComparison,
    MatrixFinding,
    MatrixRun,
    MatrixSummary,
    RuleRecord,
)
from capagap.scoring import priority_label, score_rule, suggested_action

CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}
STATUS_ORDER = {"never-observed": 0, "environment-sensitive": 1, "observed-in-all": 2}


def _filtered_rules(
    document: CapaDocument, include_library: bool
) -> dict[str, RuleRecord]:
    return {
        name: rule
        for name, rule in document.rules.items()
        if include_library or not rule.library
    }


def _finding(
    rule: RuleRecord,
    labels: tuple[str, ...],
    observed_in: tuple[str, ...],
    *,
    evasion_context: bool,
) -> MatrixFinding:
    unobserved_in = tuple(label for label in labels if label not in observed_in)
    if not observed_in:
        status = "never-observed"
        score, score_reasons = score_rule(rule, evasion_context=evasion_context)
        reasons = (
            f"not observed in any of {len(labels)} dynamic runs",
        ) + score_reasons[1:]
    elif unobserved_in:
        status = "environment-sensitive"
        score, score_reasons = score_rule(rule, evasion_context=evasion_context)
        score = min(100, score + 6)
        reasons = (
            f"observed in {len(observed_in)}/{len(labels)} runs; environment or stimuli changed coverage",
        ) + score_reasons[1:]
    else:
        status = "observed-in-all"
        score = 0
        reasons = (f"observed in all {len(labels)} dynamic runs",)

    return MatrixFinding(
        status=status,
        rule=rule,
        observed_in=observed_in,
        unobserved_in=unobserved_in,
        priority=score,
        priority_label=priority_label(score) if score else "informational",
        reasons=reasons,
        action=suggested_action(rule) if unobserved_in else "",
    )


def compare_matrix(
    static: CapaDocument,
    dynamic_runs: Iterable[tuple[str, CapaDocument]],
    *,
    allow_mismatch: bool = False,
    include_library: bool = False,
    ruleset_manifest: RuleManifest | None = None,
    experiment_conditions: Iterable[tuple[str, str, str]] = (),
) -> MatrixComparison:
    """Compare one static result with two or more labeled dynamic results."""

    raw_runs = tuple(dynamic_runs)
    if len(raw_runs) < 2:
        raise ComparisonError("matrix analysis requires at least two dynamic runs")

    labels = tuple(label.strip() for label, _ in raw_runs)
    if any(not label for label in labels):
        raise ComparisonError("matrix run labels cannot be empty")
    if len(set(labels)) != len(labels):
        raise ComparisonError("matrix run labels must be unique")

    condition_maps: dict[str, dict[str, str]] = {label: {} for label in labels}
    for label, key, value in experiment_conditions:
        if label not in condition_maps:
            raise ComparisonError(f"condition references unknown run label: {label!r}")
        if not key:
            raise ComparisonError("condition keys cannot be empty")
        if key in condition_maps[label]:
            raise ComparisonError(f"duplicate condition key {key!r} for run {label!r}")
        condition_maps[label][key] = value

    baseline_label = labels[0]
    baseline_conditions = condition_maps[baseline_label]
    experiment_warnings: list[str] = []
    if not baseline_conditions:
        experiment_warnings.append(
            f"baseline run {baseline_label!r} has no declared conditions"
        )

    runs: list[MatrixRun] = []
    for (raw_label, dynamic), label in zip(raw_runs, labels, strict=True):
        del raw_label
        comparison = compare_documents(
            static,
            dynamic,
            allow_mismatch=allow_mismatch,
            include_library=include_library,
            ruleset_manifest=ruleset_manifest,
        )
        conditions = condition_maps[label]
        changed = tuple(
            sorted(
                key
                for key in baseline_conditions.keys() | conditions.keys()
                if baseline_conditions.get(key) != conditions.get(key)
            )
        )
        if label != baseline_label:
            if not conditions:
                experiment_warnings.append(f"run {label!r} has no declared conditions")
            if len(changed) != 1:
                experiment_warnings.append(
                    f"run {label!r} differs from baseline in {len(changed)} declared conditions; causal attribution is not controlled"
                )
        runs.append(
            MatrixRun(
                label=label,
                comparison=comparison,
                conditions=tuple(sorted(conditions.items())),
                changed_conditions=changed,
            )
        )

    static_rules = _filtered_rules(static, include_library)
    comparable = {
        finding.rule.name: finding.rule
        for finding in runs[0].comparison.observed + runs[0].comparison.unobserved
    }
    static_only_rules = {
        finding.rule.name: finding.rule for finding in runs[0].comparison.static_only
    }
    ruleset_unverified = runs[0].comparison.ruleset_unverified
    dynamic_rule_sets = {
        run.label: set(_filtered_rules(run.comparison.dynamic, include_library))
        for run in runs
    }

    gate_signals = {
        run.label: run.comparison.gate_signals
        for run in runs
        if run.comparison.gate_signals
    }
    evasion_context = bool(gate_signals)
    findings = []
    for name, rule in comparable.items():
        observed_in = tuple(
            label for label in labels if name in dynamic_rule_sets[label]
        )
        findings.append(
            _finding(
                rule,
                labels,
                observed_in,
                evasion_context=evasion_context,
            )
        )

    findings.sort(
        key=lambda item: (
            STATUS_ORDER[item.status],
            -item.priority,
            item.rule.name.lower(),
        )
    )
    never_observed = tuple(item for item in findings if item.status == "never-observed")
    environment_sensitive = tuple(
        item for item in findings if item.status == "environment-sensitive"
    )
    observed_in_all = tuple(
        item for item in findings if item.status == "observed-in-all"
    )

    static_only = tuple(
        Finding(
            status="static-only",
            rule=rule,
            priority=0,
            priority_label="informational",
        )
        for _, rule in sorted(static_only_rules.items())
    )

    dynamic_only: dict[str, tuple[str, ...]] = {}
    dynamic_only_names = set().union(
        *(rules - static_rules.keys() for rules in dynamic_rule_sets.values())
    )
    for name in dynamic_only_names:
        dynamic_only[name] = tuple(
            label for label in labels if name in dynamic_rule_sets[label]
        )

    warnings = tuple(
        dict.fromkeys(
            f"{run.label}: {warning}"
            for run in runs
            for warning in run.comparison.warnings
        )
    )
    confidence = min(
        (run.comparison.confidence for run in runs),
        key=lambda value: CONFIDENCE_ORDER[value],
    )
    summary = MatrixSummary(
        run_count=len(runs),
        static_rules=len(static_rules),
        comparable_static_rules=len(comparable),
        union_observed_rules=len(comparable) - len(never_observed),
        never_observed_rules=len(never_observed),
        environment_sensitive_rules=len(environment_sensitive),
        observed_in_all_rules=len(observed_in_all),
        static_only_rules=len(static_only),
        dynamic_only_rules=len(dynamic_only),
        ruleset_unverified_rules=len(ruleset_unverified),
    )
    return MatrixComparison(
        static=static,
        runs=tuple(runs),
        confidence=confidence,
        summary=summary,
        findings=tuple(findings),
        never_observed=never_observed,
        environment_sensitive=environment_sensitive,
        observed_in_all=observed_in_all,
        static_only=static_only,
        dynamic_only=dynamic_only,
        gate_signals=gate_signals,
        ruleset_unverified=ruleset_unverified,
        evidence_hotspots=build_evidence_hotspots(
            never_observed + environment_sensitive, static.base_address
        ),
        experiment_baseline=baseline_label,
        experiment_warnings=tuple(experiment_warnings),
        warnings=warnings,
    )
