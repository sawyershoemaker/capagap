"""Small, dependency-free domain models used by CapaGap."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class AddressRecord:
    """A normalized capa match address with enough structure for RE-tool handoff."""

    kind: str
    value: int | tuple[int, ...] | None
    display: str

    def rva(self, image_base: int | None) -> int | None:
        """Return a portable RVA when this address can be mapped into a binary."""

        if not isinstance(self.value, int) or self.value < 0:
            return None
        if self.kind == "relative":
            return self.value
        if self.kind == "absolute" and image_base is not None:
            offset = self.value - image_base
            return offset if offset >= 0 else None
        return None

    def to_dict(self, image_base: int | None = None) -> dict[str, Any]:
        value: int | list[int] | None = self.value
        if isinstance(value, tuple):
            value = list(value)
        return {
            "kind": self.kind,
            "value": value,
            "display": self.display,
            "rva": self.rva(image_base),
        }


@dataclass(frozen=True)
class RuleRecord:
    """The subset of a capa rule result needed for comparison and triage."""

    name: str
    namespace: str
    static_scope: str | None
    dynamic_scope: str | None
    attack: tuple[dict[str, Any], ...]
    mbc: tuple[dict[str, Any], ...]
    description: str
    library: bool
    source_digest: str
    evidence: tuple[str, ...]
    evidence_addresses: tuple[AddressRecord, ...] = ()

    @property
    def dynamically_comparable(self) -> bool:
        return bool(self.dynamic_scope and self.dynamic_scope != "unsupported")

    @property
    def attack_ids(self) -> tuple[str, ...]:
        return tuple(str(item.get("id", "")) for item in self.attack if item.get("id"))

    @property
    def mbc_ids(self) -> tuple[str, ...]:
        return tuple(str(item.get("id", "")) for item in self.mbc if item.get("id"))


@dataclass(frozen=True)
class CapaDocument:
    path: Path
    flavor: str
    capa_version: str
    sample_sha256: str
    sample_path: str
    format: str
    arch: str
    os: str
    extractor: str
    rules: dict[str, RuleRecord]
    base_address: int | None = None
    synthetic: bool = False


@dataclass(frozen=True)
class Finding:
    status: str
    rule: RuleRecord
    priority: int
    priority_label: str
    reasons: tuple[str, ...] = ()
    action: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "name": self.rule.name,
            "namespace": self.rule.namespace,
            "priority": self.priority,
            "priority_label": self.priority_label,
            "static_scope": self.rule.static_scope,
            "dynamic_scope": self.rule.dynamic_scope,
            "attack": list(self.rule.attack_ids),
            "mbc": list(self.rule.mbc_ids),
            "static_evidence": list(self.rule.evidence),
            "reasons": list(self.reasons),
            "suggested_action": self.action,
        }


@dataclass(frozen=True)
class ComparisonSummary:
    static_rules: int
    dynamic_rules: int
    comparable_static_rules: int
    observed_rules: int
    unobserved_rules: int
    static_only_rules: int
    dynamic_only_rules: int
    ruleset_unverified_rules: int = 0

    @property
    def observed_coverage(self) -> float | None:
        if self.comparable_static_rules == 0:
            return None
        return self.observed_rules / self.comparable_static_rules

    def to_dict(self) -> dict[str, Any]:
        result = {
            "static_rules": self.static_rules,
            "dynamic_rules": self.dynamic_rules,
            "comparable_static_rules": self.comparable_static_rules,
            "observed_rules": self.observed_rules,
            "unobserved_rules": self.unobserved_rules,
            "static_only_rules": self.static_only_rules,
            "dynamic_only_rules": self.dynamic_only_rules,
            "ruleset_unverified_rules": self.ruleset_unverified_rules,
        }
        result["observed_coverage"] = self.observed_coverage
        return result


@dataclass(frozen=True)
class Comparison:
    static: CapaDocument
    dynamic: CapaDocument
    confidence: str
    summary: ComparisonSummary
    unobserved: tuple[Finding, ...]
    observed: tuple[Finding, ...]
    static_only: tuple[Finding, ...]
    dynamic_only: tuple[Finding, ...]
    ruleset_unverified: tuple[Finding, ...] = ()
    evidence_hotspots: tuple[EvidenceHotspot, ...] = ()
    gate_signals: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    source_drift: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "comparison": {
                "confidence": self.confidence,
                "sample_sha256": self.static.sample_sha256
                or self.dynamic.sample_sha256,
                "static_input": str(self.static.path),
                "dynamic_input": str(self.dynamic.path),
                "static_capa_version": self.static.capa_version,
                "dynamic_capa_version": self.dynamic.capa_version,
                "gate_signals": list(self.gate_signals),
                "warnings": list(self.warnings),
                "source_drift": list(self.source_drift),
            },
            "summary": self.summary.to_dict(),
            "unobserved": [item.to_dict() for item in self.unobserved],
            "observed": [item.to_dict() for item in self.observed],
            "static_only": [item.to_dict() for item in self.static_only],
            "dynamic_only": [item.to_dict() for item in self.dynamic_only],
            "ruleset_unverified": [item.to_dict() for item in self.ruleset_unverified],
            "evidence_hotspots": [item.to_dict() for item in self.evidence_hotspots],
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class MatrixRun:
    """A labeled dynamic run and its individual static comparison."""

    label: str
    comparison: Comparison
    conditions: tuple[tuple[str, str], ...] = ()
    changed_conditions: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "input": str(self.comparison.dynamic.path),
            "extractor": self.comparison.dynamic.extractor,
            "capa_version": self.comparison.dynamic.capa_version,
            "confidence": self.comparison.confidence,
            "observed_rules": self.comparison.summary.observed_rules,
            "comparable_static_rules": self.comparison.summary.comparable_static_rules,
            "observed_coverage": self.comparison.summary.observed_coverage,
            "dynamic_only_rules": self.comparison.summary.dynamic_only_rules,
            "gate_signals": list(self.comparison.gate_signals),
            "warnings": list(self.comparison.warnings),
            "conditions": dict(self.conditions),
            "changed_conditions": list(self.changed_conditions),
        }


@dataclass(frozen=True)
class EvidenceHotspot:
    """An exact RVA shared by prioritized findings; not inferred control flow."""

    rva: int
    rule_names: tuple[str, ...]
    statuses: tuple[str, ...]
    aggregate_priority: int
    maximum_priority: int

    @property
    def display(self) -> str:
        return f"0x{self.rva:X}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "rva": self.rva,
            "display": self.display,
            "finding_count": len(self.rule_names),
            "rule_names": list(self.rule_names),
            "statuses": list(self.statuses),
            "aggregate_priority": self.aggregate_priority,
            "maximum_priority": self.maximum_priority,
        }


@dataclass(frozen=True)
class MatrixFinding:
    """The observation state of one statically present capability across runs."""

    status: str
    rule: RuleRecord
    observed_in: tuple[str, ...]
    unobserved_in: tuple[str, ...]
    priority: int
    priority_label: str
    reasons: tuple[str, ...] = ()
    action: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "name": self.rule.name,
            "namespace": self.rule.namespace,
            "priority": self.priority,
            "priority_label": self.priority_label,
            "observed_in": list(self.observed_in),
            "unobserved_in": list(self.unobserved_in),
            "static_scope": self.rule.static_scope,
            "dynamic_scope": self.rule.dynamic_scope,
            "attack": list(self.rule.attack_ids),
            "mbc": list(self.rule.mbc_ids),
            "static_evidence": list(self.rule.evidence),
            "reasons": list(self.reasons),
            "suggested_action": self.action,
        }


@dataclass(frozen=True)
class MatrixSummary:
    run_count: int
    static_rules: int
    comparable_static_rules: int
    union_observed_rules: int
    never_observed_rules: int
    environment_sensitive_rules: int
    observed_in_all_rules: int
    static_only_rules: int
    dynamic_only_rules: int
    ruleset_unverified_rules: int = 0

    @property
    def union_coverage(self) -> float | None:
        if self.comparable_static_rules == 0:
            return None
        return self.union_observed_rules / self.comparable_static_rules

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_count": self.run_count,
            "static_rules": self.static_rules,
            "comparable_static_rules": self.comparable_static_rules,
            "union_observed_rules": self.union_observed_rules,
            "never_observed_rules": self.never_observed_rules,
            "environment_sensitive_rules": self.environment_sensitive_rules,
            "observed_in_all_rules": self.observed_in_all_rules,
            "static_only_rules": self.static_only_rules,
            "dynamic_only_rules": self.dynamic_only_rules,
            "ruleset_unverified_rules": self.ruleset_unverified_rules,
            "union_coverage": self.union_coverage,
        }


@dataclass(frozen=True)
class MatrixComparison:
    """One static analysis compared with two or more labeled dynamic runs."""

    static: CapaDocument
    runs: tuple[MatrixRun, ...]
    confidence: str
    summary: MatrixSummary
    findings: tuple[MatrixFinding, ...]
    never_observed: tuple[MatrixFinding, ...]
    environment_sensitive: tuple[MatrixFinding, ...]
    observed_in_all: tuple[MatrixFinding, ...]
    static_only: tuple[Finding, ...]
    dynamic_only: dict[str, tuple[str, ...]]
    gate_signals: dict[str, tuple[str, ...]]
    ruleset_unverified: tuple[Finding, ...] = ()
    evidence_hotspots: tuple[EvidenceHotspot, ...] = ()
    experiment_baseline: str = ""
    experiment_warnings: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "analysis_type": "multi-run-matrix",
            "matrix": {
                "confidence": self.confidence,
                "sample_sha256": self.static.sample_sha256,
                "static_input": str(self.static.path),
                "static_capa_version": self.static.capa_version,
                "run_labels": [run.label for run in self.runs],
                "warnings": list(self.warnings),
                "experiment_baseline": self.experiment_baseline,
                "experiment_warnings": list(self.experiment_warnings),
            },
            "summary": self.summary.to_dict(),
            "runs": [run.to_dict() for run in self.runs],
            "findings": [item.to_dict() for item in self.findings],
            "never_observed": [item.to_dict() for item in self.never_observed],
            "environment_sensitive": [
                item.to_dict() for item in self.environment_sensitive
            ],
            "observed_in_all": [item.to_dict() for item in self.observed_in_all],
            "static_only": [item.to_dict() for item in self.static_only],
            "dynamic_only": [
                {"name": name, "observed_in": list(labels)}
                for name, labels in sorted(self.dynamic_only.items())
            ],
            "gate_signals": {
                label: list(signals) for label, signals in self.gate_signals.items()
            },
            "ruleset_unverified": [item.to_dict() for item in self.ruleset_unverified],
            "evidence_hotspots": [item.to_dict() for item in self.evidence_hotspots],
        }
