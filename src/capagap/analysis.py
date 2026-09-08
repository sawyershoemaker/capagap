"""Core comparison engine."""

from __future__ import annotations

import re
from collections.abc import Iterable

from capagap.diagnostics import require_valid
from capagap.hotspots import build_evidence_hotspots
from capagap.manifest import RuleManifest
from capagap.models import (
    CapaDocument,
    Comparison,
    ComparisonSummary,
    Finding,
    RuleRecord,
)
from capagap.scoring import priority_label, score_rule, suggested_action


class ComparisonError(ValueError):
    """Raised when two documents cannot be compared responsibly."""


def _major(version: str) -> str | None:
    head = version.split(".", 1)[0]
    return head if head.isdigit() else None


def _filter_rules(
    document: CapaDocument, include_library: bool
) -> dict[str, RuleRecord]:
    return {
        name: rule
        for name, rule in document.rules.items()
        if include_library or not rule.library
    }


def _finding(
    status: str, rule: RuleRecord, *, evasion_context: bool = False
) -> Finding:
    if status == "unobserved":
        score, reasons = score_rule(rule, evasion_context=evasion_context)
        return Finding(
            status=status,
            rule=rule,
            priority=score,
            priority_label=priority_label(score),
            reasons=reasons,
            action=suggested_action(rule),
        )
    return Finding(status=status, rule=rule, priority=0, priority_label="informational")


def _sort_findings(findings: Iterable[Finding]) -> tuple[Finding, ...]:
    return tuple(
        sorted(findings, key=lambda item: (-item.priority, item.rule.name.lower()))
    )


def compare_documents(
    static: CapaDocument,
    dynamic: CapaDocument,
    *,
    allow_mismatch: bool = False,
    include_library: bool = False,
    ruleset_manifest: RuleManifest | None = None,
    strict: bool = False,
) -> Comparison:
    """Compare static potential with behavior observed in one dynamic run."""

    if static.flavor != "static":
        raise ComparisonError(f"first input must be static, got {static.flavor}")
    if dynamic.flavor != "dynamic":
        raise ComparisonError(f"second input must be dynamic, got {dynamic.flavor}")

    warnings: list[str] = []
    confidence = "high"
    hashes_present = all(
        re.fullmatch(r"[0-9a-fA-F]{64}", value)
        for value in (static.sample_sha256, dynamic.sample_sha256)
    )
    hashes_match = (
        hashes_present and static.sample_sha256.lower() == dynamic.sample_sha256.lower()
    )
    if hashes_present and not hashes_match:
        message = (
            "sample SHA-256 values differ; the reports may describe different samples"
        )
        if not allow_mismatch:
            raise ComparisonError(
                message + " (use --allow-mismatch only when this is intentional)"
            )
        warnings.append(message)
        confidence = "low"
    elif not hashes_present:
        warnings.append(
            "one or both reports lack a valid sample SHA-256; sample identity is unverified"
        )
        confidence = "medium"

    if static.os != dynamic.os:
        warnings.append(f"OS differs: static={static.os}, dynamic={dynamic.os}")
        confidence = (
            "low"
            if confidence == "medium"
            else "medium"
            if confidence == "high"
            else confidence
        )
    if static.arch != dynamic.arch:
        warnings.append(
            f"architecture differs: static={static.arch}, dynamic={dynamic.arch}"
        )
        confidence = (
            "low"
            if confidence == "medium"
            else "medium"
            if confidence == "high"
            else confidence
        )

    static_major = _major(static.capa_version)
    dynamic_major = _major(dynamic.capa_version)
    if static_major and dynamic_major and static_major != dynamic_major:
        warnings.append(
            f"capa major versions differ: static={static.capa_version}, dynamic={dynamic.capa_version}"
        )
        confidence = (
            "low"
            if confidence == "medium"
            else "medium"
            if confidence == "high"
            else confidence
        )

    static_rules = _filter_rules(static, include_library)
    dynamic_rules = _filter_rules(dynamic, include_library)
    raw_comparable = {
        name: rule for name, rule in static_rules.items() if rule.dynamically_comparable
    }
    static_only_rules = {
        name: rule
        for name, rule in static_rules.items()
        if not rule.dynamically_comparable
    }

    ruleset_unverified: tuple[Finding, ...] = ()
    comparable = raw_comparable
    if ruleset_manifest is not None:
        for name, rule in dynamic_rules.items():
            entry = ruleset_manifest.rules.get(name)
            if entry is None:
                raise ComparisonError(
                    f"dynamic result rule {name!r} is absent from ruleset manifest"
                )
            if entry.source_digest != rule.source_digest:
                raise ComparisonError(
                    f"dynamic result rule {name!r} does not match its manifest source digest"
                )

        verified = {
            name: rule
            for name, rule in raw_comparable.items()
            if (
                name in ruleset_manifest.rules
                and ruleset_manifest.rules[name].source_digest == rule.source_digest
            )
        }
        unverified_names = raw_comparable.keys() - verified.keys()
        ruleset_unverified = _sort_findings(
            Finding(
                status="ruleset-unverified",
                rule=raw_comparable[name],
                priority=0,
                priority_label="informational",
                reasons=(
                    "rule is absent from the supplied manifest"
                    if name not in ruleset_manifest.rules
                    else "static rule source differs from the supplied manifest",
                    "excluded from verified coverage",
                ),
                action="Regenerate both capa results and the manifest from the same ruleset revision.",
            )
            for name in unverified_names
        )
        comparable = verified
        if ruleset_unverified:
            warnings.append(
                f"{len(ruleset_unverified)} comparable static rule(s) could not be verified against the supplied ruleset manifest and were excluded from coverage"
            )

    observed_names = comparable.keys() & dynamic_rules.keys()
    unobserved_names = comparable.keys() - dynamic_rules.keys()
    dynamic_only_names = dynamic_rules.keys() - static_rules.keys()

    gate_signals = tuple(
        sorted(
            static_rules[name].name
            for name in observed_names
            if "anti-analysis" in static_rules[name].namespace.lower()
        )
    )
    evasion_context = bool(gate_signals)

    observed = _sort_findings(
        _finding("observed", static_rules[name]) for name in observed_names
    )
    unobserved = _sort_findings(
        _finding("unobserved", static_rules[name], evasion_context=evasion_context)
        for name in unobserved_names
    )
    static_only = _sort_findings(
        _finding("static-only", static_only_rules[name]) for name in static_only_rules
    )
    dynamic_only = _sort_findings(
        _finding("dynamic-only", dynamic_rules[name]) for name in dynamic_only_names
    )

    source_drift = tuple(
        sorted(
            name
            for name in static_rules.keys() & dynamic_rules.keys()
            if static_rules[name].source_digest != dynamic_rules[name].source_digest
        )
    )
    if source_drift:
        warnings.append(
            f"{len(source_drift)} shared rule(s) have different source text between reports; rule-set drift may affect results"
        )

    summary = ComparisonSummary(
        static_rules=len(static_rules),
        dynamic_rules=len(dynamic_rules),
        comparable_static_rules=len(comparable),
        observed_rules=len(observed),
        unobserved_rules=len(unobserved),
        static_only_rules=len(static_only),
        dynamic_only_rules=len(dynamic_only),
        ruleset_unverified_rules=len(ruleset_unverified),
    )
    metadata = {
        "include_library_rules": include_library,
        "sample_hashes_match": hashes_match,
        "static_extractor": static.extractor,
        "dynamic_extractor": dynamic.extractor,
    }
    if ruleset_manifest is not None:
        metadata["ruleset_manifest"] = {
            "source_name": ruleset_manifest.source_name,
            "fingerprint": ruleset_manifest.fingerprint,
            "path": ruleset_manifest.path.name,
            "verified_comparable_rules": len(comparable),
            "excluded_unverified_rules": len(ruleset_unverified),
        }

    result = Comparison(
        static=static,
        dynamic=dynamic,
        confidence=confidence,
        summary=summary,
        unobserved=unobserved,
        observed=observed,
        static_only=static_only,
        dynamic_only=dynamic_only,
        ruleset_unverified=ruleset_unverified,
        evidence_hotspots=build_evidence_hotspots(unobserved, static.base_address),
        gate_signals=gate_signals,
        warnings=tuple(warnings),
        source_drift=source_drift,
        metadata=metadata,
    )
    if strict:
        require_valid(result)
    return result
