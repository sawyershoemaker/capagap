"""Input-quality observations, separate from behavioral coverage."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from capagap.models import CapaDocument, Comparison, MatrixComparison


@dataclass(frozen=True)
class Diagnostic:
    code: str
    severity: str
    message: str
    input: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
            "input": self.input,
        }


class ValidationError(ValueError):
    """Strict input checks found warnings or errors."""


def inspect_document(
    document: CapaDocument, *, minimum_features: int = 1
) -> tuple[Diagnostic, ...]:
    findings = []

    def add(code: str, severity: str, message: str) -> None:
        findings.append(Diagnostic(code, severity, message, document.path.name))

    if not re.fullmatch(r"[0-9a-f]{64}", document.sample_sha256):
        add("sample-identity", "warning", "A valid sample SHA-256 is not recorded.")
    for name in ("capa_version", "format", "arch", "os", "extractor"):
        if getattr(document, name) in {"", "unknown"}:
            add(
                "missing-metadata",
                "warning",
                f"The {name.replace('_', ' ')} is not recorded.",
            )
    argv = document.provenance.get("argv")
    if argv is None:
        add(
            "command-unavailable",
            "info",
            "Invocation arguments are unavailable; analysis restrictions cannot be checked.",
        )
    else:
        restricted = (
            "-t",
            "--tag",
            "--restrict-to-functions",
            "--restrict-to-processes",
            "--restrict-to-threads",
        )
        flags = sorted(
            {
                arg.split("=", 1)[0]
                for arg in argv
                if arg.split("=", 1)[0] in restricted
                or (arg.startswith("-t") and not arg.startswith("--") and len(arg) > 2)
            }
        )
        if flags:
            add(
                "restricted-analysis",
                "warning",
                "Invocation restricted the analysis: "
                + ", ".join(flags)
                + ". Coverage describes this selection only.",
            )
    if not document.rules:
        add(
            "no-rule-matches",
            "warning",
            "No rule matches were recorded; this alone does not establish an empty execution trace.",
        )
    counts = document.provenance.get("feature_counts", {})
    total = counts.get("total")
    if total is None:
        add(
            "feature-counts-unavailable",
            "info",
            "Feature counts are unavailable; telemetry volume cannot be assessed.",
        )
    elif total < minimum_features:
        add(
            "sparse-features",
            "warning",
            f"The result records {total} extracted features, below the requested minimum of {minimum_features}. This is an input-quality threshold, not a behavioral conclusion.",
        )
    if document.provenance.get("counts_invalid"):
        add(
            "invalid-feature-counts",
            "warning",
            "Some feature counts were invalid and were not used.",
        )
    if document.provenance.get("evidence_truncated"):
        add(
            "evidence-truncated",
            "warning",
            "The bounded evidence view was truncated. Original input hashes are retained; consult the original result for omitted detail.",
        )
    if document.provenance.get("evidence_malformed"):
        add(
            "malformed-evidence",
            "warning",
            "Some match-tree or layout records were malformed and were not included in the evidence view.",
        )
    missing_sources = sum(not rule.source_available for rule in document.rules.values())
    if missing_sources:
        add(
            "rule-source-unavailable",
            "warning",
            f"{missing_sources} rule(s) lack source text; source identity cannot be verified for them.",
        )
    unsupported = sorted(
        {
            rule.dynamic_scope
            for rule in document.rules.values()
            if rule.dynamic_scope and not rule.dynamically_comparable
        }
    )
    if unsupported:
        add(
            "unsupported-dynamic-scope",
            "warning",
            "Unrecognized dynamic scopes are excluded from coverage: "
            + ", ".join(unsupported),
        )
    if document.rules and not any(
        match.get("tree") for rule in document.rules.values() for match in rule.matches
    ):
        add(
            "match-trees-unavailable",
            "info",
            "Match locations are available, but detailed match trees were not recorded.",
        )
    return tuple(findings)


def comparison_diagnostics(
    comparison: Comparison | MatrixComparison,
) -> tuple[Diagnostic, ...]:
    from capagap.models import MatrixComparison

    result = list(comparison.static.diagnostics)
    if isinstance(comparison, MatrixComparison):
        for run in comparison.runs:
            result.extend(
                Diagnostic(item.code, item.severity, item.message, run.label)
                for item in run.comparison.dynamic.diagnostics
            )
        result.extend(
            Diagnostic("experiment-context", "warning", text)
            for text in comparison.experiment_warnings
        )
    else:
        result.extend(comparison.dynamic.diagnostics)
    result.extend(
        Diagnostic("comparison-context", "warning", text)
        for text in comparison.warnings
    )
    return tuple(dict.fromkeys(result))


def require_valid(comparison: Comparison | MatrixComparison) -> None:
    issues = [
        item
        for item in comparison_diagnostics(comparison)
        if item.severity in {"warning", "error"}
    ]
    if issues:
        raise ValidationError(
            "strict validation failed: "
            + "; ".join(
                f"{item.input}: {item.code}: {item.message}" for item in issues[:8]
            )
        )


def render_validation(result: dict[str, Any], *, markdown: bool = False) -> str:
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

    lines = [("# " if markdown else "") + "CapaGap input diagnostics", ""]
    if not result["diagnostics"]:
        lines.append("No input issues found.")
    for item in result["diagnostics"]:
        lines.append(
            f"- {clean(item['severity']).upper()} [{clean(item['code'])}] {clean(item['input'])}: {clean(item['message'])}"
        )
    return "\n".join(lines) + "\n"


def validation_result(comparison: Comparison | MatrixComparison) -> dict[str, Any]:
    items = comparison_diagnostics(comparison)
    return {
        "schema": "capagap-validation",
        "schema_version": 1,
        "passed": not any(item.severity in {"warning", "error"} for item in items),
        "diagnostics": [item.to_dict() for item in items],
        "summary": {
            level: sum(item.severity == level for item in items)
            for level in ("error", "warning", "info")
        },
    }
