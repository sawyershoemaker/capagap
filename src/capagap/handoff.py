"""Build portable RE-tool handoff bundles and emit native import scripts."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from importlib.resources import files
from pathlib import Path
from typing import Any

from capagap import __version__
from capagap.models import Comparison, Finding, MatrixComparison, MatrixFinding
from capagap.triage import build_triage_worksheet

SCHEMA_NAME = "capagap-handoff"
SCHEMA_VERSION = 1
PRIORITY_MINIMUMS = {"low": 0, "medium": 35, "high": 55, "critical": 70}
TOOL_TEMPLATES = {
    "ghidra": ("CapaGapImport_Ghidra.py", "ghidra.py.tmpl"),
    "ida": ("capagap_import_ida.py", "ida.py.tmpl"),
    "binary-ninja": ("capagap_import_binja.py", "binary_ninja.py.tmpl"),
}


class HandoffError(ValueError):
    """Raised when a handoff bundle cannot be built or written safely."""


def _finding_id(finding: Finding | MatrixFinding) -> str:
    identity = f"{finding.rule.name}\0{finding.rule.source_digest}"
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]


def _one_line(value: str) -> str:
    return " ".join(value.split())


def _path_name(value: str) -> str:
    return value.replace("\\", "/").rsplit("/", 1)[-1]


def _comment(finding: Finding | MatrixFinding, finding_id: str) -> str:
    parts = [
        f"[CapaGap:{finding_id}]",
        f"{finding.priority_label.upper()} {finding.priority}",
        finding.status,
        _one_line(finding.rule.name),
    ]
    if finding.rule.attack_ids:
        parts.append("ATT&CK " + ", ".join(finding.rule.attack_ids))
    if isinstance(finding, MatrixFinding):
        if finding.observed_in:
            parts.append("seen: " + ", ".join(finding.observed_in))
        if finding.unobserved_in:
            parts.append("not seen: " + ", ".join(finding.unobserved_in))
    if finding.action:
        parts.append("next: " + _one_line(finding.action))
    return " | ".join(parts)[:1200]


def _serialize_finding(
    finding: Finding | MatrixFinding, image_base: int | None
) -> dict[str, Any]:
    finding_id = _finding_id(finding)
    locations = []
    seen: set[tuple[str, int | tuple[int, ...] | None]] = set()
    for address in finding.rule.evidence_addresses:
        key = (address.kind, address.value)
        if key in seen:
            continue
        seen.add(key)
        location = address.to_dict(image_base)
        if location["rva"] is not None:
            locations.append(location)

    result: dict[str, Any] = {
        "id": finding_id,
        "status": finding.status,
        "name": finding.rule.name,
        "namespace": finding.rule.namespace,
        "priority": finding.priority,
        "priority_label": finding.priority_label,
        "static_scope": finding.rule.static_scope,
        "dynamic_scope": finding.rule.dynamic_scope,
        "attack": list(finding.rule.attack_ids),
        "mbc": list(finding.rule.mbc_ids),
        "reasons": list(finding.reasons),
        "suggested_action": finding.action,
        "comment": _comment(finding, finding_id),
        "locations": locations,
        "unmappable_evidence": [
            address.to_dict(image_base)
            for address in finding.rule.evidence_addresses
            if address.rva(image_base) is None
        ],
        "source_digest": finding.rule.source_digest,
        "match_evidence": finding.rule.evidence_dict(),
    }
    if isinstance(finding, MatrixFinding):
        result["observed_in"] = list(finding.observed_in)
        result["unobserved_in"] = list(finding.unobserved_in)
    return result


def _bundle(
    comparison: Comparison | MatrixComparison,
    findings: Iterable[Finding | MatrixFinding],
    *,
    analysis_type: str,
    run_labels: tuple[str, ...],
    minimum_priority: str,
    statuses: tuple[str, ...],
) -> dict[str, Any]:
    if minimum_priority not in PRIORITY_MINIMUMS:
        raise HandoffError(f"unknown priority threshold: {minimum_priority}")

    threshold = PRIORITY_MINIMUMS[minimum_priority]
    selected = tuple(item for item in findings if item.priority >= threshold)
    absolute_evidence = any(
        address.kind == "absolute"
        for item in selected
        for address in item.rule.evidence_addresses
    )
    if absolute_evidence and comparison.static.base_address is None:
        raise HandoffError(
            "static capa result has no absolute analysis base_address; RVAs cannot be derived safely"
        )

    serialized = [
        _serialize_finding(item, comparison.static.base_address) for item in selected
    ]
    evidence_runs = (
        [(run.label, run.comparison.dynamic) for run in comparison.runs]
        if isinstance(comparison, MatrixComparison)
        else [(run_labels[0], comparison.dynamic)]
    )
    for entry in serialized:
        entry["runtime_evidence"] = {
            label: document.rules[entry["name"]].evidence_dict()
            for label, document in evidence_runs
            if entry["name"] in document.rules
        }
    addressable = sum(bool(item["locations"]) for item in serialized)
    location_count = sum(len(item["locations"]) for item in serialized)
    unmappable_count = sum(len(item["unmappable_evidence"]) for item in serialized)

    if isinstance(comparison, MatrixComparison):
        ruleset = (
            comparison.runs[0].comparison.metadata.get("ruleset_manifest")
            if comparison.runs
            else None
        )
        experiment = {
            "baseline": comparison.experiment_baseline,
            "warnings": list(comparison.experiment_warnings),
            "runs": [
                {
                    "label": run.label,
                    "conditions": dict(run.conditions),
                    "changed_conditions": list(run.changed_conditions),
                }
                for run in comparison.runs
            ],
        }
    else:
        ruleset = comparison.metadata.get("ruleset_manifest")
        experiment = None

    return {
        "schema": SCHEMA_NAME,
        "schema_version": SCHEMA_VERSION,
        "generator": {"name": "capagap", "version": __version__},
        "analysis": {
            "type": analysis_type,
            "confidence": comparison.confidence,
            "static_input": comparison.static.path.name,
            "static_capa_version": comparison.static.capa_version,
            "sample": {
                "sha256": comparison.static.sample_sha256,
                "path": _path_name(comparison.static.sample_path),
                "format": comparison.static.format,
                "arch": comparison.static.arch,
                "os": comparison.static.os,
            },
            "source_image_base": comparison.static.base_address,
            "source_image_base_hex": (
                f"0x{comparison.static.base_address:X}"
                if comparison.static.base_address is not None
                else None
            ),
            "run_labels": list(run_labels),
            "selection": {
                "statuses": list(statuses),
                "minimum_priority": minimum_priority,
                "minimum_score": threshold,
            },
            "warnings": list(comparison.warnings)
            + (
                list(comparison.experiment_warnings)
                if isinstance(comparison, MatrixComparison)
                else []
            ),
            "ruleset_manifest": ruleset,
            "experiment": experiment,
            "case": comparison.metadata.get("case"),
            "provenance": {
                "static": comparison.static.provenance_dict(),
                "runs": {
                    label: document.provenance_dict()
                    for label, document in evidence_runs
                },
            },
        },
        "summary": {
            "selected_findings": len(serialized),
            "addressable_findings": addressable,
            "non_addressable_findings": len(serialized) - addressable,
            "addressable_locations": location_count,
            "unmappable_evidence": unmappable_count,
        },
        "findings": serialized,
        "evidence_hotspots": [
            hotspot.to_dict() for hotspot in comparison.evidence_hotspots
        ],
    }


def build_single_handoff(
    comparison: Comparison,
    *,
    run_label: str,
    minimum_priority: str = "low",
) -> dict[str, Any]:
    """Build a bundle from the unobserved findings in one dynamic run."""

    return _bundle(
        comparison,
        comparison.unobserved,
        analysis_type="single-run",
        run_labels=(run_label,),
        minimum_priority=minimum_priority,
        statuses=("unobserved",),
    )


def build_matrix_handoff(
    comparison: MatrixComparison,
    *,
    minimum_priority: str = "low",
    never_only: bool = False,
) -> dict[str, Any]:
    """Build a bundle from multi-run gaps and environment-sensitive findings."""

    findings: tuple[MatrixFinding, ...]
    statuses: tuple[str, ...]
    if never_only:
        findings = comparison.never_observed
        statuses = ("never-observed",)
    else:
        findings = comparison.never_observed + comparison.environment_sensitive
        statuses = ("never-observed", "environment-sensitive")
    return _bundle(
        comparison,
        findings,
        analysis_type="multi-run-matrix",
        run_labels=tuple(run.label for run in comparison.runs),
        minimum_priority=minimum_priority,
        statuses=statuses,
    )


def _read_template(name: str) -> str:
    return files("capagap").joinpath("importers", name).read_text(encoding="utf-8")


def _requested_templates(tool: str) -> dict[str, tuple[str, str]]:
    if tool == "all":
        return TOOL_TEMPLATES
    if tool in TOOL_TEMPLATES:
        return {tool: TOOL_TEMPLATES[tool]}
    return {}


def _readme(bundle: dict[str, Any], tool: str) -> str:
    summary = bundle["summary"]
    sections = [
        "CapaGap RE-tool handoff",
        "=======================",
        "",
        f"Findings: {summary['selected_findings']}",
        f"Addressable locations: {summary['addressable_locations']}",
        f"Sample SHA-256: {bundle['analysis']['sample']['sha256'] or '<unavailable>'}",
        "",
        "The importers use RVAs from capagap-handoff.json and rebase them against",
        "the image base of the currently open database. Importers reject a known",
        "sample-hash mismatch and skip addresses outside mapped memory.",
        "",
        "Analyst review",
        "--------------",
        "Edit capagap-triage.json using one of its documented dispositions. Keep",
        "the original handoff unchanged, then run:",
        "  capagap triage apply capagap-handoff.json capagap-triage.json --output reviewed-handoff.json",
        "Importing the reviewed handoff updates the CapaGap annotation while",
        "preserving unrelated analyst comments.",
        "",
    ]
    requested = _requested_templates(tool)
    if "ghidra" in requested:
        sections.extend(
            [
                "Ghidra",
                "------",
                "Open the matching sample, then run CapaGapImport_Ghidra.py from",
                "Script Manager (category: CapaGap). Select capagap-handoff.json.",
                "The script creates Analysis bookmarks in category CapaGap.",
                "",
            ]
        )
    if "ida" in requested:
        sections.extend(
            [
                "IDA Pro",
                "-------",
                "Open the matching sample, choose File > Script file, and run",
                "capagap_import_ida.py. Select capagap-handoff.json when prompted.",
                "The script adds repeatable comments and preserves existing text.",
                "",
            ]
        )
    if "binary-ninja" in requested:
        sections.extend(
            [
                "Binary Ninja",
                "------------",
                "Install capagap_import_binja.py in your user plugin directory and",
                "restart Binary Ninja. Open the matching sample, then choose",
                "Plugins > CapaGap > Import handoff and select the JSON bundle.",
                "The plugin adds address comments and preserves existing text.",
                "",
            ]
        )
    sections.extend(
        [
            "Safety",
            "------",
            "This bundle contains analysis metadata and comments only. It does not",
            "contain or execute the analyzed sample. Review imported findings as",
            "triage leads; an unobserved capability is not proof of non-execution.",
            "",
        ]
    )
    return "\n".join(sections)


def write_handoff(
    bundle: dict[str, Any],
    output_directory: str | Path,
    *,
    tool: str = "all",
    force: bool = False,
) -> tuple[Path, ...]:
    """Write a bundle and requested importers without silent overwrites."""

    if tool not in {"all", "json", *TOOL_TEMPLATES}:
        raise HandoffError(f"unsupported handoff tool: {tool}")
    output = Path(output_directory)
    if output.exists() and not output.is_dir():
        raise HandoffError(f"handoff output is not a directory: {output}")

    payloads = {
        "capagap-handoff.json": json.dumps(bundle, indent=2, sort_keys=True) + "\n",
        "capagap-triage.json": json.dumps(
            build_triage_worksheet(bundle), indent=2, sort_keys=True
        )
        + "\n",
        "README.txt": _readme(bundle, tool),
    }
    requested = _requested_templates(tool)
    for output_name, template_name in requested.values():
        payloads[output_name] = _read_template(template_name)

    targets = tuple(output / name for name in payloads)
    conflicts = tuple(path for path in targets if path.exists())
    if conflicts and not force:
        names = ", ".join(path.name for path in conflicts)
        raise HandoffError(
            f"refusing to overwrite existing handoff file(s): {names} (use --force)"
        )

    try:
        output.mkdir(parents=True, exist_ok=True)
        for path, content in zip(targets, payloads.values(), strict=True):
            path.write_text(content, encoding="utf-8", newline="\n")
    except OSError as exc:
        raise HandoffError(f"could not write handoff bundle: {exc}") from exc
    return targets
