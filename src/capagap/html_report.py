"""Render standalone HTML reports with an interactive capability matrix."""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from html import escape
from importlib.resources import files
from typing import Any

from capagap.contributions import analyze_contributions
from capagap.diagnostics import comparison_diagnostics
from capagap.evidence import search_terms
from capagap.models import (
    CapaDocument,
    Comparison,
    EvidenceHotspot,
    Finding,
    MatrixComparison,
    MatrixFinding,
    MatrixRun,
    RuleRecord,
)
from capagap.repeatability import analyze_repeatability

STATUS_LABELS = {
    "never-observed": "Never observed",
    "environment-sensitive": "Some runs",
    "observed-in-all": "All runs",
    "unobserved": "Unobserved",
    "observed": "Observed",
    "dynamic-only": "Runtime-only",
    "static-only": "Static-only",
    "ruleset-unverified": "Ruleset unverified",
}
GROUP_LABELS = {
    "comparable": "Comparable",
    "runtime": "Runtime-only",
    "excluded": "Excluded",
}
ICONS = {
    "chevron": '<path d="m9 5 7 7-7 7"/>',
    "check": '<circle cx="12" cy="12" r="10"/><path d="m7 12 3 3 7-7"/>',
    "missing": '<circle cx="12" cy="12" r="10"/><path d="M8 12h8"/>',
    "mixed": '<circle cx="12" cy="12" r="10"/><path d="M12 7v10M7 12h10"/>',
    "search": '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/>',
    "copy": '<rect x="8" y="8" width="12" height="13" rx="2"/>'
    '<path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h3"/>',
    "download": '<path d="M12 3v12m-5-5 5 5 5-5M4 15v5h16v-5"/>',
    "info": '<circle cx="12" cy="12" r="10"/><path d="M12 11v6M12 7v1"/>',
}


@dataclass(frozen=True)
class _Row:
    finding: Finding | MatrixFinding
    group: str
    observed_in: tuple[str, ...]
    evidence: tuple[tuple[str, RuleRecord, int | None, bool], ...]


def _e(value: Any) -> str:
    return escape(str(value), quote=True)


def _icon(name: str) -> str:
    return (
        '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
        'stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" '
        f'aria-hidden="true" focusable="false">{ICONS[name]}</svg>'
    )


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.0%}"


@lru_cache(maxsize=2)
def _asset(name: str) -> str:
    return (
        files("capagap").joinpath("assets").joinpath(name).read_text(encoding="utf-8")
    )


def _copy(value: str, label: str) -> str:
    return (
        f'<button type="button" class="icon-button copy-button js-only" '
        f'data-copy="{_e(value)}" aria-label="{_e(label)}" title="{_e(label)}">'
        f"{_icon('copy')}</button>"
    )


def _document_name(document: CapaDocument) -> str:
    return (
        document.sample_path.replace("\\", "/").rsplit("/", 1)[-1] or "Unknown sample"
    )


def _definition(label: str, value: str, *, code: bool = False) -> str:
    text = f"<code>{_e(value)}</code>" if code else _e(value)
    return f"<div><dt>{_e(label)}</dt><dd>{text}</dd></div>"


def _location_context(location: dict) -> str:
    context = location.get("context", {})
    return " · ".join(
        str(context[key])
        for key in ("process_name", "thread", "call_name", "function")
        if context.get(key)
    )


def _match_trees(rule: RuleRecord) -> str:
    matches = [match for match in rule.matches if match.get("tree")]
    if not matches:
        return '<p class="muted evidence-note">Detailed match trees were not recorded in this result.</p>'
    budget = [160]
    omitted = [False]

    def render_node(node: dict, depth: int = 0) -> str:
        if budget[0] <= 0 or depth >= 6:
            omitted[0] = True
            return '<li class="muted">Further detail is available in Export JSON.</li>'
        budget[0] -= 1
        state = (
            "Matched"
            if node.get("success") is True
            else "Not matched"
            if node.get("success") is False
            else "Not recorded"
        )
        label = str(node.get("label", "Unknown node"))
        description = node.get("details", {}).get("description", "")
        if (
            len(label) > 512
            or len(node.get("locations", [])) > 8
            or len(node.get("captures", {})) > 8
            or any(
                len(addresses) > 8 for addresses in node.get("captures", {}).values()
            )
        ):
            omitted[0] = True
        locations = []
        for location in node.get("locations", [])[:8]:
            context = _location_context(location)
            locations.append(
                f"<span><code>{_e(location['display'])}</code>{' · ' + _e(context) if context else ''}</span>"
            )
        captures = "".join(
            f"<li><code>{_e(value)}</code> at {_e(', '.join(location['display'] for location in addresses[:8]))}</li>"
            for value, addresses in list(node.get("captures", {}).items())[:8]
        )
        children = []
        for child in node.get("children", []):
            if budget[0] <= 0:
                omitted[0] = True
                break
            children.append(render_node(child, depth + 1))
        return (
            '<li><div class="evidence-node">'
            f'<span class="node-state">{state}</span><code title="{_e(label)}">{_e(label[:512])}</code></div>'
            + (
                f'<p class="node-description">{_e(description)}</p>'
                if description
                else ""
            )
            + (
                f'<div class="node-locations">{"".join(locations)}</div>'
                if locations
                else ""
            )
            + (f'<ul class="node-captures">{captures}</ul>' if captures else "")
            + (
                f'<ul class="evidence-tree">{"".join(children)}</ul>'
                if children
                else ""
            )
            + "</li>"
        )

    blocks = []
    for match in matches[:8]:
        if budget[0] <= 0:
            omitted[0] = True
            break
        address = match["address"]
        context = _location_context(address)
        blocks.append(
            '<details class="match-location" open><summary>'
            f"Match at <code>{_e(address['display'])}</code></summary>"
            + (f'<p class="muted">{_e(context)}</p>' if context else "")
            + f'<ul class="evidence-tree">{render_node(match["tree"])}</ul></details>'
        )
    note = ""
    if omitted[0] or len(matches) > 8:
        note = '<p class="muted evidence-note">This compact view omits detail. Export JSON contains the complete retained evidence.</p>'
    if rule.evidence_truncated:
        note += '<p class="evidence-note">Input evidence exceeded the retention limit. Consult the original capa document for omitted data.</p>'
    if rule.evidence_malformed:
        note += '<p class="evidence-note">Malformed evidence was omitted. Consult Input diagnostics and the original result.</p>'
    return (
        '<details class="match-evidence"><summary>Matched features and rule logic</summary>'
        '<p class="muted evidence-note">Branch states describe capa rule evaluation, not whether code executed.</p>'
        + "".join(blocks)
        + note
        + "</details>"
    )


def _evidence_block(
    label: str, rule: RuleRecord, base: int | None, static: bool
) -> str:
    entries = []
    for address in rule.evidence_addresses:
        if static:
            rva = address.rva(base)
            va = (
                address.value
                if address.kind == "absolute"
                else base + rva
                if base is not None and rva is not None
                else None
            )
            if address.kind in {"absolute", "relative"}:
                left = f"0x{va:X}" if va is not None else "Unknown"
                right = f"0x{rva:X}" if rva is not None else "Unmapped"
            else:
                left, right = address.display, "Unmapped"
        else:
            left, right = address.display, address.kind
        entries.append(
            f"<tr><td><code>{_e(left)}</code></td><td><code>{_e(right)}</code>"
            f"{_copy(right, 'Copy RVA ' + right) if static and rva is not None else ''}</td>"
            f"<td>{_copy(address.display, 'Copy evidence ' + address.display)}</td></tr>"
        )
    if not entries:
        entries = [
            f'<tr><td colspan="2"><code>{_e(value)}</code></td>'
            f"<td>{_copy(value, 'Copy evidence ' + value)}</td></tr>"
            for value in rule.evidence
        ]
    if entries:
        headers = ("VA / location", "RVA") if static else ("Location", "Address type")
        content = (
            f'<table class="evidence-table"><caption class="sr-only">{_e(label)}'
            f'</caption><thead><tr><th scope="col">{headers[0]}</th>'
            f'<th scope="col">{headers[1]}</th><th scope="col">'
            '<span class="sr-only">Copy</span></th></tr></thead>'
            f"<tbody>{''.join(entries)}</tbody></table>"
        )
    else:
        content = '<p class="muted">No match locations recorded.</p>'
    if static:
        base_text = f"0x{base:X}" if base is not None else "Not recorded"
        content += (
            f'<div class="image-base"><span>Image base</span><code>{base_text}</code>'
            f"{_copy(base_text, 'Copy image base') if base is not None else ''}</div>"
        )
        if any(address.rva(base) is None for address in rule.evidence_addresses):
            content += (
                '<p class="muted evidence-note">Unmapped locations have no portable '
                "RVA. Absolute locations need an image base; other address types "
                "are retained as reported.</p>"
            )
    count = len(rule.evidence_addresses) or len(rule.evidence)
    content += _match_trees(rule)
    return (
        f'<section class="evidence-source"><h3>{_e(label)} '
        f'<span class="muted">({count} {"location" if count == 1 else "locations"})'
        f"</span></h3>{content}</section>"
    )


def _detail(row: _Row, row_id: str, labels: tuple[str, ...]) -> str:
    item, rule = row.finding, row.finding.rule
    sources = "".join(_evidence_block(*source) for source in row.evidence if source[3])
    runtime = [source for source in row.evidence if not source[3]]
    if runtime:
        runtime_blocks = "".join(_evidence_block(*source) for source in runtime)
        sources += (
            '<details class="runtime-evidence"><summary>Runtime evidence '
            f"({len(runtime)} {'run' if len(runtime) == 1 else 'runs'})</summary>{runtime_blocks}</details>"
            if row.group != "runtime"
            else runtime_blocks
        )
    identifiers = _definition(
        "ATT&CK", ", ".join(rule.attack_ids) or "Not mapped", code=True
    ) + _definition("MBC", ", ".join(rule.mbc_ids) or "Not mapped", code=True)
    scopes = _definition(
        "Static scope", rule.static_scope or "Not supported"
    ) + _definition("Dynamic scope", rule.dynamic_scope or "Not supported")
    reasons = ""
    if item.reasons:
        reasons = (
            '<details class="reason-details"><summary>Priority and context</summary>'
            '<p class="muted">Scores set investigation order, not severity or probability.</p>'
            f"<ul>{''.join(f'<li>{_e(reason)}</li>' for reason in item.reasons)}</ul>"
            "</details>"
        )
    if row.group == "excluded":
        follow_up = (
            "<h3>Coverage boundary</h3><p>This capability is excluded from the "
            "coverage denominator. "
            + (
                "Its source could not be verified against the supplied manifest."
                if item.status == "ruleset-unverified"
                else "The rule does not declare a supported dynamic scope."
            )
            + "</p>"
        )
        if item.action:
            follow_up += f"<p>{_e(item.action)}</p>"
    elif item.action:
        follow_up = f"<h3>Suggested follow-up</h3><p>{_e(item.action)}</p>"
    elif row.group == "runtime":
        follow_up = (
            "<h3>Runtime observation</h3><p>This capability appears only in "
            "dynamic results. Runtime resolution, unpacking, or extractor "
            "differences may explain the additional match.</p>"
        )
    else:
        follow_up = (
            "<h3>Observation</h3><p>This capability was observed in every supplied "
            "dynamic result.</p>"
        )
    description = f"<p>{_e(rule.description)}</p>" if rule.description else ""
    observed = ", ".join(row.observed_in) or "None"
    missing = ", ".join(label for label in labels if label not in row.observed_in)
    run_context = ""
    if row.group != "excluded":
        run_context = (
            '<details class="reason-details"><summary>Observation by run</summary>'
            f'<dl class="key-values">{_definition("Observed in", observed)}'
            f"{_definition('Missing from', missing or 'None')}</dl></details>"
        )
    return (
        f'<div class="finding-detail" id="{row_id}-content" role="region" '
        f'aria-label="Evidence for {_e(rule.name)}">'
        f'<h2 class="sr-only">Evidence for {_e(rule.name)}</h2>'
        f'<div class="evidence-column">{sources}</div>'
        f'<div class="rule-column"><dl class="key-values identifiers">{identifiers}</dl>'
        f'<dl class="key-values scopes">{scopes}</dl>{run_context}</div>'
        f'<div class="action-column">{follow_up}{description}{reasons}</div></div>'
    )


def _row_html(row: _Row, index: int, labels: tuple[str, ...], expanded: bool) -> str:
    item, rule = row.finding, row.finding.rule
    row_id = f"finding-{index}"
    is_hidden = row.group != "comparable"
    detail_hidden = "" if expanded else " hidden"
    group_hidden = " hidden" if is_hidden else ""
    cells = []
    for label in labels:
        if row.group == "excluded":
            mark, state = '<span aria-hidden="true">—</span>', "Not comparable"
            tone = "neutral"
        elif label in row.observed_in:
            mark, state, tone = _icon("check"), "Observed", "observed"
        else:
            mark, state, tone = _icon("missing"), "Missing", "missing"
        cells.append(
            f'<td class="run-cell {tone}" data-label="{_e(label)}">'
            f'<span class="observation" title="{_e(label + ": " + state)}">'
            f'{mark}<span class="sr-only">{_e(state)}</span></span></td>'
        )
    status = STATUS_LABELS[item.status]
    attack = (
        ", ".join(
            f'<span class="identifier-token">{_e(identifier)}</span>'
            for identifier in rule.attack_ids
        )
        or "—"
    )
    priority = (
        f'{_e(item.priority_label)} <span class="score">{item.priority}</span>'
        if item.priority
        else '<span class="muted">info</span>'
    )
    search_text = " ".join(
        (
            rule.name,
            rule.namespace,
            status,
            item.status,
            item.priority_label,
            *rule.attack_ids,
            *rule.mbc_ids,
            *rule.evidence,
            *(
                search_terms(source_rule.matches)
                for _, source_rule, _, _ in row.evidence
            ),
            *(address.display for address in rule.evidence_addresses),
            *(
                value
                for _, source_rule, _, _ in row.evidence
                for value in source_rule.evidence
            ),
            *(
                address.display
                for _, source_rule, _, _ in row.evidence
                for address in source_rule.evidence_addresses
            ),
            *(
                f"0x{rva:X}"
                for _, source_rule, base, static in row.evidence
                if static
                for address in source_rule.evidence_addresses
                if (rva := address.rva(base)) is not None
            ),
        )
    )
    return (
        f'<tbody class="matrix-group" data-record data-group="{row.group}" '
        f'data-state="{_e(item.status)}" data-name="{_e(rule.name)}" '
        f'data-search="{_e(search_text)}"{group_hidden}>'
        f'<tr class="capability-row{" selected" if expanded else ""}" data-row>'
        f'<td class="expand-cell"><button type="button" class="row-toggle" '
        f'id="{row_id}-toggle" aria-expanded="{str(expanded).lower()}" '
        f'aria-controls="{row_id}-detail" aria-label="Evidence for {_e(rule.name)}">'
        f"{_icon('chevron')}</button></td>"
        f'<th scope="row" class="name-cell">{_e(rule.name)}'
        f'<span class="mobile-namespace">{_e(rule.namespace)}</span></th>'
        f'<td class="namespace-cell">{_e(rule.namespace)}</td>'
        f'<td class="state-cell" data-label="State">{_e(status)}</td>'
        f"{''.join(cells)}"
        f'<td class="attack-cell" data-label="ATT&CK"><code>'
        f"{attack}</code></td>"
        f'<td class="priority-cell" data-label="Priority">{priority}</td></tr>'
        f'<tr class="details-row" id="{row_id}-detail"{detail_hidden}>'
        f'<td colspan="{len(labels) + 6}">{_detail(row, row_id, labels)}</td>'
        "</tr></tbody>"
    )


def _disclosure(
    element_id: str, title: str, content: str, *, open_by_default: bool = False
) -> str:
    return (
        f'<details class="report-section" id="{element_id}"'
        f"{' open' if open_by_default else ''}>"
        f"<summary>{_icon('chevron')}<span>{_e(title)}</span></summary>"
        f'<div class="section-content"><h2 class="sr-only">{_e(title)}</h2>{content}</div></details>'
    )


def _contributions(comparison: MatrixComparison) -> str:
    result = analyze_contributions(comparison)
    rows = []
    for run in result["runs"]:
        unique = ", ".join(run["unique_capabilities"]) or "None"
        added = ", ".join(run["added_vs_baseline"]) or "None"
        rows.append(
            f'<tr><th scope="row">{_e(run["label"])}</th><td>{run["observed_count"]}</td>'
            f"<td>{run['unique_count']}</td><td>{_e(unique)}</td><td>{_e(added)}</td></tr>"
        )
    selection = (
        ", ".join(result["representative_set"]["labels"])
        or "None: the measured union is empty"
    )
    return (
        '<p class="section-intro">Unique means observed in this run and no other supplied run. '
        f"Baseline: <strong>{_e(result['baseline'])}</strong>.</p>"
        '<div class="horizontal-scroll" tabindex="0" role="region" aria-label="Run contribution table">'
        '<table class="data-table"><caption class="sr-only">Run contributions</caption><thead><tr>'
        '<th scope="col">Run</th><th scope="col">Observed</th><th scope="col">Unique</th>'
        '<th scope="col">Unique capabilities</th><th scope="col">Added vs baseline</th>'
        f"</tr></thead><tbody>{''.join(rows)}</tbody></table></div>"
        f'<p class="support-heading">Representative set</p><p>{_e(selection)}</p>'
        '<p class="muted contribution-boundary">A deterministic greedy selection preserving the measured capability union; '
        "not a guaranteed minimum. Equivalent capability coverage does not establish equivalent behavior. "
        "Runs with no unique capabilities cannot necessarily all be removed together.</p>"
        + "".join(
            f'<p class="evidence-note">{_e(warning)}</p>'
            for warning in result["warnings"]
        )
    )


def _repeatability(comparison: MatrixComparison) -> str:
    result = analyze_repeatability(comparison)
    content = [f'<p class="section-intro">{_e(result["interpretation"])}</p>']
    for group in result["groups"]:
        settings = ", ".join(f"{k}={v}" for k, v in group["conditions"].items())
        content.append(
            f"<h3>{_e(settings)}</h3><p>{_e(', '.join(group['run_labels']))}: {group['run_count']} distinct documents</p>"
        )
        if not group["assessed"]:
            content.append(
                '<p class="muted">At least two distinct documents are required.</p>'
            )
            continue
        counts = group["counts"]
        content.append(
            f"<p>{counts['intermittent']} intermittent · {counts['observed-in-all']} observed in all · {counts['never-observed']} never observed · {counts['source-unverified']} source-unverified</p>"
        )
        rows = "".join(
            f'<tr><th scope="row">{_e(row["name"])}</th><td>{row["observed_count"]}/{row["run_count"]}</td><td>{_e(row["state"])}</td></tr>'
            for row in group["capabilities"][:20]
        )
        content.append(
            '<div class="horizontal-scroll" tabindex="0" role="region" aria-label="Repeatability table">'
            '<table class="data-table"><caption class="sr-only">Run repeatability</caption>'
            '<thead><tr><th scope="col">Capability</th><th scope="col">Observed</th><th scope="col">State</th></tr></thead>'
            f"<tbody>{rows}</tbody></table></div>"
        )
        if len(group["capabilities"]) > 20 or group["omitted_capabilities"]:
            content.append(
                '<p class="muted">First 20 retained details shown, with intermittent observations first. Export JSON for more detail; omitted rows are counted explicitly.</p>'
            )
    content.extend(
        f'<p class="evidence-note">{_e(warning)}</p>' for warning in result["warnings"]
    )
    return "".join(content)


def _diagnostics(comparison: Comparison | MatrixComparison) -> str:
    issues = comparison_diagnostics(comparison)
    if not issues:
        return '<p class="muted">No input-quality issues found.</p>'
    return (
        '<ul class="diagnostic-list">'
        + "".join(
            f'<li><span class="diagnostic-label">{_e(item.severity.capitalize())} · {_e(item.input or "Comparison")}</span>'
            f"<code>{_e(item.code)}</code><p>{_e(item.message)}</p></li>"
            for item in issues
        )
        + "</ul>"
    )


def _conditions(
    runs: tuple[MatrixRun, ...], matrix: bool, warnings: tuple[str, ...]
) -> str:
    headers = (
        '<th scope="col">Declared conditions</th><th scope="col">Changed vs baseline</th>'
        if matrix
        else ""
    )
    rows = []
    for run in runs:
        summary = run.comparison.summary
        cells = ""
        if matrix:
            conditions = ", ".join(f"{key}={value}" for key, value in run.conditions)
            cells = (
                f"<td><code>{_e(conditions or 'Not declared')}</code></td>"
                f"<td>{_e(', '.join(run.changed_conditions) or 'None')}</td>"
            )
        rows.append(
            f'<tr><th scope="row">{_e(run.label)}</th>'
            f"<td>{_pct(summary.observed_coverage)} "
            f'<span class="muted">({summary.observed_rules}/'
            f"{summary.comparable_static_rules})</span></td>"
            f"<td>{summary.dynamic_only_rules}</td>"
            f"<td>{_e(run.comparison.confidence)}</td>{cells}</tr>"
        )
    note = (
        f'<p class="section-intro">Declared inputs relative to baseline '
        f"<strong>{_e(runs[0].label)}</strong>. A changed setting does not establish causation.</p>"
        if matrix
        else '<p class="section-intro">Coverage for the supplied dynamic result.</p>'
    )
    warning_html = (
        '<ul class="warning-list">'
        + "".join(f"<li>{_e(warning)}</li>" for warning in warnings)
        + "</ul>"
        if warnings
        else ""
    )
    return (
        f'{note}<div class="horizontal-scroll" tabindex="0" role="region" '
        'aria-label="Run coverage and conditions"><table class="data-table">'
        '<caption class="sr-only">Run coverage and conditions</caption>'
        '<thead><tr><th scope="col">Run</th><th scope="col">Coverage</th>'
        '<th scope="col">Runtime-only</th><th scope="col">Input confidence</th>'
        f"{headers}</tr></thead><tbody>{''.join(rows)}</tbody></table></div>{warning_html}"
    )


def _hotspots(hotspots: tuple[EvidenceHotspot, ...]) -> str:
    if not hotspots:
        return '<p class="muted">No mapped evidence locations for the prioritized findings.</p>'
    rows = []
    for hotspot in hotspots:
        links = "".join(
            f'<button type="button" class="text-button js-only" '
            f'data-find="{_e(name)}">{_e(name)}</button>'
            f'<span class="print-only">{_e(name)}</span>'
            for name in hotspot.rule_names
        )
        rows.append(
            f'<tr><th scope="row"><code>{hotspot.display}</code>'
            f"{_copy(hotspot.display, 'Copy RVA ' + hotspot.display)}</th>"
            f"<td>{len(hotspot.rule_names)}</td><td>{hotspot.maximum_priority}</td>"
            f'<td class="hotspot-links">{links}</td></tr>'
        )
    return (
        '<p class="section-intro">Findings at the same exact RVA. These are not '
        "inferred function boundaries or call-graph relationships.</p>"
        '<div class="horizontal-scroll" tabindex="0" role="region" '
        'aria-label="Evidence hotspots"><table class="data-table">'
        '<caption class="sr-only">Evidence hotspots</caption><thead><tr>'
        '<th scope="col">RVA</th><th scope="col">Findings</th>'
        '<th scope="col">Max priority</th><th scope="col">Capabilities</th>'
        f"</tr></thead><tbody>{''.join(rows)}</tbody></table></div>"
    )


def _input_details(
    static: CapaDocument, runs: tuple[MatrixRun, ...], confidence: str
) -> str:
    documents = [("Static", static)] + [
        (run.label, run.comparison.dynamic) for run in runs
    ]
    blocks = []
    for label, document in documents:
        digest = document.sample_sha256 or "Not recorded"
        rows = (
            _definition("Report", str(document.path), code=True)
            + _definition("Sample", document.sample_path or "Not recorded", code=True)
            + _definition("capa version", document.capa_version)
            + _definition("Extractor", document.extractor)
            + _definition(
                "Result SHA-256",
                document.provenance.get("content_sha256", "Not recorded"),
                code=True,
            )
            + _definition(
                "Analyzed at", document.provenance.get("timestamp") or "Not recorded"
            )
            + _definition(
                "Invocation",
                " ".join(document.provenance["argv"])
                if document.provenance.get("argv") is not None
                else "Not recorded",
                code=True,
            )
            + _definition(
                "Platform", f"{document.os} / {document.arch} / {document.format}"
            )
        )
        blocks.append(
            f'<section class="input-document"><h3>{_e(label)}</h3>'
            f'<div class="hash-line"><span>SHA-256</span><code>{_e(digest)}</code>'
            f"{_copy(digest, 'Copy SHA-256 for ' + label) if document.sample_sha256 else ''}"
            f'</div><dl class="key-values">{rows}</dl></section>'
        )
    manifest = runs[0].comparison.metadata.get("ruleset_manifest")
    manifest_text = (
        '<h3>Ruleset manifest</h3><dl class="key-values">'
        + "".join(
            _definition(key.replace("_", " ").capitalize(), str(value), code=True)
            for key, value in manifest.items()
        )
        + "</dl>"
        if isinstance(manifest, dict)
        else '<p class="muted">No ruleset manifest supplied.</p>'
    )
    drift = "".join(
        f"<li><strong>{_e(run.label)}</strong>: {_e(', '.join(run.comparison.source_drift))}</li>"
        for run in runs
        if run.comparison.source_drift
    )
    return (
        f'<p class="section-intro">{_e(confidence.capitalize())} input confidence '
        "describes consistency between the supplied documents. It is not a "
        "confidence score for a behavioral conclusion.</p>"
        f'<div class="input-documents">{"".join(blocks)}</div>{manifest_text}'
        + (
            f'<h3>Rule source drift</h3><ul class="warning-list">{drift}</ul>'
            if drift
            else ""
        )
    )


def _rows(
    comparison: Comparison | MatrixComparison,
) -> tuple[tuple[MatrixRun, ...], list[_Row]]:
    matrix = isinstance(comparison, MatrixComparison)
    runs = comparison.runs if matrix else (MatrixRun("dynamic", comparison),)
    comparable = (
        comparison.findings if matrix else comparison.unobserved + comparison.observed
    )
    result = [
        _Row(
            finding=item,
            group="comparable",
            observed_in=item.observed_in
            if matrix
            else (("dynamic",) if item.status == "observed" else ()),
            evidence=(
                ("Static evidence", item.rule, comparison.static.base_address, True),
            )
            + tuple(
                (
                    run.label + " evidence",
                    run.comparison.dynamic.rules[item.rule.name],
                    None,
                    False,
                )
                for run in runs
                if item.rule.name in run.comparison.dynamic.rules
            ),
        )
        for item in comparable
    ]
    runtime_names = (
        sorted(comparison.dynamic_only)
        if matrix
        else [item.rule.name for item in comparison.dynamic_only]
    )
    for name in runtime_names:
        sources = tuple(
            (run.label + " evidence", run.comparison.dynamic.rules[name], None, False)
            for run in runs
            if name in run.comparison.dynamic.rules
        )
        result.append(
            _Row(
                finding=Finding("dynamic-only", sources[0][1], 0, "informational"),
                group="runtime",
                observed_in=tuple(
                    run.label for run in runs if name in run.comparison.dynamic.rules
                ),
                evidence=sources,
            )
        )
    result.extend(
        _Row(
            item,
            "excluded",
            (),
            (("Static evidence", item.rule, comparison.static.base_address, True),),
        )
        for item in comparison.static_only + comparison.ruleset_unverified
    )
    return tuple(runs), result


def _render(comparison: Comparison | MatrixComparison) -> str:
    matrix = isinstance(comparison, MatrixComparison)
    runs, rows = _rows(comparison)
    labels = tuple(run.label for run in runs)
    static, summary = comparison.static, comparison.summary
    coverage = summary.union_coverage if matrix else summary.observed_coverage
    observed = summary.union_observed_rules if matrix else summary.observed_rules
    comparable = summary.comparable_static_rules
    group_counts = {
        group: sum(row.group == group for row in rows) for group in GROUP_LABELS
    }
    controls = "".join(
        f'<button type="button" data-group-button="{group}" '
        f'aria-pressed="{str(group == "comparable").lower()}" '
        f'class="group-button">{label}<span>{group_counts[group]}</span></button>'
        for group, label in GROUP_LABELS.items()
    )
    states = list(dict.fromkeys(row.finding.status for row in rows))
    options = '<option value="">All states</option>' + "".join(
        f'<option value="{_e(status)}">{_e(STATUS_LABELS[status])}</option>'
        for status in states
    )
    run_headers = "".join(
        f'<th scope="col" class="run-heading">{_e(run.label)}'
        f'<span class="muted">{_pct(run.comparison.summary.observed_coverage)}</span>'
        f"<span>{run.comparison.summary.observed_rules} / "
        f"{run.comparison.summary.comparable_static_rules}</span></th>"
        for run in runs
    )
    inventory = "".join(
        _row_html(row, index, labels, index == 0 and row.group == "comparable")
        for index, row in enumerate(rows)
    )
    warning_list = comparison.warnings + tuple(
        f"{item.input}: {item.message}"
        for document in [comparison.static, *(run.comparison.dynamic for run in runs)]
        for item in document.diagnostics
        if item.severity in {"warning", "error"}
    )
    experiment_warnings = comparison.experiment_warnings if matrix else ()
    warning_count = len(warning_list) + len(experiment_warnings)
    warning_notice = (
        f'<a class="warning-link" href="#analysis-warnings" data-open-section>'
        f"{_icon('info')}{warning_count} "
        f"{'warning' if warning_count == 1 else 'warnings'}</a>"
        if warning_count
        else ""
    )
    conditions_title = "Run conditions" if matrix else "Run details"
    sections = (
        _disclosure(
            "run-conditions",
            conditions_title,
            _conditions(runs, matrix, experiment_warnings),
        )
        + _disclosure(
            "evidence-hotspots",
            "Evidence hotspots",
            _hotspots(comparison.evidence_hotspots),
        )
        + _disclosure(
            "input-details",
            "Input details",
            _input_details(static, runs, comparison.confidence),
        )
    )
    if matrix:
        sections = (
            _disclosure(
                "run-contributions", "Run contributions", _contributions(comparison)
            )
            + _disclosure(
                "run-repeatability", "Run repeatability", _repeatability(comparison)
            )
            + sections
        )
    sections += _disclosure(
        "input-diagnostics", "Input diagnostics", _diagnostics(comparison)
    )
    case = comparison.metadata.get("case")
    if isinstance(case, dict):
        sections = (
            _disclosure(
                "case-details",
                case["name"] + " · Case notes",
                '<dl class="key-values">'
                + _definition("Case ID", case["id"], code=True)
                + _definition("Input verification", "Pinned input hashes verified")
                + "</dl>"
                + (
                    f'<p class="case-notes">{_e(case["notes"])}</p>'
                    if case["notes"]
                    else '<p class="muted">No analyst notes recorded. Edit notes in case.json and regenerate the report.</p>'
                ),
            )
            + sections
        )
    gates = comparison.gate_signals if matrix else {"dynamic": comparison.gate_signals}
    gates = {label: signals for label, signals in gates.items() if signals}
    if gates:
        gate_rows = "".join(
            f"<li><strong>{_e(label)}</strong>: {_e(', '.join(signals))}</li>"
            for label, signals in gates.items()
        )
        sections += _disclosure(
            "analysis-context",
            "Anti-analysis context",
            f'<ul>{gate_rows}</ul><p class="muted">These observed matches add a small '
            "priority boost to other gaps. They do not establish that any check "
            "caused the missing behavior.</p>",
        )
    if warning_count:
        sections += _disclosure(
            "analysis-warnings",
            f"Analysis warnings ({warning_count})",
            '<ul class="warning-list">'
            + "".join(
                f"<li>{_e(warning)}</li>"
                for warning in warning_list + experiment_warnings
            )
            + "</ul>",
            open_by_default=True,
        )
    sample_name = _document_name(static)
    all_documents = [static] + [run.comparison.dynamic for run in runs]
    synthetic = all(document.synthetic for document in all_documents)
    synthetic_label = (
        '<span class="example-label">Synthetic example</span>' if synthetic else ""
    )
    coverage_label = "union coverage" if matrix else "observed coverage"
    title = (
        "Multi-run capability coverage"
        if matrix
        else "Static and dynamic capability coverage"
    )
    payload = json.dumps(comparison.to_dict(), ensure_ascii=True, separators=(",", ":"))
    payload = (
        payload.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<title>CapaGap — {_e(sample_name)} — {_e(title)}</title>
<link rel="icon" href="data:,">
<style>{_asset("report.css")}</style>
</head>
<body>
<a class="skip-link" href="#capability-matrix">Skip to capability matrix</a>
<header class="appbar">
  <div class="brand"><span class="wordmark"><span>Capa</span>Gap</span>
    <span class="sample-name">{_e(sample_name)}</span></div>
  <button class="button js-only" type="button" data-export="capagap-{"matrix" if matrix else "comparison"}.json">{_icon("download")}Export JSON</button>
</header>
<section class="sample-strip" aria-label="Sample and coverage summary">
  <div class="sample-metadata">{synthetic_label}
    <span><small>File</small> {_e(sample_name)}</span>
    <span><small>Arch</small> {_e(static.arch)}</span>
    <span><small>OS</small> {_e(static.os)}</span>
  </div>
  <div class="coverage-summary">
    <span><strong>{_pct(coverage)}</strong> {coverage_label}</span>
    <span><strong>{observed} / {comparable}</strong> comparable</span>
    <span><strong>{len(runs)}</strong> {"runs" if matrix else "run"}</span>
    <a href="#input-details" data-open-section>{_e(comparison.confidence.capitalize())} input confidence</a>
    {warning_notice}
  </div>
</section>
<main>
<h1 class="sr-only">{_e(title)}</h1>
<div class="workspace-toolbar">
  <nav aria-label="Report sections">
    <a class="active" href="#capability-matrix" data-matrix-link>Matrix</a>
    <a href="#run-conditions" data-open-section>{conditions_title}</a>
{'    <a href="#run-contributions" data-open-section>Run contributions</a>' if matrix else ""}
    <a href="#evidence-hotspots" data-open-section>Evidence hotspots</a>
  </nav>
  <div class="filters js-only">
    <label class="search-field">{_icon("search")}
      <span class="sr-only">Filter capabilities</span>
      <input type="search" data-search placeholder="Filter capabilities…" autocomplete="off">
    </label>
    <label class="state-filter"><span class="sr-only">Observation state</span>
      <select data-state-filter>{options}</select>
    </label>
  </div>
</div>
<section class="matrix-section" id="capability-matrix" aria-label="Capability matrix" tabindex="-1">
  <div class="groupbar js-only" role="group" aria-label="Capability views">{controls}</div>
  <noscript><p class="no-script">All findings and evidence are shown. Enable JavaScript for filtering, copying, and export.</p>
  <style>.matrix-group[hidden]{{display:table-row-group!important}}.details-row[hidden]{{display:table-row!important}}.js-only,.row-toggle{{display:none!important}}.print-only{{display:inline!important}}</style></noscript>
  <p class="group-description" data-group-description hidden></p>
  <div class="matrix-scroll" role="region" aria-label="Scrollable capability matrix" tabindex="0">
    <table class="matrix">
      <caption class="sr-only">Capability matrix across {_e(", ".join(labels))}</caption>
      <thead><tr>
        <th scope="col" class="expand-cell"><span class="sr-only">Expand evidence</span></th>
        <th scope="col" class="name-heading">Capability</th>
        <th scope="col" class="namespace-heading">Namespace</th>
        <th scope="col" class="state-heading">State</th>{run_headers}
        <th scope="col" class="attack-heading">ATT&amp;CK</th>
        <th scope="col" class="priority-heading">Priority</th>
      </tr></thead>{inventory}
    </table>
  </div>
  <div class="empty-state" data-empty{" hidden" if comparable else ""}>
    <h2 data-empty-title>No comparable capabilities</h2>
    <p data-empty-message>Check the runtime-only and excluded views for other matches.</p>
    <button type="button" class="button js-only" data-reset>Reset filters</button>
  </div>
  <div class="matrix-footer">
    <span data-result-count role="status" aria-live="polite">{comparable} comparable capabilities</span>
    <div class="legend" aria-label="Observation legend">
      <span class="observed">{_icon("check")}<span>Observed</span></span>
      <span class="missing">{_icon("missing")}<span>Missing</span></span>
      <span class="mixed">{_icon("mixed")}<span>Some runs</span></span>
    </div>
    <span class="boundary">A missing match does not prove non-execution.</span>
  </div>
</section>
<div class="report-sections">{sections}</div>
</main>
<div class="toast" data-feedback role="status" aria-live="polite" hidden></div>
<dialog class="copy-dialog" aria-labelledby="copy-title">
  <form method="dialog"><div class="dialog-heading"><h2 id="copy-title">Copy text</h2>
    <button type="submit" class="button">Close</button></div>
    <p>Your browser blocked automatic copying. Select and copy the text below.</p>
    <textarea readonly aria-label="Text to copy"></textarea>
  </form>
</dialog>
<script id="report-data" type="application/json">{payload}</script>
<script>{_asset("report.js")}</script>
</body>
</html>
"""


def render_html(comparison: Comparison) -> str:
    return _render(comparison)


def render_matrix_html(comparison: MatrixComparison) -> str:
    return _render(comparison)
