"""Derive conservative triage hotspots from exact evidence addresses."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from capagap.models import EvidenceHotspot, Finding, MatrixFinding


def build_evidence_hotspots(
    findings: Iterable[Finding | MatrixFinding],
    image_base: int | None,
) -> tuple[EvidenceHotspot, ...]:
    """Group findings by exact, mappable RVA without inferring control flow."""

    grouped: dict[int, dict[str, Finding | MatrixFinding]] = defaultdict(dict)
    for finding in findings:
        for address in finding.rule.evidence_addresses:
            rva = address.rva(image_base)
            if rva is not None:
                grouped[rva][finding.rule.name] = finding

    hotspots = []
    for rva, items_by_name in grouped.items():
        items = tuple(items_by_name.values())
        hotspots.append(
            EvidenceHotspot(
                rva=rva,
                rule_names=tuple(sorted(items_by_name)),
                statuses=tuple(sorted({item.status for item in items})),
                aggregate_priority=sum(item.priority for item in items),
                maximum_priority=max(item.priority for item in items),
            )
        )
    return tuple(
        sorted(
            hotspots,
            key=lambda item: (
                -len(item.rule_names),
                -item.aggregate_priority,
                item.rva,
            ),
        )
    )
