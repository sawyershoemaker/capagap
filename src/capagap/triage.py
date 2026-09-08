"""Offline analyst review worksheets for CapaGap handoff bundles."""

from __future__ import annotations

import copy
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from capagap.jsonio import read_json

TRIAGE_SCHEMA = "capagap-triage"
TRIAGE_SCHEMA_VERSION = 1
HANDOFF_SCHEMA = "capagap-handoff"
MAX_JSON_BYTES = 64 * 1024 * 1024
DISPOSITIONS = {
    "unreviewed",
    "confirmed",
    "likely",
    "benign",
    "false-positive",
    "needs-data",
    "deferred",
}


class TriageError(ValueError):
    """Raised when a handoff or review worksheet is unsafe or inconsistent."""


def _load_json(path: str | Path, label: str) -> dict[str, Any]:
    source = Path(path)
    try:
        payload = read_json(source, MAX_JSON_BYTES)
    except FileNotFoundError as exc:
        raise TriageError(f"{label} does not exist: {source}") from exc
    except OSError as exc:
        raise TriageError(f"could not read {label} {source}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise TriageError(
            f"invalid {label} JSON at line {exc.lineno}, column {exc.colno}"
        ) from exc
    except (ValueError, RecursionError) as exc:
        raise TriageError(f"invalid {label} JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise TriageError(f"{label} root must be an object")
    return payload


def load_handoff(path: str | Path) -> dict[str, Any]:
    return _validate_handoff(_load_json(path, "handoff"))


def _validate_handoff(payload: dict[str, Any]) -> dict[str, Any]:
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != HANDOFF_SCHEMA
        or type(payload.get("schema_version")) is not int
        or payload["schema_version"] != 1
    ):
        raise TriageError("unsupported handoff schema")
    findings = payload.get("findings")
    analysis = payload.get("analysis")
    summary = payload.get("summary")
    if not isinstance(analysis, dict) or not isinstance(analysis.get("sample"), dict):
        raise TriageError("handoff analysis and sample metadata must be objects")
    if not isinstance(summary, dict):
        raise TriageError("handoff summary must be an object")
    if not isinstance(findings, list):
        raise TriageError("handoff findings must be an array")
    seen = set()
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            raise TriageError(f"handoff finding {index} must be an object")
        finding_id = finding.get("id")
        if not isinstance(finding_id, str) or not finding_id:
            raise TriageError(f"handoff finding {index} has no valid id")
        if finding_id in seen:
            raise TriageError(f"duplicate handoff finding id: {finding_id}")
        if not isinstance(finding.get("name", ""), str) or not isinstance(
            finding.get("comment", ""), str
        ):
            raise TriageError(f"handoff finding {finding_id!r} has invalid text")
        if "triage" in finding:
            _validate_review_fields(
                finding["triage"], f"handoff finding {finding_id!r} triage"
            )
        seen.add(finding_id)
    return payload


def _handoff_identity(bundle: dict[str, Any]) -> str:
    sample = bundle.get("analysis", {}).get("sample", {}).get("sha256", "")
    finding_ids = sorted(
        finding.get("id", "") for finding in bundle.get("findings", [])
    )
    content = json.dumps([sample, finding_ids], separators=(",", ":"))
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def build_triage_worksheet(bundle: dict[str, Any]) -> dict[str, Any]:
    """Create an editable worksheet bound to one exact handoff finding set."""

    _validate_handoff(bundle)
    reviews = []
    for finding in bundle.get("findings", []):
        reviews.append(
            {
                "id": finding["id"],
                "name": finding.get("name", ""),
                "disposition": "unreviewed",
                "analyst_notes": "",
                "evidence": "",
                "reviewer": "",
                "reviewed_at": "",
            }
        )
    return {
        "schema": TRIAGE_SCHEMA,
        "schema_version": TRIAGE_SCHEMA_VERSION,
        "handoff_identity": _handoff_identity(bundle),
        "sample_sha256": bundle.get("analysis", {}).get("sample", {}).get("sha256", ""),
        "reviews": reviews,
    }


def load_triage(path: str | Path) -> dict[str, Any]:
    return _validate_triage(_load_json(path, "triage worksheet"))


def _validate_review_fields(review: dict[str, Any], label: str) -> None:
    if not isinstance(review, dict):
        raise TriageError(f"{label} must be an object")
    disposition = review.get("disposition")
    if not isinstance(disposition, str) or disposition not in DISPOSITIONS:
        raise TriageError(f"{label} has invalid disposition {disposition!r}")
    for field in ("analyst_notes", "evidence", "reviewer", "reviewed_at"):
        if not isinstance(review.get(field, ""), str):
            raise TriageError(f"{label} field {field!r} must be text")


def _validate_triage(payload: dict[str, Any]) -> dict[str, Any]:
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != TRIAGE_SCHEMA
        or type(payload.get("schema_version")) is not int
        or payload["schema_version"] != 1
    ):
        raise TriageError("unsupported triage worksheet schema")
    if not isinstance(payload.get("handoff_identity"), str):
        raise TriageError("triage worksheet has no valid handoff identity")
    reviews = payload.get("reviews")
    if not isinstance(reviews, list):
        raise TriageError("triage reviews must be an array")
    seen = set()
    for index, review in enumerate(reviews):
        if not isinstance(review, dict):
            raise TriageError(f"triage review {index} must be an object")
        finding_id = review.get("id")
        if not isinstance(finding_id, str) or not finding_id:
            raise TriageError(f"triage review {index} has no valid id")
        if finding_id in seen:
            raise TriageError(f"duplicate triage review id: {finding_id}")
        _validate_review_fields(review, f"triage review {finding_id!r}")
        seen.add(finding_id)
    return payload


def _one_line(value: str) -> str:
    return " ".join(value.split())


def apply_triage(bundle: dict[str, Any], worksheet: dict[str, Any]) -> dict[str, Any]:
    _validate_handoff(bundle)
    _validate_triage(worksheet)
    if worksheet.get("handoff_identity") != _handoff_identity(bundle):
        raise TriageError("triage worksheet does not belong to this handoff")
    findings = {finding["id"]: finding for finding in bundle["findings"]}
    reviews = {review["id"]: review for review in worksheet["reviews"]}
    unknown = reviews.keys() - findings.keys()
    if unknown:
        raise TriageError(
            f"triage worksheet contains unknown finding id: {min(unknown)}"
        )

    reviewed = copy.deepcopy(bundle)
    reviewed["analysis"]["triage_applied"] = True
    for finding in reviewed["findings"]:
        review = reviews.get(finding["id"])
        if review is None:
            continue
        finding["triage"] = {
            key: review.get(key, "")
            for key in (
                "disposition",
                "analyst_notes",
                "evidence",
                "reviewer",
                "reviewed_at",
            )
        }
        marker = f"[CapaGap:{finding['id']}]"
        base = finding.get("comment", marker).split(" | triage:", 1)[0]
        disposition = review["disposition"]
        note = _one_line(review.get("analyst_notes", ""))
        suffix = f" | triage: {disposition}"
        if note:
            suffix += f" ({note})"
        finding["comment"] = (base + suffix)[:1200]
    counts = Counter(
        finding.get("triage", {}).get("disposition", "unreviewed")
        for finding in reviewed["findings"]
    )
    reviewed["summary"]["triage"] = dict(sorted(counts.items()))
    return reviewed


def render_triage_report(
    bundle: dict[str, Any], worksheet: dict[str, Any], *, markdown: bool = False
) -> str:
    reviewed = apply_triage(bundle, worksheet)
    reviews = [
        {
            **finding.get("triage", {"disposition": "unreviewed"}),
            "id": finding["id"],
            "name": finding.get("name", ""),
        }
        for finding in reviewed["findings"]
    ]
    counts = Counter(review["disposition"] for review in reviews)
    if markdown:
        lines = [
            "# CapaGap triage review",
            "",
            f"- Findings: **{len(bundle['findings'])}**",
            f"- Reviewed: **{len(bundle['findings']) - counts['unreviewed']}**",
            "",
            "| Disposition | Count |",
            "|---|---:|",
        ]
        lines.extend(f"| {key} | {value} |" for key, value in sorted(counts.items()))
        lines.extend(["", "## Findings", ""])
        for review in reviews:
            note = review.get("analyst_notes") or "-"
            lines.append(f"- **{review['name']}** — {review['disposition']}: {note}")
        return "\n".join(lines) + "\n"

    lines = [
        "CapaGap triage review",
        "",
        f"Findings: {len(bundle['findings'])}",
        f"Reviewed: {len(bundle['findings']) - counts['unreviewed']}",
        "",
        "Disposition counts",
    ]
    lines.extend(f"  {key}: {value}" for key, value in sorted(counts.items()))
    lines.extend(["", "Findings"])
    for review in reviews:
        note = _one_line(review.get("analyst_notes", "")) or "-"
        lines.append(f"  [{review['disposition']}] {review['name']}: {note}")
    return "\n".join(lines) + "\n"


def write_json(
    payload: dict[str, Any], output: str | Path, *, force: bool = False
) -> Path:
    destination = Path(output)
    if destination.exists() and not force:
        raise TriageError(f"refusing to overwrite existing file: {destination}")
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    except OSError as exc:
        raise TriageError(f"could not write {destination}: {exc}") from exc
    return destination
