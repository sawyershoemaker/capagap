"""Offline analyst review worksheets for CapaGap handoff bundles."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from capagap.evidence import fingerprint
from capagap.jsonio import read_json
from capagap.output import write_text

TRIAGE_SCHEMA = "capagap-triage"
TRIAGE_SCHEMA_VERSION = 2
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


def _hash(value: Any) -> str:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise TriageError("review context is not valid JSON data") from exc
    return hashlib.sha256(encoded.encode()).hexdigest()


def _valid_digest(value: Any) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f]{64}", value))


def _review_bases(bundle: dict[str, Any]) -> dict[str, dict[str, Any]]:
    analysis = bundle["analysis"]
    provenance = analysis.get("provenance")
    known = isinstance(provenance, dict)
    provenance = provenance if known else {}
    run_sources = provenance.get("runs")
    labels = analysis.get("run_labels")
    known = (
        known
        and isinstance(run_sources, dict)
        and bool(run_sources)
        and isinstance(labels, list)
        and all(isinstance(label, str) for label in labels)
        and set(labels) == set(run_sources)
    )
    run_sources = run_sources if isinstance(run_sources, dict) else {}
    sources = {
        "static": provenance.get("static"),
        **{"run:" + label: value for label, value in run_sources.items()},
    }
    retained = {}
    for label, source in sources.items():
        if not isinstance(source, dict):
            known = False
            retained[label] = None
            continue
        known = (
            known
            and _valid_digest(source.get("content_sha256"))
            and all(
                isinstance(source.get(key), str) and source[key] not in ("", "unknown")
                for key in ("capa_version", "extractor", "format", "arch", "os")
            )
        )
        # File locations and timestamps are display metadata. Content digests bind
        # the actual inputs, including when negative evidence supports a review.
        retained[label] = {
            key: value
            for key, value in source.items()
            if key not in {"input", "timestamp"}
        }
    case = analysis.get("case")
    context = _hash(
        {
            "sample": {
                key: analysis["sample"].get(key)
                for key in ("sha256", "format", "arch", "os")
            },
            "type": analysis.get("type"),
            "base": analysis.get("source_image_base"),
            "runs": analysis.get("run_labels"),
            "provenance": retained,
            "ruleset": analysis.get("ruleset_manifest", {}).get("fingerprint")
            if isinstance(analysis.get("ruleset_manifest"), dict)
            else None,
            "experiment": analysis.get("experiment"),
            "case_conditions": case.get("conditions")
            if isinstance(case, dict)
            else None,
        }
    )
    bases = {}
    for finding in bundle["findings"]:
        runtime = finding.get("runtime_evidence", {})
        if not isinstance(runtime, dict):
            raise TriageError("runtime evidence must be an object")
        complete = bool(known) and _valid_digest(finding.get("source_digest"))
        for evidence in (finding.get("match_evidence"), *runtime.values()):
            if evidence is None:
                complete = False
                continue
            if not isinstance(evidence, dict) or not isinstance(
                evidence.get("matches"), list
            ):
                raise TriageError(
                    "retained match evidence must contain a matches array"
                )
            actual = fingerprint(evidence["matches"])
            if "fingerprint" in evidence and evidence["fingerprint"] != actual:
                raise TriageError("evidence fingerprint does not match retained data")
            complete = (
                complete
                and evidence.get("fingerprint") == actual
                and evidence.get("complete") is True
                and evidence.get("source_available") is True
                and evidence.get("tree_availability") == "retained"
                and evidence.get("source_digest") == finding.get("source_digest")
            )
        bases[finding["id"]] = {
            "rule": _hash(
                {
                    key: finding.get(key)
                    for key in (
                        "name",
                        "source_digest",
                        "namespace",
                        "static_scope",
                        "dynamic_scope",
                        "attack",
                        "mbc",
                    )
                }
            ),
            "evidence": _hash([finding.get("match_evidence"), runtime]),
            "observations": _hash(
                {
                    key: finding.get(key)
                    for key in (
                        "status",
                        "observed_in",
                        "unobserved_in",
                        "locations",
                        "unmappable_evidence",
                    )
                }
            ),
            "context": context,
            "complete": bool(complete),
        }
    return bases


def _worksheet_context(bundle: dict, bases: dict) -> str:
    return _hash([_handoff_identity(bundle), bases])


def build_triage_worksheet(bundle: dict[str, Any]) -> dict[str, Any]:
    """Create an editable worksheet bound to one exact handoff finding set."""

    _validate_handoff(bundle)
    bases = _review_bases(bundle)
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
                "basis": _hash(bases[finding["id"]]),
            }
        )
    return {
        "schema": TRIAGE_SCHEMA,
        "schema_version": TRIAGE_SCHEMA_VERSION,
        "handoff_identity": _handoff_identity(bundle),
        "handoff_context": _worksheet_context(bundle, bases),
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
    if "basis" in review and not _valid_digest(review["basis"]):
        raise TriageError(f"{label} has an invalid evidence basis")


def _validate_triage(payload: dict[str, Any]) -> dict[str, Any]:
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != TRIAGE_SCHEMA
        or type(payload.get("schema_version")) is not int
        or payload["schema_version"] not in (1, 2)
    ):
        raise TriageError("unsupported triage worksheet schema")
    if not isinstance(payload.get("handoff_identity"), str):
        raise TriageError("triage worksheet has no valid handoff identity")
    if payload["schema_version"] == 2 and not _valid_digest(
        payload.get("handoff_context")
    ):
        raise TriageError("triage worksheet has no valid evidence/context binding")
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
        if payload["schema_version"] == 2 and not _valid_digest(review.get("basis")):
            raise TriageError("triage review has no valid evidence basis")
        seen.add(finding_id)
    migration = payload.get("migration")
    if "migration" in payload:
        keys = {"retained", "needs_review", "new", "removed_reviews"}
        if (
            not isinstance(migration, dict)
            or set(migration) != keys
            or any(not isinstance(migration[key], list) for key in keys)
        ):
            raise TriageError("invalid review migration record")
        for key in ("retained", "new"):
            if any(not isinstance(value, str) for value in migration[key]):
                raise TriageError("invalid migration finding ID")
        for item in migration["needs_review"]:
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("id"), str)
                or not isinstance(item.get("reasons"), list)
                or any(not isinstance(reason, str) for reason in item["reasons"])
            ):
                raise TriageError("invalid reassessment record")
            _validate_review_fields(item.get("previous_review"), "previous review")
        for review in migration["removed_reviews"]:
            _validate_review_fields(review, "removed review")
    return payload


def _one_line(value: str) -> str:
    return " ".join(value.split())


def apply_triage(bundle: dict[str, Any], worksheet: dict[str, Any]) -> dict[str, Any]:
    return _apply_triage(bundle, worksheet, carrying=False)


def _apply_triage(
    bundle: dict[str, Any], worksheet: dict[str, Any], *, carrying: bool
) -> dict[str, Any]:
    _validate_handoff(bundle)
    _validate_triage(worksheet)
    if worksheet.get("handoff_identity") != _handoff_identity(bundle):
        raise TriageError("triage worksheet does not belong to this handoff")
    bases = None
    if worksheet["schema_version"] == 2:
        bases = _review_bases(bundle)
        if worksheet["handoff_context"] != _worksheet_context(bundle, bases):
            raise TriageError(
                "handoff evidence or context changed; use triage carry with the original handoff"
            )
        for review in worksheet["reviews"]:
            if review["id"] in bases and review["basis"] != _hash(bases[review["id"]]):
                raise TriageError("review evidence basis differs from the handoff")
    findings = {finding["id"]: finding for finding in bundle["findings"]}
    reviews = {review["id"]: review for review in worksheet["reviews"]}
    unknown = reviews.keys() - findings.keys()
    if unknown:
        raise TriageError(
            f"triage worksheet contains unknown finding id: {min(unknown)}"
        )
    if not carrying:
        for finding in bundle["findings"]:
            applied = finding.get("triage", {})
            if finding["id"] in reviews or "basis" not in applied:
                continue
            if bases is None:
                bases = _review_bases(bundle)
            if applied["basis"] != _hash(bases[finding["id"]]):
                raise TriageError(
                    "applied review evidence or context changed; use triage carry with the original handoff"
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
        if worksheet["schema_version"] == 2:
            finding["triage"]["basis"] = review["basis"]
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


def carry_triage(
    before: dict[str, Any], worksheet: dict[str, Any], after: dict[str, Any]
) -> dict[str, Any]:
    """Transfer reviews, preserving notes but never silently retaining stale judgments."""
    # Inherited judgments can be archived here even when their recorded basis
    # is stale. Explicit worksheet entries must still match the source handoff.
    reviewed = _apply_triage(before, worksheet, carrying=True)
    _validate_handoff(after)
    old_sample, new_sample = (
        before["analysis"]["sample"].get("sha256"),
        after["analysis"]["sample"].get("sha256"),
    )
    if not _valid_digest(old_sample) or old_sample != new_sample:
        raise TriageError("review carry requires matching valid sample SHA-256 hashes")
    for bundle in (before, after):
        names = [finding.get("name") for finding in bundle["findings"]]
        if any(not isinstance(name, str) or not name for name in names) or len(
            set(names)
        ) != len(names):
            raise TriageError("review carry requires unique, nonempty rule names")
    old_bases, new_bases = _review_bases(before), _review_bases(after)
    explicit_reviews = {review["id"] for review in worksheet["reviews"]}
    previous = {finding["name"]: finding for finding in reviewed["findings"]}
    result = build_triage_worksheet(after)
    migration = {"retained": [], "needs_review": [], "new": [], "removed_reviews": []}
    fields = ("disposition", "analyst_notes", "evidence", "reviewer", "reviewed_at")
    for review in result["reviews"]:
        prior = previous.pop(review["name"], None)
        if prior is None:
            migration["new"].append(review["id"])
            continue
        prior_review = {
            "id": prior["id"],
            "name": prior["name"],
            **prior.get("triage", {"disposition": "unreviewed"}),
        }
        old, new = old_bases[prior["id"]], new_bases[review["id"]]
        reasons = [
            key + "-changed"
            for key in ("rule", "evidence", "observations", "context")
            if old[key] != new[key]
        ]
        if (
            not old["complete"]
            or not new["complete"]
            or worksheet["schema_version"] == 1
        ):
            reasons.append("prior-basis-unverified")
        if (
            prior["id"] not in explicit_reviews
            and "triage" in prior
            and prior["triage"].get("basis") != _hash(old)
        ):
            reasons.append("applied-basis-unverified")
        for field in fields:
            review[field] = prior_review.get(
                field, "unreviewed" if field == "disposition" else ""
            )
        if reasons:
            review.update(disposition="unreviewed", reviewer="", reviewed_at="")
            migration["needs_review"].append(
                {
                    "id": review["id"],
                    "reasons": reasons,
                    "previous_review": prior_review,
                }
            )
        else:
            migration["retained"].append(review["id"])
    migration["removed_reviews"] = [
        {
            "id": finding["id"],
            "name": finding["name"],
            **finding.get("triage", {"disposition": "unreviewed"}),
        }
        for finding in previous.values()
    ]
    result["migration"] = migration
    return _validate_triage(result)


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
    pending = {
        item["id"] for item in worksheet.get("migration", {}).get("needs_review", [])
    }
    awaiting = sum(
        review["id"] in pending and review["disposition"] == "unreviewed"
        for review in reviews
    )
    if markdown:
        lines = [
            "# CapaGap triage review",
            "",
            f"- Findings: **{len(bundle['findings'])}**",
            f"- Reviewed: **{len(bundle['findings']) - counts['unreviewed']}**",
            f"- Awaiting reassessment: **{awaiting}**",
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
        f"Awaiting reassessment: {awaiting}",
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
    payload: dict[str, Any],
    output: str | Path,
    *,
    force: bool = False,
    forbidden: Iterable[str | Path] = (),
) -> Path:
    destination = Path(output)
    if (destination.exists() or destination.is_symlink()) and not force:
        raise TriageError(f"refusing to overwrite existing file: {destination}")
    try:
        content = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        if len(content.encode("utf-8")) > MAX_JSON_BYTES:
            raise TriageError("triage output exceeds the 64 MiB read limit")
        write_text(destination, content, forbidden=forbidden)
    except OSError as exc:
        raise TriageError(f"could not write {destination}: {exc}") from exc
    return destination
