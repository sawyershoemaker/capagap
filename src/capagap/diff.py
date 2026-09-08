"""Compare saved CapaGap reports while retaining the analysis boundary."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from capagap.evidence import fingerprint
from capagap.io import _read_bytes
from capagap.jsonio import decode_json


class DiffError(ValueError):
    """Saved reports cannot be compared safely."""


def load_report(path: str | Path) -> dict[str, Any]:
    try:
        result = decode_json(_read_bytes(Path(path)))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DiffError(f"invalid saved report: {exc}") from exc
    _view(result)
    return result


def _view(report: Any) -> dict:
    if (
        not isinstance(report, dict)
        or type(report.get("schema_version")) is not int
        or report["schema_version"] != 1
    ):
        raise DiffError("expected a CapaGap report with schema_version 1")
    matrix = report.get("analysis_type") == "multi-run-matrix"
    if report.get("analysis_type") not in (None, "single-run", "multi-run-matrix"):
        raise DiffError("unknown saved-report analysis type")
    metadata = report.get("matrix" if matrix else "comparison")
    if not isinstance(metadata, dict):
        raise DiffError("expected a saved comparison or matrix, not a raw capa result")
    labels = metadata.get("run_labels") if matrix else ["dynamic"]
    if (
        not isinstance(labels, list)
        or not labels
        or len(labels) > 128
        or any(not isinstance(label, str) or not label for label in labels)
        or len(set(labels)) != len(labels)
    ):
        raise DiffError("invalid or duplicate saved-report run labels")
    names = {}
    groups = (
        ("findings", "static_only", "ruleset_unverified", "dynamic_only")
        if matrix
        else (
            "observed",
            "unobserved",
            "static_only",
            "ruleset_unverified",
            "dynamic_only",
        )
    )
    for group in groups:
        if group != "ruleset_unverified" and group not in report:
            raise DiffError(f"saved report is missing {group}")
        items = report.get(group, [])
        if not isinstance(items, list):
            raise DiffError(f"report {group} must be an array")
        for item in items:
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("name"), str)
                or not item["name"]
                or item["name"] in names
            ):
                raise DiffError("findings require unique, nonempty names")
            status = item.get(
                "status", "dynamic-only" if group == "dynamic_only" else None
            )
            if (
                "source_available" in item
                and type(item["source_available"]) is not bool
            ):
                raise DiffError("invalid finding source availability")
            if "source_digest" in item and (
                not isinstance(item["source_digest"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", item["source_digest"])
            ):
                raise DiffError("invalid finding source digest")
            if not isinstance(status, str):
                raise DiffError("finding status is missing")
            allowed = (
                {
                    "never-observed",
                    "environment-sensitive",
                    "observed-in-all",
                    "static-only",
                    "ruleset-unverified",
                    "dynamic-only",
                }
                if matrix
                else {
                    "observed",
                    "unobserved",
                    "static-only",
                    "ruleset-unverified",
                    "dynamic-only",
                }
            )
            if status not in allowed:
                raise DiffError("unknown finding status")
            observed = (
                item.get("observed_in", [])
                if matrix
                else (["dynamic"] if status in {"observed", "dynamic-only"} else [])
            )
            if (
                not isinstance(observed, list)
                or any(
                    not isinstance(label, str) or label not in labels
                    for label in observed
                )
                or len(set(observed)) != len(observed)
            ):
                raise DiffError("finding references invalid run labels")
            if matrix and group == "findings":
                expected_status = (
                    "never-observed"
                    if not observed
                    else "observed-in-all"
                    if len(observed) == len(labels)
                    else "environment-sensitive"
                )
                if status != expected_status:
                    raise DiffError("finding status conflicts with its observed runs")
            elif status != group.replace("_", "-"):
                raise DiffError("finding is in the wrong status group")
            names[item["name"]] = {**item, "status": status, "observed_in": observed}
    sample = metadata.get("sample_sha256", "")
    if not isinstance(sample, str):
        raise DiffError("invalid saved-report sample identity")
    return {
        "kind": "matrix" if matrix else "single",
        "metadata": metadata,
        "labels": labels,
        "sample": sample,
        "findings": names,
    }


def _evidence_index(report: dict) -> dict:
    """Verify every retained fingerprint once, including added/removed findings."""
    evidence = report.get("evidence", {})
    if not isinstance(evidence, dict):
        raise DiffError("report evidence must be an object")
    result = {}
    sources = [("static", evidence.get("static", {}))]
    runs = evidence.get("runs", {})
    if not isinstance(runs, dict):
        raise DiffError("report run evidence must be an object")
    sources.extend(("run:" + label, rules) for label, rules in runs.items())
    for label, rules in sources:
        if not isinstance(rules, dict):
            raise DiffError("report evidence source must be an object")
        for name, entry in rules.items():
            if not isinstance(name, str) or not name:
                raise DiffError("invalid evidence rule name")
            if not isinstance(entry, dict):
                raise DiffError("invalid report rule evidence")
            matches = entry.get("matches")
            if not isinstance(matches, list) or any(
                not isinstance(match, dict) for match in matches
            ):
                raise DiffError("evidence matches must be an array")
            if (
                type(entry.get("complete")) is not bool
                or type(entry.get("source_available")) is not bool
                or not isinstance(entry.get("source_digest"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", entry["source_digest"])
            ):
                raise DiffError("invalid evidence identity or completeness")
            actual = fingerprint(matches)
            if entry.get("fingerprint") != actual:
                raise DiffError("evidence fingerprint does not match the retained data")
            result.setdefault(name, {})[label] = (
                actual,
                entry["complete"],
                entry["source_digest"],
                entry["source_available"],
            )
    return result


def _rule_source(finding: dict, evidence: dict) -> str | None:
    digest = finding.get("source_digest")
    if (
        finding.get("source_available", True)
        and isinstance(digest, str)
        and re.fullmatch(r"[0-9a-f]{64}", digest)
    ):
        return digest
    sources = {entry[2] for entry in evidence.values() if entry[3]}
    return next(iter(sources)) if len(sources) == 1 else None


def _case_metadata(report: dict) -> dict:
    metadata = report.get("metadata", {})
    if not isinstance(metadata, dict) or not isinstance(metadata.get("case", {}), dict):
        raise DiffError("invalid saved-report case metadata")
    return metadata.get("case", {})


def _context(report: dict, view: dict, shared: set[str]) -> dict:
    provenance = report.get("provenance", {})
    if not isinstance(provenance, dict) or not isinstance(
        provenance.get("runs", {}), dict
    ):
        raise DiffError("invalid report provenance")
    context = {}
    for label, source in [("static", provenance.get("static", {}))] + [
        ("run:" + label, provenance.get("runs", {}).get(label, {}))
        for label in sorted(shared)
    ]:
        if not isinstance(source, dict):
            raise DiffError("invalid source provenance")
        if label == "static":
            base = source.get("base_address")
            if base is not None and (type(base) is not int or base < 0):
                raise DiffError("invalid static image base")
            context["static:base_address"] = base
            context["static:base_address_recorded"] = "base_address" in source
        for key in (
            "sample_sha256",
            "capa_version",
            "extractor",
            "format",
            "arch",
            "os",
        ):
            context[label + ":" + key] = source.get(key)
        argv = source.get("argv")
        if isinstance(argv, list):
            restrictions = []
            for index, arg in enumerate(argv):
                if isinstance(arg, str) and (
                    arg in {"-t", "--tag"}
                    or arg.startswith("--restrict-to-")
                    or arg.startswith("--tag=")
                    or (arg.startswith("-t") and not arg.startswith("--"))
                ):
                    restrictions.append(
                        [
                            arg,
                            argv[index + 1]
                            if "=" not in arg and index + 1 < len(argv)
                            else None,
                        ]
                    )
            context[label + ":restrictions"] = restrictions
        else:
            context[label + ":restrictions"] = None
    options = report.get("metadata", {})
    if not isinstance(options, dict):
        raise DiffError("report metadata must be an object")
    context["include_library"] = options.get("include_library_rules")
    manifest = options.get("ruleset_manifest")
    context["ruleset_manifest"] = (
        manifest.get("fingerprint") if isinstance(manifest, dict) else None
    )
    context["static_capa_version"] = view["metadata"].get("static_capa_version")
    context["sample_sha256"] = view["sample"].lower()
    context["confidence"] = view["metadata"].get("confidence")
    if view["kind"] == "matrix":
        baseline = view["metadata"].get("experiment_baseline")
        if baseline is not None and (
            not isinstance(baseline, str) or baseline not in view["labels"]
        ):
            raise DiffError("invalid experiment baseline")
        context["experiment_baseline"] = baseline
        # Appending a run is a run-set change; reordering shared runs changes
        # incremental contributions even if their observations are identical.
        context["shared_run_order"] = [
            label for label in view["labels"] if label in shared
        ]
        runs = report.get("runs", [])
        if not isinstance(runs, list) or any(
            not isinstance(run, dict)
            or not isinstance(run.get("label"), str)
            or not isinstance(run.get("conditions", {}), dict)
            for run in runs
        ):
            raise DiffError("invalid saved-report run metadata")
        for run in runs:
            if run["label"] in shared:
                context["run:" + run["label"] + ":conditions"] = run.get(
                    "conditions", {}
                )
    else:
        case = _case_metadata(report)
        context["case_run_labels"] = case.get("run_labels")
        context["case_conditions"] = case.get("conditions")
    return context


def compare_reports(
    before: dict, after: dict, *, allow_mismatch: bool = False
) -> dict[str, Any]:
    old, new = _view(before), _view(after)
    if old["kind"] != new["kind"]:
        raise DiffError("compare reports of the same type (single-run or matrix)")

    def valid_hash(value):
        return bool(re.fullmatch(r"[0-9a-fA-F]{64}", value))

    identity_known = valid_hash(old["sample"]) and valid_hash(new["sample"])
    same_sample = identity_known and old["sample"].lower() == new["sample"].lower()
    if identity_known and not same_sample and not allow_mismatch:
        raise DiffError(
            "saved reports describe different samples; use --allow-mismatch only intentionally"
        )
    shared = set(old["labels"]) & set(new["labels"])
    before_evidence, after_evidence = _evidence_index(before), _evidence_index(after)
    context_old, context_new = (
        _context(before, old, shared),
        _context(after, new, shared),
    )
    context_changes = [
        {"field": key, "before": context_old.get(key), "after": context_new.get(key)}
        for key in sorted(context_old.keys() | context_new.keys())
        if context_old.get(key) != context_new.get(key)
    ]
    warnings = []
    if (
        not context_old["static:base_address_recorded"]
        or not context_new["static:base_address_recorded"]
    ):
        warnings.append(
            "A report lacks image-base provenance; equivalence of portable addresses is unverified."
        )
    if old["kind"] == "matrix" and (
        context_old["experiment_baseline"] is None
        or context_new["experiment_baseline"] is None
    ):
        warnings.append(
            "A report lacks an experiment baseline; baseline equivalence is unverified."
        )
    if not same_sample:
        warnings.append(
            "Sample identity is unverified or different; changes are not attributed to behavior."
        )
    if not before.get("provenance") or not after.get("provenance"):
        warnings.append(
            "A report predates detailed provenance; analysis-context equivalence cannot be established."
        )
    elif any(
        value in (None, "", "unknown")
        for key, value in context_old.items()
        if key.endswith((":extractor", ":capa_version", ":restrictions"))
    ) or any(
        value in (None, "", "unknown")
        for key, value in context_new.items()
        if key.endswith((":extractor", ":capa_version", ":restrictions"))
    ):
        warnings.append(
            "Analysis provenance is incomplete; equivalence of extraction settings is unverified."
        )
    changes = []
    for name in sorted(old["findings"].keys() | new["findings"].keys()):
        prior, current = old["findings"].get(name), new["findings"].get(name)
        if prior is None or current is None:
            changes.append(
                {
                    "name": name,
                    "kind": "finding-added" if prior is None else "finding-removed",
                    "before_status": prior["status"] if prior else None,
                    "after_status": current["status"] if current else None,
                }
            )
            continue
        relevant = {"static", *("run:" + label for label in shared)}
        evidence_old = {
            key: entry
            for key, entry in before_evidence.get(name, {}).items()
            if key in relevant
        }
        evidence_new = {
            key: entry
            for key, entry in after_evidence.get(name, {}).items()
            if key in relevant
        }
        old_source = _rule_source(prior, before_evidence.get(name, {}))
        new_source = _rule_source(current, after_evidence.get(name, {}))
        source_known = (
            old_source is not None
            and new_source is not None
            and all(
                entry[3] for entry in (*evidence_old.values(), *evidence_new.values())
            )
        )
        gained = sorted(
            (set(current["observed_in"]) - set(prior["observed_in"])) & shared
        )
        lost = sorted(
            (set(prior["observed_in"]) - set(current["observed_in"])) & shared
        )
        evidence_changed = evidence_old != evidence_new
        statuses_changed = prior["status"] != current["status"]
        source_changed = source_known and old_source != new_source
        drift = source_known and (
            any(entry[2] != old_source for entry in evidence_old.values())
            or any(entry[2] != new_source for entry in evidence_new.values())
        )
        added_observations = sorted(set(current["observed_in"]) - set(old["labels"]))
        removed_observations = sorted(set(prior["observed_in"]) - set(new["labels"]))
        if not (
            gained
            or lost
            or evidence_changed
            or statuses_changed
            or source_changed
            or added_observations
            or removed_observations
        ):
            continue
        if source_changed or drift:
            kind = "rule-changed"
        elif not source_known:
            kind = "source-unverified"
        elif context_changes or not same_sample or warnings:
            kind = "analysis-context-changed"
        elif gained or lost:
            kind = "observation-changed"
        elif added_observations or removed_observations:
            kind = "run-set-changed"
        elif statuses_changed:
            kind = "classification-changed"
        else:
            kind = "evidence-changed"
        changes.append(
            {
                "name": name,
                "kind": kind,
                "before_status": prior["status"],
                "after_status": current["status"],
                "gained_in": gained,
                "lost_from": lost,
                "observed_in_added_runs": added_observations,
                "observed_in_removed_runs": removed_observations,
                "evidence_changed": evidence_changed,
                "before_source_digest": old_source,
                "after_source_digest": new_source,
            }
        )
    added_runs = sorted(set(new["labels"]) - set(old["labels"]))
    removed_runs = sorted(set(old["labels"]) - set(new["labels"]))
    old_case, new_case = _case_metadata(before), _case_metadata(after)
    review_changes = [
        {"field": key, "before": old_case.get(key), "after": new_case.get(key)}
        for key in ("name", "notes")
        if old_case.get(key) != new_case.get(key)
    ]
    return {
        "schema": "capagap-diff",
        "schema_version": 1,
        "changed": bool(
            changes or context_changes or added_runs or removed_runs or review_changes
        ),
        "sample_sha256": new["sample"],
        "same_sample_verified": same_sample,
        "runs": {
            "shared": sorted(shared),
            "added": added_runs,
            "removed": removed_runs,
        },
        "context_changes": context_changes,
        "review_changes": review_changes,
        "warnings": warnings,
        "changes": changes,
        "summary": {
            kind: sum(item["kind"] == kind for item in changes)
            for kind in sorted({item["kind"] for item in changes})
        },
        "interpretation": "Observation changes describe result documents, not proof of changed execution or causality. Rule and analysis-context changes are reported separately.",
    }


def render_diff(result: dict[str, Any], *, markdown: bool = False) -> str:
    def clean(value: Any) -> str:
        text = " ".join(str(value).split())
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("|", "\\|")
            if markdown
            else text
        )

    lines = [
        ("# " if markdown else "") + "CapaGap report diff",
        "",
        "Changes found." if result["changed"] else "No changes found.",
    ]
    for key in ("added", "removed"):
        if result["runs"][key]:
            lines.append(f"Runs {key}: " + ", ".join(map(clean, result["runs"][key])))
    for item in result["context_changes"]:
        lines.append(
            f"- Context {clean(item['field'])}: {clean(item['before'])} -> {clean(item['after'])}"
        )
    for item in result["review_changes"]:
        lines.append(
            f"- Case {clean(item['field'])}: {clean(item['before'])} -> {clean(item['after'])}"
        )
    for item in result["changes"]:
        lines.append(
            f"- {item['kind']}: {clean(item['name'])} ({clean(item['before_status'])} -> {clean(item['after_status'])})"
        )
        if item.get("gained_in"):
            lines.append(
                "  Newly observed in: " + ", ".join(map(clean, item["gained_in"]))
            )
        if item.get("lost_from"):
            lines.append(
                "  No longer observed in: " + ", ".join(map(clean, item["lost_from"]))
            )
    lines.extend(["", *result["warnings"], result["interpretation"], ""])
    return "\n".join(lines)
