"""Bounded directory analysis with explicit sample matching and staged output."""

from __future__ import annotations

import json
import os
import re
import tempfile
from collections import defaultdict
from dataclasses import replace
from pathlib import Path
from typing import Any

from capagap.analysis import ComparisonError
from capagap.cases import CaseError, create_case, load_case, relocate_comparison
from capagap.diagnostics import ValidationError, require_valid
from capagap.html_report import render_html, render_matrix_html
from capagap.io import DocumentError, load_document
from capagap.manifest import ManifestError, load_ruleset_manifest
from capagap.models import MatrixComparison
from capagap.output import write_text
from capagap.render import (
    render_markdown,
    render_matrix_markdown,
    render_matrix_text,
    render_text,
)

MAX_INPUTS = 1000
MAX_DISCOVERY_ENTRIES = 10000


class BatchError(ValueError):
    """A directory batch cannot be processed safely."""


def _discover(root: Path, recursive: bool) -> tuple[list[Path], list[dict]]:
    paths, rejected = [], []
    scanned = 0

    def traversal_error(error):
        raise BatchError(f"could not enumerate inputs: {error}") from error

    for directory, directories, files in os.walk(
        root, onerror=traversal_error, followlinks=False
    ):
        scanned += len(directories) + len(files)
        if scanned > MAX_DISCOVERY_ENTRIES:
            raise BatchError(
                f"input discovery exceeds {MAX_DISCOVERY_ENTRIES} directory entries"
            )
        directories.sort()
        allowed = []
        for name in directories:
            path = Path(directory) / name
            if path.is_symlink() or path.resolve() != path.absolute():
                if recursive:
                    rejected.append(
                        {
                            "input": path.relative_to(root).as_posix(),
                            "reason": "Linked directories are not traversed.",
                        }
                    )
            elif recursive:
                allowed.append(name)
        directories[:] = allowed
        for name in sorted(files):
            if not name.lower().endswith((".json", ".json.gz")):
                continue
            path = Path(directory) / name
            if path.is_symlink() or not path.resolve().is_relative_to(root):
                rejected.append(
                    {
                        "input": path.relative_to(root).as_posix(),
                        "reason": "Linked or escaping inputs are not followed.",
                    }
                )
                continue
            if not path.is_file():
                continue
            paths.append(path)
            if len(paths) > MAX_INPUTS:
                raise BatchError(f"batch supports at most {MAX_INPUTS} result inputs")
    return sorted(paths, key=lambda path: path.relative_to(root).as_posix()), rejected


def _render(comparison, report_format: str) -> str:
    matrix = isinstance(comparison, MatrixComparison)
    if report_format == "html":
        return (render_matrix_html if matrix else render_html)(comparison)
    if report_format == "markdown":
        return (render_matrix_markdown if matrix else render_markdown)(comparison)
    return (render_matrix_text if matrix else render_text)(comparison)


def _markdown(result: dict[str, Any]) -> str:
    def clean(value):
        return (
            " ".join(str(value).split())
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("|", "\\|")
            .replace("[", "\\[")
            .replace("]", "\\]")
            .replace("`", "\\`")
        )

    lines = [
        "# CapaGap batch",
        "",
        f"Completed: {result['summary']['completed']}. Failed samples: {result['summary']['failed']}. Rejected inputs: {len(result['rejected_inputs'])}.",
        "",
        "| Sample SHA-256 | Runs | Coverage | Unobserved | Confidence | Report |",
        "|---|---:|---:|---:|---|---|",
    ]
    for sample in result["samples"]:
        if sample["status"] != "completed":
            continue
        coverage = sample["coverage"]
        percentage = "n/a" if coverage is None else f"{coverage:.1%}"
        lines.append(
            f"| {sample['sample_sha256']} | {sample['run_count']} | {percentage} | {sample['unobserved_count']} | {sample['confidence']} | [Open]({sample['report']}) |"
        )
    lines.extend(
        [
            "",
            "Order follows investigation priority, not severity. Coverage counts comparable capabilities, not executed code. Conditions are undeclared in directory batches; inspect each report's diagnostics.",
        ]
    )
    failures = [sample for sample in result["samples"] if sample["status"] == "failed"]
    if failures or result["rejected_inputs"]:
        lines.extend(["", "## Inputs requiring attention", ""])
        lines.extend(
            f"- {sample['sample_sha256']}: {clean(sample['reason'])}"
            for sample in failures
        )
        lines.extend(
            f"- {clean(item['input'])}: {clean(item['reason'])}"
            for item in result["rejected_inputs"]
        )
    if result["duplicates"]:
        lines.extend(["", "## Duplicate inputs", ""])
        lines.extend(
            f"- {clean(item['input'])}: same content as {clean(item['duplicate_of'])}"
            for item in result["duplicates"]
        )
    return "\n".join(lines) + "\n"


def analyze_directory(
    directory: str | Path,
    destination: str | Path,
    *,
    recursive: bool = False,
    report_format: str = "html",
    ruleset_path: str | Path | None = None,
    include_library: bool = False,
    minimum_features: int = 1,
    strict: bool = False,
) -> dict[str, Any]:
    root = Path(directory).resolve()
    target = Path(destination).absolute()
    if not root.is_dir():
        raise BatchError("batch input must be an existing directory")
    if target.exists() or target.is_symlink():
        raise BatchError("batch output must be a new directory")
    if target.resolve().is_relative_to(root):
        raise BatchError("batch output must be outside the input directory")
    if report_format not in {"html", "json", "markdown", "text"}:
        raise BatchError("unsupported batch report format")
    if minimum_features < 1:
        raise BatchError("minimum features must be at least 1")
    if ruleset_path is not None:
        load_ruleset_manifest(ruleset_path)
    paths, rejected = _discover(root, recursive)
    if not paths and not rejected:
        raise BatchError("no .json or .json.gz inputs found")
    samples: dict[str, dict[str, list]] = defaultdict(
        lambda: {"static": [], "dynamic": []}
    )
    duplicates = []
    identities: dict[str, str] = {}
    for path in paths:
        relative = path.relative_to(root).as_posix()
        try:
            if path.is_symlink() or not path.resolve().is_relative_to(root):
                raise BatchError(
                    "Input reference changed or escaped the input directory."
                )
            document = load_document(path, minimum_features=minimum_features)
            if not re.fullmatch(r"[0-9a-f]{64}", document.sample_sha256):
                raise BatchError(
                    "A valid sample SHA-256 is required for automatic grouping."
                )
            digest = document.provenance["content_sha256"]
            if digest in identities:
                duplicates.append(
                    {"input": relative, "duplicate_of": identities[digest]}
                )
                continue
            identities[digest] = relative
            samples[document.sample_sha256][document.flavor].append(
                {"path": path, "label": relative, "sha256": digest}
            )
        except (DocumentError, BatchError, OSError) as exc:
            rejected.append({"input": relative, "reason": str(exc)})
    result: dict[str, Any] = {
        "schema": "capagap-batch",
        "schema_version": 1,
        "samples": [],
        "rejected_inputs": rejected,
        "duplicates": duplicates,
    }
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".capagap-batch-", dir=target.parent
    ) as temporary:
        staging = Path(temporary) / "batch"
        staging.mkdir()
        for sample_hash, inputs in sorted(samples.items()):
            try:
                if len(inputs["static"]) != 1:
                    raise BatchError(
                        "Exactly one distinct static result is required; no static input is selected automatically."
                    )
                if not inputs["dynamic"]:
                    raise BatchError("No dynamic result with this sample SHA-256.")
                static = inputs["static"][0]
                with tempfile.TemporaryDirectory(
                    prefix=".sample-", dir=staging
                ) as sample_temp:
                    sample_dir = Path(sample_temp) / "sample"
                    manifest = create_case(
                        static["path"],
                        [(run["label"], run["path"]) for run in inputs["dynamic"]],
                        sample_dir / "case",
                        name=sample_hash,
                        ruleset_path=ruleset_path,
                        include_library=include_library,
                    )
                    case, comparison = load_case(
                        manifest, minimum_features=minimum_features
                    )
                    captured = [case["static"], *case["runs"]]
                    discovered = [static, *inputs["dynamic"]]
                    if any(
                        a["sha256"] != b["sha256"] for a, b in zip(captured, discovered)
                    ):
                        raise BatchError(
                            "An input changed after discovery; rerun with stable inputs."
                        )
                    matrix = isinstance(comparison, MatrixComparison)
                    # Batches do not declare experimental conditions. Strictness here
                    # concerns document quality and compatibility, not experiment design.
                    if strict:
                        require_valid(
                            replace(comparison, experiment_warnings=())
                            if matrix
                            else comparison
                        )
                    comparison = relocate_comparison(
                        comparison, sample_dir.resolve(), target.resolve() / sample_hash
                    )
                    payload = (
                        json.dumps(comparison.to_dict(), indent=2, ensure_ascii=True)
                        + "\n"
                    )
                    write_text(sample_dir / "report.json", payload)
                    extension = {
                        "html": "html",
                        "json": "json",
                        "markdown": "md",
                        "text": "txt",
                    }[report_format]
                    if report_format != "json":
                        write_text(
                            sample_dir / f"report.{extension}",
                            _render(comparison, report_format),
                        )
                    gaps = (
                        comparison.never_observed if matrix else comparison.unobserved
                    )
                    summary = comparison.summary
                    row = {
                        "sample_sha256": sample_hash,
                        "status": "completed",
                        "case_id": case["id"],
                        "run_count": len(case["runs"]),
                        "run_labels": [r["label"] for r in case["runs"]],
                        "coverage": summary.union_coverage
                        if matrix
                        else summary.observed_coverage,
                        "unobserved_count": len(gaps),
                        "maximum_priority": max((g.priority for g in gaps), default=0),
                        "confidence": comparison.confidence,
                        "case": f"{sample_hash}/case/case.json",
                        "report": f"{sample_hash}/report.{extension}",
                        "json_report": f"{sample_hash}/report.json",
                    }
                    sample_dir.rename(staging / sample_hash)
                    result["samples"].append(row)
            except (
                BatchError,
                CaseError,
                ComparisonError,
                DocumentError,
                ManifestError,
                ValidationError,
                OSError,
            ) as exc:
                result["samples"].append(
                    {
                        "sample_sha256": sample_hash,
                        "status": "failed",
                        "reason": str(exc),
                    }
                )
        result["samples"].sort(
            key=lambda row: (
                row["status"] != "completed",
                -row.get("maximum_priority", 0),
                -row.get("unobserved_count", 0),
                row["sample_sha256"],
            )
        )
        completed = sum(row["status"] == "completed" for row in result["samples"])
        result["summary"] = {
            "completed": completed,
            "failed": len(result["samples"]) - completed,
            "rejected_inputs": len(rejected),
            "duplicate_inputs": len(duplicates),
        }
        write_text(
            staging / "index.json",
            json.dumps(result, indent=2, ensure_ascii=True) + "\n",
        )
        write_text(staging / "index.md", _markdown(result))
        if target.exists() or target.is_symlink():
            raise BatchError("batch destination appeared during processing")
        staging.rename(target)
    return result
