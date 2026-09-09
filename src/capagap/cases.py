"""Portable, hash-pinned analysis cases containing result documents, not samples."""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
from dataclasses import replace
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from capagap.analysis import compare_documents
from capagap.io import MAX_INPUT_BYTES, _read_bytes, load_document
from capagap.jsonio import decode_json
from capagap.manifest import load_ruleset_manifest
from capagap.matrix import compare_matrix
from capagap.models import MatrixComparison

MAX_CASE_BYTES = 2 * 1024 * 1024
MAX_RUNS = 128


class CaseError(ValueError):
    """A case is malformed, changed, or unsafe to resolve."""


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(chunk)
            if size > MAX_INPUT_BYTES:
                raise CaseError("pinned input exceeds the 256 MiB limit")
            digest.update(chunk)
    return digest.hexdigest()


def _identity(case: dict) -> str:
    identity = {key: case.get(key) for key in ("static", "runs", "ruleset", "options")}
    if case.get("schema_version") == 2:
        identity["history"] = case.get("history")
    return hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _resolve(root: Path, entry: Any) -> Path:
    if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
        raise CaseError("case input reference must contain a relative path")
    name = entry["path"]
    if (
        not name
        or "\\" in name
        or ":" in name
        or "\0" in name
        or PureWindowsPath(name).drive
        or PurePosixPath(name).is_absolute()
        or ".." in PurePosixPath(name).parts
    ):
        raise CaseError("case input paths must stay within the case directory")
    path = (root / name).resolve()
    if not path.is_relative_to(root.resolve()) or not path.is_file():
        raise CaseError(f"case input is missing or outside its directory: {name}")
    expected = entry.get("sha256")
    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise CaseError(f"invalid pinned SHA-256: {name}")
    if _digest(path) != expected:
        raise CaseError(
            f"case input changed: {name}; preserve this case and create a new snapshot"
        )
    return path


def _case_path(path: str | Path) -> Path:
    result = Path(path)
    return result / "case.json" if result.is_dir() else result


def load_case(path: str | Path) -> tuple[dict[str, Any], Any]:
    source = _case_path(path).resolve()
    try:
        with source.open("rb") as stream:
            raw = stream.read(MAX_CASE_BYTES + 1)
        if len(raw) > MAX_CASE_BYTES:
            raise CaseError("case manifest exceeds the 2 MiB limit")
        case = decode_json(raw)
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        raise CaseError(f"could not read case manifest: {exc}") from exc
    if (
        not isinstance(case, dict)
        or case.get("schema") != "capagap-case"
        or type(case.get("schema_version")) is not int
        or case["schema_version"] not in (1, 2)
    ):
        raise CaseError("unsupported case schema")
    for field in ("name", "notes"):
        if not isinstance(case.get(field), str) or len(case[field]) > 32768:
            raise CaseError(f"case {field} must be text of at most 32768 characters")
    runs = case.get("runs")
    if not isinstance(runs, list) or not 1 <= len(runs) <= MAX_RUNS:
        raise CaseError(f"a case requires 1 to {MAX_RUNS} runs")
    labels = set()
    conditions = []
    for run in runs:
        if (
            not isinstance(run, dict)
            or not isinstance(run.get("label"), str)
            or not run["label"].strip()
            or run["label"] != run["label"].strip()
            or len(run["label"]) > 256
            or run["label"] in labels
        ):
            raise CaseError("case run labels must be nonempty, unique text")
        labels.add(run["label"])
        declared = run.get("conditions")
        if (
            not isinstance(declared, dict)
            or len(declared) > 128
            or any(
                not isinstance(key, str) or not key or not isinstance(value, str)
                for key, value in declared.items()
            )
        ):
            raise CaseError("run conditions must map nonempty keys to text values")
        conditions.extend((run["label"], key, value) for key, value in declared.items())
    options = case.get("options")
    if (
        not isinstance(options, dict)
        or set(options) != {"include_library", "allow_mismatch"}
        or any(type(value) is not bool for value in options.values())
    ):
        raise CaseError("invalid case comparison options")
    _validate_history(case)
    if case.get("id") != _identity(case):
        raise CaseError(
            "case configuration differs from its recorded identity; create a new snapshot"
        )
    root = source.parent

    def read_input(entry, flavor):
        document = load_document(_resolve(root, entry), expected_flavor=flavor)
        if document.provenance["content_sha256"] != entry["sha256"]:
            raise CaseError(
                "case input changed while being read or is not plain captured JSON"
            )
        return document

    static = read_input(case.get("static"), "static")
    documents = [(run["label"], read_input(run, "dynamic")) for run in runs]
    manifest = None
    if case.get("ruleset") is not None:
        manifest = load_ruleset_manifest(_resolve(root, case["ruleset"]))
        if manifest.fingerprint != case["ruleset"].get("fingerprint"):
            raise CaseError("ruleset fingerprint differs from the case")
    arguments = {**options, "ruleset_manifest": manifest}
    if len(documents) == 1:
        comparison = compare_documents(static, documents[0][1], **arguments)
    else:
        comparison = compare_matrix(
            static, documents, experiment_conditions=conditions, **arguments
        )
    metadata = {
        **comparison.metadata,
        "case": {
            "id": case["id"],
            "name": case["name"],
            "notes": case["notes"],
            "run_labels": [run["label"] for run in runs],
            "conditions": {run["label"]: run["conditions"] for run in runs},
            "inputs_verified": True,
            "revision": len(case.get("history", [])) + 1,
            "parent_id": case.get("history", [{}])[-1].get("id")
            if case.get("history")
            else None,
        },
    }
    return case, replace(comparison, metadata=metadata)


def create_case(
    static_path: str | Path,
    runs: list[tuple[str, Path]],
    destination: str | Path,
    *,
    name: str = "Analysis case",
    notes: str = "",
    conditions: list[tuple[str, str, str]] | tuple = (),
    ruleset_path: str | Path | None = None,
    include_library: bool = False,
    allow_mismatch: bool = False,
) -> Path:
    target = Path(destination).absolute()
    if target.exists() or target.is_symlink():
        raise CaseError(f"case destination already exists: {target}")
    if not 1 <= len(runs) <= MAX_RUNS:
        raise CaseError(f"a case requires 1 to {MAX_RUNS} runs")
    if len({label for label, _ in runs}) != len(runs) or any(
        not label.strip() or label != label.strip() for label, _ in runs
    ):
        raise CaseError("case run labels must be nonempty, unique and trimmed")
    declared: dict[str, dict[str, str]] = {label: {} for label, _ in runs}
    for label, key, value in conditions:
        if label not in declared or not key or key in declared[label]:
            raise CaseError("condition has an unknown run, empty key or duplicate key")
        declared[label][key] = value
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".capagap-case-", dir=target.parent
    ) as temporary:
        staging = Path(temporary) / "case"
        (staging / "inputs").mkdir(parents=True)

        def capture(path: str | Path, filename: str, flavor: str | None) -> dict:
            source = Path(path)
            content = _read_bytes(source)
            if flavor:
                document = load_document(source, expected_flavor=flavor)
                if (
                    hashlib.sha256(content).hexdigest()
                    != document.provenance["content_sha256"]
                ):
                    raise CaseError("input changed while the case was being captured")
            # Store decompressed JSON so the portable copy has a stable byte hash.
            relative = "inputs/" + filename
            copied = staging / relative
            copied.write_bytes(content)
            return {"path": relative, "sha256": hashlib.sha256(content).hexdigest()}

        case: dict[str, Any] = {
            "schema": "capagap-case",
            "schema_version": 1,
            "name": name,
            "notes": notes,
            "static": capture(static_path, "static.json", "static"),
            "runs": [
                {
                    **capture(path, f"run-{index:03d}.json", "dynamic"),
                    "label": label,
                    "conditions": declared[label],
                }
                for index, (label, path) in enumerate(runs, 1)
            ],
            "ruleset": None,
            "options": {
                "include_library": include_library,
                "allow_mismatch": allow_mismatch,
            },
        }
        if ruleset_path is not None:
            entry = capture(ruleset_path, "ruleset.json", None)
            entry["fingerprint"] = load_ruleset_manifest(
                staging / entry["path"]
            ).fingerprint
            case["ruleset"] = entry
        case["id"] = _identity(case)
        (staging / "case.json").write_text(
            json.dumps(case, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
        )
        load_case(
            staging
        )  # Verify the exact copied inputs and manifest before exposing it.
        if target.exists() or target.is_symlink():
            raise CaseError("case destination appeared during capture")
        staging.rename(target)
    return target / "case.json"


def _validate_history(case: dict[str, Any]) -> None:
    history = case.get("history", [])
    if not isinstance(case.get("id"), str):
        raise CaseError("case identity must be text")
    if case["schema_version"] == 1:
        if history != []:
            raise CaseError("legacy cases cannot contain revision history")
        return
    if not isinstance(history, list) or not 1 <= len(history) < MAX_RUNS:
        raise CaseError("a revised case requires bounded revision history")
    labels = [run["label"] for run in case["runs"]]
    previous_count = 0
    identities = {case.get("id")}
    for entry in history:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"id", "run_labels"}
            or not isinstance(entry["id"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", entry["id"])
            or entry["id"] in identities
            or not isinstance(entry["run_labels"], list)
            or not previous_count < len(entry["run_labels"]) < len(labels)
            or entry["run_labels"] != labels[: len(entry["run_labels"])]
        ):
            raise CaseError("invalid case revision history")
        identities.add(entry["id"])
        previous_count = len(entry["run_labels"])


def case_history(case: dict[str, Any]) -> dict[str, Any]:
    """Recorded ancestor identities, not authentication of historical snapshots."""
    return {
        "schema": "capagap-case-history",
        "schema_version": 1,
        "revisions": [
            {"revision": index, **entry}
            for index, entry in enumerate(
                [
                    *case.get("history", []),
                    {
                        "id": case["id"],
                        "run_labels": [r["label"] for r in case["runs"]],
                    },
                ],
                1,
            )
        ],
    }


def render_case_history(result: dict[str, Any], *, markdown: bool = False) -> str:
    lines = [("## " if markdown else "") + "Case history", ""]
    for entry in result["revisions"]:
        lines.append(
            f"- Revision {entry['revision']}: {entry['id']} ({len(entry['run_labels'])} runs)"
        )
    lines.append("Ancestor identities are recorded references, not signatures.")
    return "\n".join(lines) + "\n"


def _observations(comparison) -> tuple[set[str], set[str]]:
    if isinstance(comparison, MatrixComparison):
        return (
            {f.rule.name for f in comparison.findings if f.observed_in},
            {f.rule.name for f in comparison.never_observed},
        )
    return (
        {f.rule.name for f in comparison.observed},
        {f.rule.name for f in comparison.unobserved},
    )


def add_case_runs(
    path: str | Path,
    runs: list[tuple[str, Path]],
    destination: str | Path,
    *,
    conditions: list[tuple[str, str, str]] | tuple = (),
    name: str | None = None,
    notes: str | None = None,
) -> tuple[Path, dict[str, Any]]:
    """Append runs into a verified new snapshot without modifying the parent."""
    source = _case_path(path).resolve()
    parent, before = load_case(source)
    target = Path(destination).absolute()
    if target.exists() or target.is_symlink():
        raise CaseError(f"case destination already exists: {target}")
    if target.resolve().is_relative_to(source.parent):
        raise CaseError("a revision must be outside its parent case directory")
    if not runs:
        raise CaseError("a revision requires at least one new run")
    old_labels = {run["label"] for run in parent["runs"]}
    new_labels = {label for label, _ in runs}
    if old_labels & new_labels:
        raise CaseError("new run labels must not replace existing runs")
    if any(label not in new_labels for label, _, _ in conditions):
        raise CaseError("revision conditions may only describe new runs")
    combined = [
        (run["label"], _resolve(source.parent, run)) for run in parent["runs"]
    ] + runs
    declared = [
        (run["label"], key, value)
        for run in parent["runs"]
        for key, value in run["conditions"].items()
    ] + list(conditions)
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".capagap-revision-", dir=target.parent
    ) as temp:
        staged = create_case(
            _resolve(source.parent, parent["static"]),
            combined,
            Path(temp) / "case",
            name=parent["name"] if name is None else name,
            notes=parent["notes"] if notes is None else notes,
            conditions=declared,
            ruleset_path=_resolve(source.parent, parent["ruleset"])
            if parent.get("ruleset")
            else None,
            **parent["options"],
        )
        revised, _ = load_case(staged)
        old_entries = [parent["static"], *parent["runs"]]
        new_entries = [revised["static"], *revised["runs"][: len(parent["runs"])]]
        if parent.get("ruleset"):
            old_entries.append(parent["ruleset"])
            new_entries.append(revised["ruleset"])
        if any(a["sha256"] != b["sha256"] for a, b in zip(old_entries, new_entries)):
            raise CaseError("parent input changed during revision capture")
        revised["schema_version"] = 2
        revised["history"] = [
            *parent.get("history", []),
            {
                "id": parent["id"],
                "run_labels": [run["label"] for run in parent["runs"]],
            },
        ]
        revised["id"] = _identity(revised)
        staged.write_text(json.dumps(revised, indent=2) + "\n", encoding="utf-8")
        _, after = load_case(staged)
        old_observed, _ = _observations(before)
        new_observed, missing = _observations(after)
        delta = {
            "schema": "capagap-case-revision",
            "schema_version": 1,
            "parent_id": parent["id"],
            "case_id": revised["id"],
            "revision": len(revised["history"]) + 1,
            "added_runs": [label for label, _ in runs],
            "newly_observed": sorted(new_observed - old_observed),
            "still_unobserved": sorted(missing),
        }
        if target.exists() or target.is_symlink():
            raise CaseError("case destination appeared during capture")
        staged.parent.rename(target)
    return target / "case.json", delta
