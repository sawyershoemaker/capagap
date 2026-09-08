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
        or case["schema_version"] != 1
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
