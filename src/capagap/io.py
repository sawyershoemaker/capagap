"""Read and normalize capa result documents."""

from __future__ import annotations

import gzip
import hashlib
import json
import zlib
from dataclasses import replace
from pathlib import Path
from typing import Any, BinaryIO

from capagap.diagnostics import inspect_document
from capagap.evidence import MAX_MATCHES, EvidenceBudget, layout_context, parse_matches
from capagap.jsonio import decode_json
from capagap.models import AddressRecord, CapaDocument, RuleRecord

MAX_INPUT_BYTES = 256 * 1024 * 1024
GZIP_MAGIC = b"\x1f\x8b"


class DocumentError(ValueError):
    """Raised when an input cannot be treated as a capa result document."""


def _read_limited(stream: BinaryIO, limit: int = MAX_INPUT_BYTES) -> bytes:
    data = stream.read(limit + 1)
    if len(data) > limit:
        raise DocumentError(
            f"decompressed input exceeds the {limit // (1024 * 1024)} MiB safety limit"
        )
    return data


def _read_bytes(path: Path) -> bytes:
    try:
        with path.open("rb") as stream:
            prefix = stream.read(2)
            stream.seek(0)
            if prefix == GZIP_MAGIC:
                try:
                    with gzip.GzipFile(fileobj=stream) as compressed:
                        return _read_limited(compressed)
                except (gzip.BadGzipFile, EOFError, OSError, zlib.error) as exc:
                    raise DocumentError(f"invalid gzip stream: {path}") from exc
            return _read_limited(stream)
    except FileNotFoundError as exc:
        raise DocumentError(f"input does not exist: {path}") from exc
    except PermissionError as exc:
        raise DocumentError(f"cannot read input: {path}") from exc
    except OSError as exc:
        raise DocumentError(f"could not read input {path}: {exc}") from exc


def _normalize_address(address: Any) -> AddressRecord:
    if not isinstance(address, dict):
        return AddressRecord(kind="unknown", value=None, display="unknown")

    kind = address.get("type", "unknown")
    if not isinstance(kind, str) or len(kind) > 64:
        return AddressRecord(kind="unknown", value=None, display="invalid address")
    raw_value = address.get("value")
    value: int | tuple[int, ...] | None
    if isinstance(raw_value, bool):
        value = None
    elif isinstance(raw_value, int):
        value = raw_value
    elif (
        isinstance(raw_value, list)
        and len(raw_value) <= 4
        and all(
            isinstance(part, int) and not isinstance(part, bool) for part in raw_value
        )
    ):
        value = tuple(raw_value)
    else:
        value = None

    if value is None:
        display = "global" if raw_value is None else f"{kind}:invalid"
        return AddressRecord(kind=kind, value=value, display=display)
    if kind in {"absolute", "relative"} and isinstance(value, int):
        display = f"0x{value:X}"
    elif kind == "file" and isinstance(value, int):
        display = f"file+0x{value:X}"
    elif kind == "dn token" and isinstance(value, int):
        display = f"token:0x{value:X}"
    elif kind == "dn token offset" and isinstance(value, tuple) and len(value) == 2:
        display = f"token:0x{value[0]:X}+0x{value[1]:X}"
    elif isinstance(value, tuple):
        labels = {
            "process": ("ppid", "pid"),
            "thread": ("ppid", "pid", "tid"),
            "call": ("ppid", "pid", "tid", "call"),
        }.get(kind)
        if labels and len(value) == len(labels):
            display = "/".join(f"{label}:{part}" for label, part in zip(labels, value))
        else:
            display = f"{kind}:{list(value)}"
    else:
        display = f"{kind}:{value}"
    return AddressRecord(kind=kind, value=value, display=display)


def _address_to_text(address: Any) -> str:
    return _normalize_address(address).display


def _normalize_scope(value: Any) -> str | None:
    if value in (None, "", "unsupported"):
        return None
    return str(value)


def _normalize_rule(
    name: str,
    payload: Any,
    *,
    contexts: dict | None = None,
    budget: EvidenceBudget | None = None,
) -> RuleRecord:
    if not isinstance(payload, dict):
        raise DocumentError(f"rule {name!r} is not an object")
    meta = payload.get("meta")
    if not isinstance(meta, dict):
        raise DocumentError(f"rule {name!r} has no metadata object")

    scopes = meta.get("scopes", {})
    if not isinstance(scopes, dict):
        scopes = {}

    attack = meta.get("attack", meta.get("att&ck", []))
    mbc = meta.get("mbc", [])
    if not isinstance(attack, list):
        attack = []
    if not isinstance(mbc, list):
        mbc = []

    evidence_addresses: list[AddressRecord] = []
    matches = payload.get("matches", [])
    if isinstance(matches, list):
        for match in matches[:MAX_MATCHES]:
            if isinstance(match, list) and match:
                evidence_addresses.append(_normalize_address(match[0]))

    evidence = [address.display for address in evidence_addresses[:8]]

    source = payload.get("source", "")
    if not isinstance(source, str):
        source = ""

    document_budget = budget
    local_budget = (
        EvidenceBudget(remaining=budget.remaining)
        if budget is not None
        else EvidenceBudget()
    )
    match_views = parse_matches(
        matches, _normalize_address, contexts or {}, local_budget
    )
    if document_budget is not None:
        document_budget.remaining = local_budget.remaining
        document_budget.truncated |= local_budget.truncated
        document_budget.malformed |= local_budget.malformed
    return RuleRecord(
        name=str(meta.get("name") or name),
        namespace=str(meta.get("namespace") or "uncategorized"),
        static_scope=_normalize_scope(scopes.get("static")),
        dynamic_scope=_normalize_scope(scopes.get("dynamic")),
        attack=tuple(item for item in attack if isinstance(item, dict)),
        mbc=tuple(item for item in mbc if isinstance(item, dict)),
        description=str(meta.get("description") or ""),
        library=bool(meta.get("lib", False)),
        source_digest=hashlib.sha256(
            source.replace("\r\n", "\n").encode("utf-8")
        ).hexdigest(),
        evidence=tuple(evidence),
        evidence_addresses=tuple(evidence_addresses),
        matches=match_views,
        source_available=bool(source.strip()),
        evidence_truncated=local_budget.truncated,
        evidence_malformed=local_budget.malformed,
    )


def _base_address(analysis: dict[str, Any]) -> int | None:
    address = analysis.get("base_address")
    if not isinstance(address, dict) or address.get("type") != "absolute":
        return None
    value = address.get("value")
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


def load_document(
    path: str | Path, *, expected_flavor: str | None = None, minimum_features: int = 1
) -> CapaDocument:
    """Load plain or gzip-compressed capa JSON without importing capa itself."""

    input_path = Path(path)
    raw = _read_bytes(input_path)
    try:
        root = decode_json(raw)
    except UnicodeError as exc:
        raise DocumentError(
            f"input contains invalid Unicode or is not UTF-8 JSON: {input_path}"
        ) from exc
    except RecursionError as exc:
        raise DocumentError(f"JSON nesting is too deep: {input_path}") from exc
    except json.JSONDecodeError as exc:
        raise DocumentError(
            f"invalid JSON in {input_path}: line {exc.lineno}, column {exc.colno}"
        ) from exc
    except ValueError as exc:
        raise DocumentError(f"invalid JSON in {input_path}: {exc}") from exc

    if not isinstance(root, dict):
        raise DocumentError("capa result root must be a JSON object")
    meta = root.get("meta")
    raw_rules = root.get("rules")
    if not isinstance(meta, dict) or not isinstance(raw_rules, dict):
        raise DocumentError(
            "input does not look like a capa result document (expected meta and rules objects)"
        )
    if len(raw_rules) > 50_000:
        raise DocumentError("input exceeds the 50000 rule limit")

    flavor = str(meta.get("flavor", ""))
    if flavor not in {"static", "dynamic"}:
        raise DocumentError(
            f"unsupported or missing capa analysis flavor: {flavor or '<missing>'}"
        )
    if expected_flavor and flavor != expected_flavor:
        raise DocumentError(
            f"expected a {expected_flavor} result, got {flavor}: {input_path}"
        )

    sample = meta.get("sample", {})
    analysis = meta.get("analysis", {})
    if not isinstance(sample, dict):
        sample = {}
    if not isinstance(analysis, dict):
        analysis = {}
    capagap_meta = meta.get("capagap", {})
    synthetic = isinstance(capagap_meta, dict) and capagap_meta.get("synthetic") is True

    budget = EvidenceBudget()
    contexts = layout_context(analysis.get("layout"), _normalize_address, budget)
    rules = {
        str(name): _normalize_rule(str(name), value, contexts=contexts, budget=budget)
        for name, value in raw_rules.items()
    }
    if any(name != rule.name for name, rule in rules.items()):
        raise DocumentError("rule mapping keys must match their metadata names")
    counts = analysis.get("feature_counts")
    count_values = []
    counts_invalid = False
    if isinstance(counts, dict):
        scope_counts = counts.get(
            "functions" if flavor == "static" else "processes", []
        )
        if not isinstance(scope_counts, list):
            counts_invalid = True
            scope_counts = []
        values = [counts.get("file")] + [
            item.get("count") if isinstance(item, dict) else None
            for item in scope_counts
        ]
        for value in values:
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                count_values.append(value)
            else:
                counts_invalid = True
    argv = meta.get("argv")
    if not isinstance(argv, list) or not all(isinstance(arg, str) for arg in argv):
        argv = None
    document = CapaDocument(
        path=input_path.resolve(),
        flavor=flavor,
        capa_version=str(meta.get("version", "unknown")),
        sample_sha256=str(sample.get("sha256", "")).lower(),
        sample_path=str(sample.get("path", "")),
        format=str(analysis.get("format", "unknown")),
        arch=str(analysis.get("arch", "unknown")),
        os=str(analysis.get("os", "unknown")),
        extractor=str(analysis.get("extractor", "unknown")),
        rules=rules,
        base_address=_base_address(analysis),
        synthetic=synthetic,
        provenance={
            "content_sha256": hashlib.sha256(raw).hexdigest(),
            "timestamp": meta.get("timestamp")
            if isinstance(meta.get("timestamp"), str)
            else None,
            "argv": argv,
            "rule_paths": [
                path for path in analysis.get("rules", []) if isinstance(path, str)
            ]
            if isinstance(analysis.get("rules"), list)
            else [],
            "feature_counts": {
                "total": sum(count_values)
                if count_values and not counts_invalid
                else None
            },
            "counts_invalid": counts_invalid,
            "evidence_truncated": budget.truncated,
            "evidence_malformed": budget.malformed,
            "layout_entries": len(contexts),
        },
    )
    return replace(
        document,
        diagnostics=inspect_document(document, minimum_features=minimum_features),
    )
