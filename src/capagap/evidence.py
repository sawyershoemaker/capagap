"""Bounded, data-only views of capa's match trees and matched layout."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Callable

MAX_MATCHES = 2048
MAX_NODES = 50_000
MAX_DEPTH = 32
MAX_ITEMS = 128
MAX_TEXT = 8192


@dataclass
class EvidenceBudget:
    remaining: int = MAX_NODES
    truncated: bool = False
    malformed: bool = False


def _text(value: Any, budget: EvidenceBudget) -> str:
    if not isinstance(value, (str, int, float, bool)) and value is not None:
        budget.malformed = True
        return "[invalid text]"
    result = str(value)
    if len(result) > MAX_TEXT:
        budget.truncated = True
        return result[:MAX_TEXT] + "…"
    return result


def _items(value: Any, budget: EvidenceBudget) -> list:
    if not isinstance(value, list):
        budget.malformed = True
        return []
    if len(value) > MAX_ITEMS:
        budget.truncated = True
    return value[:MAX_ITEMS]


def _data(value: Any, budget: EvidenceBudget, depth: int = 0) -> Any:
    if isinstance(value, str):
        return _text(value, budget)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if depth >= 4:
        budget.truncated = True
        return "[nested value omitted]"
    if isinstance(value, dict):
        if len(value) > 32:
            budget.truncated = True
        return {
            _text(key, budget): _data(item, budget, depth + 1)
            for key, item in list(value.items())[:32]
        }
    if isinstance(value, list):
        return [_data(item, budget, depth + 1) for item in _items(value, budget)]
    return _text(value, budget)


def layout_context(
    layout: Any, normalize: Callable, budget: EvidenceBudget
) -> dict[str, dict[str, str]]:
    """Index only explicitly recorded containment; never infer a call graph."""
    contexts: dict[str, dict[str, str]] = {}
    remaining = MAX_NODES
    if not isinstance(layout, dict):
        return contexts

    def records(value: Any):
        nonlocal remaining
        if not isinstance(value, list):
            budget.malformed = True
            return
        for record in value:
            if remaining <= 0:
                budget.truncated = True
                return
            remaining -= 1
            if isinstance(record, dict):
                yield record
            else:
                budget.malformed = True

    def address(record: dict) -> str:
        return normalize(record.get("address")).display

    for function in records(layout.get("functions", [])):
        parent = address(function)
        contexts[parent] = {"function": parent}
        for block in records(function.get("matched_basic_blocks", [])):
            contexts[address(block)] = {"function": parent}
    for process in records(layout.get("processes", [])):
        context = {
            "process": address(process),
            "process_name": _text(process.get("name", ""), budget),
        }
        contexts[address(process)] = context
        for thread in records(process.get("matched_threads", [])):
            thread_context = {**context, "thread": address(thread)}
            contexts[address(thread)] = thread_context
            for call in records(thread.get("matched_calls", [])):
                contexts[address(call)] = {
                    **thread_context,
                    "call_name": _text(call.get("name", ""), budget),
                }
    return contexts


def parse_matches(
    matches: Any, normalize: Callable, contexts: dict, budget: EvidenceBudget
) -> tuple[dict[str, Any], ...]:
    def location(raw: Any) -> dict:
        address = normalize(raw)
        return {**address.to_dict(), "context": contexts.get(address.display, {})}

    def node(raw: Any, depth: int = 0) -> dict | None:
        if not isinstance(raw, dict):
            budget.malformed = True
            return None
        if "node" not in raw:
            return None  # Older/minimal results may contain only match locations.
        if depth >= MAX_DEPTH or budget.remaining <= 0:
            budget.truncated = True
            return {"kind": "omitted", "label": "Evidence limit reached"}
        budget.remaining -= 1
        descriptor = raw.get("node")
        if not isinstance(descriptor, dict):
            budget.malformed = True
            return None
        kind = descriptor.get("type")
        if not isinstance(kind, str) or kind not in {"feature", "statement"}:
            budget.malformed = True
            return None
        details = descriptor.get(kind)
        if not isinstance(details, dict):
            budget.malformed = True
            return None
        clean = _data(details, budget)
        name = str(clean.get("type", kind))
        value = clean.get(name)
        if name == "subscope":
            value = clean.get("scope")
        label = name if value is None else f"{name}: {value}"
        if name == "range":
            label = f"count: {clean.get('min', '?')} to {clean.get('max', '?')} · {clean.get('child', '')}"
        success = raw.get("success")
        if not isinstance(success, bool):
            success = None
            budget.malformed = True
        captures = raw.get("captures", {})
        if not isinstance(captures, dict):
            budget.malformed = True
            captures = {}
        if len(captures) > 32:
            budget.truncated = True
        return {
            "kind": kind,
            "label": _text(label, budget),
            "success": success,
            "details": clean,
            "locations": [
                location(item) for item in _items(raw.get("locations", []), budget)
            ],
            "captures": {
                _text(key, budget): [location(item) for item in _items(values, budget)]
                for key, values in list(captures.items())[:32]
            },
            "children": [
                child
                for item in _items(raw.get("children", []), budget)
                if (child := node(item, depth + 1)) is not None
            ],
        }

    if not isinstance(matches, list):
        budget.malformed = True
        return ()
    if len(matches) > MAX_MATCHES:
        budget.truncated = True
    result = []
    for match in matches[:MAX_MATCHES]:
        if not isinstance(match, list) or not match:
            budget.malformed = True
            continue
        result.append(
            {
                "address": location(match[0]),
                "tree": node(match[1]) if len(match) > 1 else None,
            }
        )
    return tuple(result)


def fingerprint(matches: tuple | list) -> str:
    return hashlib.sha256(
        json.dumps(
            matches, sort_keys=True, ensure_ascii=True, separators=(",", ":")
        ).encode()
    ).hexdigest()


def search_terms(matches: tuple | list) -> str:
    """Search the bounded view, including API labels and process names."""
    return json.dumps(matches, ensure_ascii=False)
