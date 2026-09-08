"""Strict JSON decoding shared by externally supplied result documents."""

from __future__ import annotations

import json
import math
from itertools import chain
from pathlib import Path
from typing import Any


def decode_json(raw: bytes) -> Any:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key!r}")
            result[key] = value
        return result

    def nonfinite(value):
        raise ValueError(f"non-finite JSON number: {value}")

    def finite_float(value):
        result = float(value)
        if not math.isfinite(result):
            nonfinite(value)
        return result

    result = json.loads(
        raw.decode("utf-8-sig"),
        object_pairs_hook=pairs,
        parse_constant=nonfinite,
        parse_float=finite_float,
    )
    # Escaped, unpaired surrogates are accepted by json.loads but cannot be
    # hashed or written as UTF-8. Check strings without recursing in Python.
    pending = [iter((result,))]
    while pending:
        try:
            value = next(pending[-1])
        except StopIteration:
            pending.pop()
            continue
        if isinstance(value, str):
            value.encode("utf-8")
        elif isinstance(value, dict):
            pending.append(chain(value.keys(), value.values()))
        elif isinstance(value, list):
            pending.append(iter(value))
    return result


def read_json(path: Path, limit: int) -> Any:
    """Read at most the caller's byte limit before strict decoding."""
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError(f"JSON input exceeds {limit // (1024 * 1024)} MiB")
    return decode_json(raw)
