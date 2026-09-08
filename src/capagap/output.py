"""Input-preserving output checks and atomic report replacement."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Iterable
from pathlib import Path


def check_output(output: str | Path, forbidden: Iterable[str | Path] = ()) -> None:
    destination = Path(output)
    resolved = destination.resolve()
    for value in forbidden:
        source = Path(value)
        if resolved == source.resolve() or (
            destination.exists() and source.exists() and destination.samefile(source)
        ):
            raise OSError(f"output would overwrite an input: {source}")


def write_text(
    output: str | Path, content: str, *, forbidden: Iterable[str | Path] = ()
) -> None:
    """Replace a completed report, leaving existing bytes intact on write failure."""
    destination = Path(output)
    protected = tuple(forbidden)
    check_output(destination, protected)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=".capagap-",
            suffix=".tmp",
            dir=destination.parent,
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(content)
        check_output(destination, protected)
        os.replace(temporary, destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
