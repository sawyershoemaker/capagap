"""A self-contained synthetic case for trying an installed CapaGap package."""

from __future__ import annotations

import json
import tempfile
from importlib.resources import files
from pathlib import Path

from capagap.cases import CaseError, create_case, load_case, relocate_comparison
from capagap.html_report import render_matrix_html
from capagap.output import write_text


def create_demo(destination: str | Path) -> Path:
    """Write a complete demo or leave the requested destination untouched."""
    target = Path(destination).absolute()
    if target.exists() or target.is_symlink():
        raise CaseError(
            "demo destination already exists; choose a new --output directory"
        )
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".capagap-demo-", dir=target.parent
    ) as temporary:
        root = Path(temporary)
        for name in ("static", "baseline", "interactive"):
            content = (
                files("capagap").joinpath("demo_data", name + ".json").read_bytes()
            )
            (root / (name + ".json")).write_bytes(content)
        staged = root / "demo"
        create_case(
            root / "static.json",
            [
                ("baseline", root / "baseline.json"),
                ("interactive", root / "interactive.json"),
            ],
            staged / "case",
            name="CapaGap demo",
            notes="Synthetic result documents. No executable samples are included.",
            conditions=[
                ("baseline", "interaction", "off"),
                ("interactive", "interaction", "on"),
            ],
        )
        _, comparison = load_case(staged / "case")
        comparison = relocate_comparison(comparison, staged.resolve(), target.resolve())
        write_text(staged / "report.html", render_matrix_html(comparison))
        write_text(
            staged / "report.json",
            json.dumps(comparison.to_dict(), indent=2, ensure_ascii=True) + "\n",
        )
        if target.exists() or target.is_symlink():
            raise CaseError("demo destination appeared during generation")
        staged.rename(target)
    return target / "report.html"
