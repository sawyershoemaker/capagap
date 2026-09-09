"""Read-only diagnostics for the running interpreter and its CLI installation."""

from __future__ import annotations

import os
import shutil
import site
import sys
import sysconfig
from importlib import metadata
from pathlib import Path
from typing import Any

from capagap import __version__


def inspect_installation() -> dict[str, Any]:
    """Inspect metadata and PATH without launching tools or changing settings."""
    diagnostics = []

    def warn(code, message, recommendation):
        diagnostics.append(
            {
                "code": code,
                "severity": "warning",
                "message": message,
                "recommendation": recommendation,
            }
        )

    scripts = Path(sysconfig.get_path("scripts")).resolve()
    distribution_version = None
    entry_point = None
    try:
        distribution = metadata.distribution("capagap")
        distribution_version = distribution.version
        entry_point = next(
            (
                entry.value
                for entry in distribution.entry_points
                if entry.group == "console_scripts" and entry.name == "capagap"
            ),
            None,
        )
        location = Path(distribution.locate_file("")).resolve()
        user_sites = site.getusersitepackages()
        if isinstance(user_sites, str):
            user_sites = [user_sites]
        if any(location.is_relative_to(Path(value).resolve()) for value in user_sites):
            scripts = Path(
                sysconfig.get_path(
                    "scripts", scheme=sysconfig.get_preferred_scheme("user")
                )
            ).resolve()
        if distribution_version != __version__:
            warn(
                "version-mismatch",
                "Loaded code and installed distribution metadata have different versions.",
                "Check editable installs and use the intended interpreter's -m pip to reinstall.",
            )
        if entry_point != "capagap.cli:main":
            warn(
                "entry-point-missing",
                "Package metadata does not declare the expected capagap command.",
                "Reinstall the intended CapaGap version using this interpreter's -m pip.",
            )
    except metadata.PackageNotFoundError:
        warn(
            "metadata-unavailable",
            "CapaGap code is importable, but installation metadata is unavailable.",
            "Install the source checkout with this interpreter's -m pip install .",
        )
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        warn(
            "metadata-unreadable",
            f"Could not inspect installation metadata: {exc}",
            "Check the installation with this interpreter's -m pip show capagap.",
        )
    expected = scripts / ("capagap.exe" if os.name == "nt" else "capagap")
    launcher = shutil.which("capagap")
    if not expected.is_file():
        warn(
            "launcher-missing",
            "The expected launcher file is absent from this interpreter's Scripts directory.",
            "Use this interpreter with -m capagap, or reinstall the intended package version.",
        )
    if launcher is None:
        warn(
            "command-not-on-path",
            "The capagap command cannot be found through this process's PATH.",
            f"Activate the Python environment or add {scripts} to PATH, then reopen your terminal. The -m capagap form remains available.",
        )
    elif Path(launcher).resolve() != expected.resolve():
        warn(
            "different-launcher",
            "PATH resolves capagap to a different launcher; it may use another Python installation.",
            "Activate the intended environment or run this interpreter with -m capagap.",
        )
    return {
        "schema": "capagap-doctor",
        "schema_version": 1,
        "passed": not diagnostics,
        "python": {
            "executable": sys.executable,
            "version": sys.version.split()[0],
            "prefix": sys.prefix,
            "virtual_environment": sys.prefix != sys.base_prefix,
            "user_site_enabled": site.ENABLE_USER_SITE is True,
        },
        "package": {
            "version": __version__,
            "metadata_version": distribution_version,
            "entry_point": entry_point,
            "location": str(Path(__file__).resolve().parent),
        },
        "command": {
            "resolved": launcher,
            "expected": str(expected),
            "scripts_directory": str(scripts),
            "verification": "path-and-metadata-only",
        },
        "optional_tools": [
            {"name": "capa", "resolved": shutil.which("capa"), "required": False}
        ],
        "diagnostics": diagnostics,
        "interpretation": "No environment changes or tool execution performed. PATH checks cannot inspect shell aliases or verify a launcher's interpreter. capa is only needed to produce new analysis inputs, not to read existing result documents or run the demo.",
    }


def render_doctor(result: dict[str, Any], *, markdown: bool = False) -> str:
    def clean(value):
        text = " ".join(str(value).split())
        return (
            text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            if markdown
            else text
        )

    lines = [
        ("## " if markdown else "") + "CapaGap installation",
        "",
        f"Python: {clean(result['python']['executable'])} ({clean(result['python']['version'])})",
        f"CapaGap: {clean(result['package']['version'])}",
        f"Command: {clean(result['command']['resolved'] or 'not on PATH')}",
        f"Scripts: {clean(result['command']['scripts_directory'])}",
        "",
    ]
    if not result["diagnostics"]:
        lines.append("No installation issues found in metadata or PATH.")
    for item in result["diagnostics"]:
        lines.extend(
            [
                f"- {item['code']}: {clean(item['message'])}",
                "  " + clean(item["recommendation"]),
            ]
        )
    for tool in result["optional_tools"]:
        lines.append(
            f"Optional {tool['name']}: {clean(tool['resolved'] or 'not on PATH')}"
        )
    lines.extend(["", result["interpretation"]])
    return "\n".join(lines) + "\n"
