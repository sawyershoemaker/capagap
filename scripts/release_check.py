"""Check a release and its installed wheel without publishing anything."""

from __future__ import annotations

import argparse
import ast
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run(
    command: list[str],
    *,
    cwd: Path = ROOT,
    include_source: bool = False,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(command), flush=True)
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONHOME", None)
    environment["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    if include_source:
        environment["PYTHONPATH"] = str(ROOT / "src")
    return subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        check=True,
        text=True,
        capture_output=capture,
    )


def source_version() -> str:
    module = ast.parse((ROOT / "src/capagap/__init__.py").read_text(encoding="utf-8"))
    for statement in module.body:
        if isinstance(statement, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "__version__"
            for target in statement.targets
        ):
            value = ast.literal_eval(statement.value)
            if isinstance(value, str) and value:
                return value
    raise ValueError("src/capagap/__init__.py must define a literal __version__ string")


def check_tag(tag: str, version: str) -> None:
    if tag != f"v{version}":
        raise ValueError(
            f"Release tag {tag!r} does not match package version v{version}"
        )


def check_output_directory(outdir: Path) -> None:
    if outdir.exists() and (not outdir.is_dir() or any(outdir.iterdir())):
        raise ValueError(f"Output directory must be empty: {outdir}. Use --outdir.")


def distributions(outdir: Path, version: str) -> tuple[Path, Path]:
    wheel = outdir / f"capagap-{version}-py3-none-any.whl"
    sdist = outdir / f"capagap-{version}.tar.gz"
    if set(outdir.iterdir()) != {wheel, sdist} or not all(
        path.is_file() for path in (wheel, sdist)
    ):
        raise ValueError("Expected exactly the current version's wheel and sdist")
    return wheel, sdist


def smoke_install(wheel: Path, version: str) -> None:
    with tempfile.TemporaryDirectory(prefix="capagap-install-") as directory:
        scratch = Path(directory)
        install = scratch / "venv"
        _run([sys.executable, "-m", "venv", str(install)], cwd=scratch)
        binaries = install / ("Scripts" if os.name == "nt" else "bin")
        python = str(binaries / ("python.exe" if os.name == "nt" else "python"))
        command = str(binaries / ("capagap.exe" if os.name == "nt" else "capagap"))
        _run(
            [
                python,
                "-I",
                "-m",
                "pip",
                "--isolated",
                "install",
                "--no-index",
                "--no-deps",
                str(wheel),
            ],
            cwd=scratch,
        )
        for invocation in ([command], [python, "-I", "-m", "capagap"]):
            result = _run([*invocation, "--version"], cwd=scratch, capture=True)
            if result.stdout.strip() != f"capagap {version}":
                raise ValueError("Installed CLI version does not match the release")
        metadata = _run(
            [
                python,
                "-I",
                "-c",
                "from importlib.metadata import version; print(version('capagap'))",
            ],
            cwd=scratch,
            capture=True,
        )
        if metadata.stdout.strip() != version:
            raise ValueError("Installed package metadata version does not match")

        _run([command, "demo"], cwd=scratch)
        demo = scratch / "capagap-demo"
        demo_report = json.loads((demo / "report.json").read_text(encoding="utf-8"))
        if (
            demo_report["summary"]["union_coverage"] != 0.75
            or not (demo / "report.html").is_file()
        ):
            raise ValueError(
                "Installed demo resources or report generation are incomplete"
            )
        _run([command, "case", "verify", str(demo / "case"), "--strict"], cwd=scratch)

        examples = ROOT / "examples"
        static = str(examples / "static.json")
        baseline = str(examples / "dynamic.json")
        runs = [
            "--run",
            f"baseline={baseline}",
            "--run",
            f"interactive={examples / 'dynamic-interactive.json'}",
        ]
        comparisons = (
            ("compare", [static, baseline]),
            ("matrix", [static, *runs]),
        )
        for name, inputs in comparisons:
            for format_name in ("json", "html"):
                _run(
                    [
                        command,
                        name,
                        *inputs,
                        "--format",
                        format_name,
                        "--output",
                        str(scratch / f"{name}.{format_name}"),
                    ],
                    cwd=scratch,
                )
            report = (scratch / f"{name}.html").read_text(encoding="utf-8")
            if not all(
                marker in report
                for marker in ("<style>", "switchGroup", "finding-detail")
            ):
                raise ValueError(f"Installed {name} report is missing HTML assets")
        single = json.loads((scratch / "compare.json").read_text(encoding="utf-8"))
        matrix = json.loads((scratch / "matrix.json").read_text(encoding="utf-8"))
        if single["summary"]["unobserved_rules"] != 2:
            raise ValueError("Installed comparison produced an unexpected result")
        if matrix["summary"]["union_coverage"] != 0.75:
            raise ValueError("Installed matrix produced an unexpected result")

        handoff = scratch / "handoff"
        _run([command, "handoff", static, *runs, "--output", str(handoff)], cwd=scratch)
        bundle_path = handoff / "capagap-handoff.json"
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        if bundle["generator"]["version"] != version:
            raise ValueError("Installed handoff generator version does not match")
        for name in (
            "CapaGapImport_Ghidra.py",
            "capagap_import_ida.py",
            "capagap_import_binja.py",
        ):
            path = handoff / name
            compile(path.read_text(encoding="utf-8"), str(path), "exec")
        _run(
            [
                command,
                "triage",
                "apply",
                str(bundle_path),
                str(handoff / "capagap-triage.json"),
                "--output",
                str(scratch / "reviewed.json"),
            ],
            cwd=scratch,
        )
        _run(
            [
                command,
                "manifest",
                str(examples / "demo-rules"),
                "--output",
                str(scratch / "manifest.json"),
            ],
            cwd=scratch,
        )

        evidence = examples / "evidence"
        rich_static = str(evidence / "static.json")
        rich_runs = [
            "--run",
            f"baseline={evidence / 'dynamic.json'}",
            "--run",
            f"interactive={evidence / 'dynamic-interactive.json'}",
            "--condition",
            "baseline:interaction=off",
            "--condition",
            "interactive:interaction=on",
        ]
        _run(
            [
                command,
                "validate",
                rich_static,
                str(evidence / "dynamic.json"),
                "--format",
                "json",
                "--output",
                str(scratch / "validation.json"),
            ],
            cwd=scratch,
        )
        _run(
            [
                command,
                "contributions",
                rich_static,
                *rich_runs,
                "--strict",
                "--format",
                "json",
                "--output",
                str(scratch / "contributions.json"),
            ],
            cwd=scratch,
        )
        contributions = json.loads(
            (scratch / "contributions.json").read_text(encoding="utf-8")
        )
        if contributions["union_count"] != 3 or contributions["representative_set"][
            "labels"
        ] != ["baseline", "interactive"]:
            raise ValueError("Installed run-contribution calculation is incorrect")
        case = scratch / "case"
        _run(
            [
                command,
                "case",
                "init",
                rich_static,
                *rich_runs,
                "--name",
                "Install check",
                "--notes",
                "Synthetic inputs",
                "--output",
                str(case),
            ],
            cwd=scratch,
        )
        _run([command, "case", "verify", str(case), "--strict"], cwd=scratch)
        for format_name in ("html", "json"):
            _run(
                [
                    command,
                    "case",
                    "report",
                    str(case),
                    "--strict",
                    "--format",
                    format_name,
                    "--output",
                    str(scratch / f"case.{format_name}"),
                ],
                cwd=scratch,
            )
        _run(
            [
                command,
                "case",
                "handoff",
                str(case),
                "--strict",
                "--tool",
                "json",
                "--output",
                str(scratch / "case-handoff"),
            ],
            cwd=scratch,
        )
        case_report = scratch / "case.json"
        _run(
            [
                command,
                "diff",
                str(case_report),
                str(case_report),
                "--fail-on-change",
                "--format",
                "json",
                "--output",
                str(scratch / "unchanged.json"),
            ],
            cwd=scratch,
        )
        if json.loads((scratch / "unchanged.json").read_text())["changed"]:
            raise ValueError("Identical saved reports produced a diff")
        _run(
            [
                command,
                "diff",
                str(scratch / "matrix.json"),
                str(case_report),
                "--format",
                "json",
                "--output",
                str(scratch / "changed.json"),
            ],
            cwd=scratch,
        )
        if not json.loads((scratch / "changed.json").read_text())["changed"]:
            raise ValueError("Installed saved-report diff missed changed evidence")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--outdir", type=Path, default=ROOT / "dist")
    parser.add_argument("--tag", help="Require this release tag to match the version")
    args = parser.parse_args(argv)
    outdir = args.outdir.resolve()
    checks = (
        (["-m", "ruff", "check", "."], False),
        (["-m", "ruff", "format", "--check", "."], False),
        (["-m", "compileall", "-q", "src", "tests"], False),
        (["-m", "unittest", "discover", "-s", "tests", "-v"], True),
    )
    try:
        version = source_version()
        if args.tag is not None:
            check_tag(args.tag, version)
        check_output_directory(outdir)
        for arguments, include_source in checks:
            _run([sys.executable, *arguments], include_source=include_source)
        _run([sys.executable, "-m", "build", "--outdir", str(outdir)])
        wheel, sdist = distributions(outdir, version)
        _run(
            [sys.executable, "-m", "twine", "check", "--strict", str(wheel), str(sdist)]
        )
        smoke_install(wheel, version)
    except subprocess.CalledProcessError as exc:
        if exc.stdout:
            print(exc.stdout, file=sys.stderr)
        if exc.stderr:
            print(exc.stderr, file=sys.stderr)
        print(f"release check failed with exit code {exc.returncode}", file=sys.stderr)
        return exc.returncode or 1
    except (OSError, ValueError) as exc:
        print(f"release check failed: {exc}", file=sys.stderr)
        return 1
    print(f"Release checks passed for {version}. Distributions: {outdir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
