"""CLI workflows for cases, validation, saved-report diffs and run contributions."""

from __future__ import annotations

import argparse
import json
import sys
import webbrowser
from pathlib import Path

from capagap.analysis import ComparisonError, compare_documents
from capagap.batch import analyze_directory
from capagap.cases import (
    CaseError,
    add_case_runs,
    case_history,
    create_case,
    load_case,
    render_case_history,
)
from capagap.contributions import analyze_contributions, render_contributions
from capagap.demo import create_demo
from capagap.diagnostics import (
    Diagnostic,
    ValidationError,
    render_validation,
    require_valid,
    validation_result,
)
from capagap.diff import compare_reports, load_report, render_diff
from capagap.doctor import inspect_installation, render_doctor
from capagap.handoff import build_matrix_handoff, build_single_handoff, write_handoff
from capagap.html_report import render_html, render_matrix_html
from capagap.io import DocumentError, load_document
from capagap.manifest import load_ruleset_manifest
from capagap.matrix import compare_matrix
from capagap.models import MatrixComparison
from capagap.output import write_text
from capagap.render import (
    render_json,
    render_markdown,
    render_matrix_json,
    render_matrix_markdown,
    render_matrix_text,
    render_text,
)
from capagap.repeatability import analyze_repeatability, render_repeatability


def _output(parser: argparse.ArgumentParser, *, html: bool = False) -> None:
    parser.add_argument(
        "--format",
        choices=("text", "markdown", "json", "html")
        if html
        else ("text", "markdown", "json"),
        default="text",
    )
    parser.add_argument("--output", type=Path)


def register_commands(
    subcommands, add_report_arguments, run_argument, condition_argument
) -> None:
    doctor = subcommands.add_parser(
        "doctor", help="inspect interpreter, installation metadata, and command lookup"
    )
    _output(doctor)
    doctor.add_argument(
        "--strict",
        action="store_true",
        help="return exit code 4 when installation warnings are found",
    )
    demo = subcommands.add_parser(
        "demo", help="create a bundled synthetic case and offline report"
    )
    demo.add_argument(
        "--output", type=Path, default=Path("capagap-demo"), metavar="NEW_DIRECTORY"
    )
    demo.add_argument(
        "--open",
        action="store_true",
        help="open the generated local report in your browser",
    )
    batch = subcommands.add_parser(
        "batch", help="group a directory of capa results by sample SHA-256"
    )
    batch.add_argument("directory", type=Path)
    batch.add_argument("--output", required=True, type=Path, metavar="NEW_DIRECTORY")
    batch.add_argument("--recursive", action="store_true")
    batch.add_argument(
        "--format", choices=("html", "json", "markdown", "text"), default="html"
    )
    batch.add_argument("--ruleset-manifest", type=Path)
    batch.add_argument("--include-library", action="store_true")
    batch.add_argument("--minimum-features", type=int, default=1)
    batch.add_argument("--strict", action="store_true")
    validate = subcommands.add_parser(
        "validate", help="inspect capa result quality before interpreting coverage"
    )
    validate.add_argument("inputs", nargs="+", type=Path)
    validate.add_argument(
        "--minimum-features",
        type=int,
        default=1,
        help="warn below this explicitly chosen extracted-feature count",
    )
    _output(validate)

    diff = subcommands.add_parser("diff", help="compare two saved CapaGap JSON reports")
    diff.add_argument("before", type=Path)
    diff.add_argument("after", type=Path)
    diff.add_argument("--allow-mismatch", action="store_true")
    diff.add_argument(
        "--fail-on-change",
        action="store_true",
        help="return exit code 3 when the reports differ",
    )
    _output(diff)

    for name, help_text in (
        ("contributions", "measure unique capability coverage contributed by each run"),
        ("repeatability", "count observations across repeated declared conditions"),
    ):
        command = subcommands.add_parser(name, help=help_text)
        command.add_argument("static", type=Path)
        command.add_argument(
            "--run",
            required=True,
            action="append",
            type=run_argument,
            metavar="LABEL=PATH",
        )
        command.add_argument(
            "--condition", action="append", default=[], type=condition_argument
        )
        if name == "contributions":
            add_report_arguments(command)
        else:
            _output(command, html=True)
            command.add_argument("--strict", action="store_true")
            command.add_argument("--minimum-features", type=int, default=1)
            command.add_argument("--allow-mismatch", action="store_true")
            command.add_argument("--include-library", action="store_true")
            command.add_argument("--ruleset-manifest", type=Path)

    case = subcommands.add_parser(
        "case", help="create and use portable, hash-pinned analysis cases"
    )
    commands = case.add_subparsers(dest="case_command", required=True)
    init = commands.add_parser(
        "init",
        help="capture a new case directory; existing directories are never replaced",
    )
    init.add_argument("static", type=Path)
    init.add_argument(
        "--run", required=True, action="append", type=run_argument, metavar="LABEL=PATH"
    )
    init.add_argument(
        "--condition", action="append", default=[], type=condition_argument
    )
    init.add_argument("--output", required=True, type=Path, metavar="DIRECTORY")
    init.add_argument("--name", default="Analysis case")
    init.add_argument("--notes", default="")
    init.add_argument("--ruleset-manifest", type=Path)
    init.add_argument("--allow-mismatch", action="store_true")
    init.add_argument("--include-library", action="store_true")
    add_run = commands.add_parser(
        "add-run", help="append runs into a new case revision"
    )
    add_run.add_argument("path", type=Path)
    add_run.add_argument(
        "--run", required=True, action="append", type=run_argument, metavar="LABEL=PATH"
    )
    add_run.add_argument(
        "--condition", action="append", default=[], type=condition_argument
    )
    add_run.add_argument("--output", required=True, type=Path, metavar="NEW_DIRECTORY")
    add_run.add_argument("--name")
    add_run.add_argument("--notes")
    add_run.add_argument("--format", choices=("text", "json"), default="text")
    for name in ("verify", "report", "handoff", "history"):
        command = commands.add_parser(name)
        command.add_argument("path", type=Path, help="case directory or case.json")
        command.add_argument(
            "--strict", action="store_true", help="stop on input-quality warnings"
        )
        if name != "handoff":
            _output(command, html=name == "report")
        else:
            command.add_argument("--output", required=True, type=Path)
            command.add_argument(
                "--tool",
                choices=("all", "json", "ghidra", "ida", "binary-ninja"),
                default="all",
            )
            command.add_argument("--never-only", action="store_true")
            command.add_argument("--force", action="store_true")
        if name in {"report", "handoff"}:
            command.add_argument(
                "--minimum-priority",
                choices=("low", "medium", "high", "critical"),
                default="low",
            )
        if name == "report":
            command.add_argument("--limit", type=int, default=25)


def _write(args, payload, renderer, *, forbidden=()) -> int:
    report = (
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
        if args.format == "json"
        else renderer(payload, markdown=args.format == "markdown")
    )
    if args.output:
        write_text(args.output, report, forbidden=forbidden)
    else:
        sys.stdout.write(report)
    return 0


def _render_case(args, comparison) -> str:
    matrix = isinstance(comparison, MatrixComparison)
    if args.format == "json":
        return (render_matrix_json if matrix else render_json)(comparison)
    if args.format == "html":
        return (render_matrix_html if matrix else render_html)(comparison)
    renderer = (
        (render_matrix_markdown if matrix else render_markdown)
        if args.format == "markdown"
        else (render_matrix_text if matrix else render_text)
    )
    return renderer(
        comparison, minimum_priority=args.minimum_priority, limit=args.limit
    )


def run_workflow(args) -> int:
    if args.command == "doctor":
        result = inspect_installation()
        _write(args, result, render_doctor)
        return 4 if args.strict and not result["passed"] else 0
    if args.command == "demo":
        report = create_demo(args.output)
        print(f"CapaGap synthetic demo: {report.resolve()}")
        print(f"Portable case: {(report.parent / 'case').resolve()}")
        if args.open:
            try:
                opened = webbrowser.open(report.resolve().as_uri())
            except (webbrowser.Error, OSError):
                opened = False
            if not opened:
                print(
                    "capagap: report created; could not launch a browser. Open the report path above manually.",
                    file=sys.stderr,
                )
                return 4
        return 0
    if args.command == "batch":
        result = analyze_directory(
            args.directory,
            args.output,
            recursive=args.recursive,
            report_format=args.format,
            ruleset_path=args.ruleset_manifest,
            include_library=args.include_library,
            minimum_features=args.minimum_features,
            strict=args.strict,
        )
        summary = result["summary"]
        print(
            f"CapaGap batch: {summary['completed']} completed, {summary['failed']} failed, {summary['rejected_inputs']} rejected inputs"
        )
        print((args.output / "index.md").resolve())
        return 4 if summary["failed"] or summary["rejected_inputs"] else 0
    if args.command == "validate":
        if args.minimum_features < 1:
            raise DocumentError("--minimum-features must be at least 1")
        documents = []
        issues = []
        for path in args.inputs:
            try:
                document = load_document(path, minimum_features=args.minimum_features)
                documents.append(document)
                issues.extend(document.diagnostics)
            except DocumentError as exc:
                issues.append(Diagnostic("invalid-input", "error", str(exc), str(path)))
        statics = [document for document in documents if document.flavor == "static"]
        if len(statics) == 1:
            for document in documents:
                if document.flavor == "dynamic":
                    try:
                        comparison = compare_documents(statics[0], document)
                        issues.extend(
                            Diagnostic(
                                "comparison-context",
                                "warning",
                                message,
                                document.path.name,
                            )
                            for message in comparison.warnings
                        )
                    except ComparisonError as exc:
                        issues.append(
                            Diagnostic(
                                "incompatible-inputs",
                                "error",
                                str(exc),
                                document.path.name,
                            )
                        )
        elif len(statics) > 1:
            issues.append(
                Diagnostic(
                    "multiple-static-inputs",
                    "info",
                    "Individual inputs checked; pairwise compatibility requires exactly one static result.",
                )
            )
        issues = list(dict.fromkeys(issues))
        result = {
            "schema": "capagap-validation",
            "schema_version": 1,
            "passed": not any(item.severity in {"warning", "error"} for item in issues),
            "diagnostics": [item.to_dict() for item in issues],
        }
        _write(args, result, render_validation, forbidden=args.inputs)
        return (
            2
            if any(item.severity == "error" for item in issues)
            else 4
            if not result["passed"]
            else 0
        )
    if args.command == "diff":
        result = compare_reports(
            load_report(args.before),
            load_report(args.after),
            allow_mismatch=args.allow_mismatch,
        )
        _write(args, result, render_diff, forbidden=(args.before, args.after))
        return 3 if args.fail_on_change and result["changed"] else 0
    if args.command in {"contributions", "repeatability"}:
        if args.minimum_features < 1:
            raise DocumentError("--minimum-features must be at least 1")
        manifest = (
            load_ruleset_manifest(args.ruleset_manifest)
            if args.ruleset_manifest
            else None
        )
        comparison = compare_matrix(
            load_document(
                args.static,
                expected_flavor="static",
                minimum_features=args.minimum_features,
            ),
            [
                (
                    label,
                    load_document(
                        path,
                        expected_flavor="dynamic",
                        minimum_features=args.minimum_features,
                    ),
                )
                for label, path in args.run
            ],
            ruleset_manifest=manifest,
            allow_mismatch=args.allow_mismatch,
            include_library=args.include_library,
            experiment_conditions=args.condition,
            strict=args.strict and args.command != "repeatability",
        )
        if args.command == "repeatability":
            result = analyze_repeatability(comparison)
            renderer = render_repeatability
            if args.strict and (
                result["warnings"]
                or any(
                    item["severity"] in ("warning", "error")
                    for item in result["diagnostics"]
                )
            ):
                raise ValidationError(
                    "repeatability has input or grouping warnings; inspect without --strict"
                )
        else:
            result = analyze_contributions(comparison)
            renderer = render_contributions
        protected = (
            args.static,
            *(path for _, path in args.run),
            *((args.ruleset_manifest,) if args.ruleset_manifest else ()),
        )
        if args.format == "html":
            return _write(
                args,
                result,
                lambda *_args, **_kwargs: render_matrix_html(comparison),
                forbidden=protected,
            )
        return _write(args, result, renderer, forbidden=protected)
    if args.case_command == "init":
        destination = create_case(
            args.static,
            args.run,
            args.output,
            name=args.name,
            notes=args.notes,
            conditions=args.condition,
            ruleset_path=args.ruleset_manifest,
            allow_mismatch=args.allow_mismatch,
            include_library=args.include_library,
        )
        print(f"CapaGap case: {destination.resolve()}")
        return 0
    if args.case_command == "add-run":
        destination, delta = add_case_runs(
            args.path,
            args.run,
            args.output,
            conditions=args.condition,
            name=args.name,
            notes=args.notes,
        )
        if args.format == "json":
            print(json.dumps(delta, indent=2, ensure_ascii=True))
        else:
            print(f"CapaGap case revision {delta['revision']}: {destination.resolve()}")
            print(f"Added runs: {', '.join(delta['added_runs'])}")
            print(f"Newly observed: {len(delta['newly_observed'])}")
            for rule in delta["newly_observed"]:
                print("  " + " ".join(rule.split()))
            print(f"Still unobserved: {len(delta['still_unobserved'])}")
        return 0
    case, comparison = load_case(args.path)
    if args.strict:
        require_valid(comparison)
    root = args.path.resolve() if args.path.is_dir() else args.path.resolve().parent
    protected = [
        root / "case.json",
        root / case["static"]["path"],
        *(root / run["path"] for run in case["runs"]),
    ]
    if args.path.is_file():
        protected.append(args.path)
    if case.get("ruleset"):
        protected.append(root / case["ruleset"]["path"])
    if args.case_command == "history":
        return _write(
            args, case_history(case), render_case_history, forbidden=protected
        )
    if args.case_command == "verify":
        result = {
            **validation_result(comparison),
            "case_id": case["id"],
            "name": case["name"],
            "inputs_verified": True,
        }
        return _write(
            args,
            result,
            lambda payload, **kwargs: (
                "Case inputs and configuration verified.\n"
                + render_validation(payload, **kwargs)
            ),
            forbidden=protected,
        )
    if args.case_command == "report":
        return _write(
            args,
            comparison.to_dict(),
            lambda *_args, **_kwargs: _render_case(args, comparison),
            forbidden=protected,
        )
    if args.output.resolve() == root or args.output.resolve().is_relative_to(
        root / "inputs"
    ):
        raise CaseError("handoff output must not replace the case or its inputs")
    if isinstance(comparison, MatrixComparison):
        bundle = build_matrix_handoff(
            comparison,
            minimum_priority=args.minimum_priority,
            never_only=args.never_only,
        )
    else:
        if args.never_only:
            raise CaseError("--never-only requires at least two runs")
        bundle = build_single_handoff(
            comparison,
            run_label=case["runs"][0]["label"],
            minimum_priority=args.minimum_priority,
        )
    for path in write_handoff(
        bundle, args.output, tool=args.tool, force=args.force, forbidden=protected
    ):
        print(path.resolve())
    return 0
