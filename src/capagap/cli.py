"""Command-line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from capagap import __version__
from capagap.analysis import ComparisonError, compare_documents
from capagap.cases import CaseError
from capagap.diagnostics import ValidationError
from capagap.diff import DiffError
from capagap.handoff import (
    HandoffError,
    build_matrix_handoff,
    build_single_handoff,
    write_handoff,
)
from capagap.html_report import render_html, render_matrix_html
from capagap.io import DocumentError, load_document
from capagap.manifest import (
    ManifestError,
    build_ruleset_manifest,
    load_ruleset_manifest,
    write_ruleset_manifest,
)
from capagap.matrix import compare_matrix
from capagap.render import (
    render_json,
    render_markdown,
    render_matrix_json,
    render_matrix_markdown,
    render_matrix_text,
    render_text,
)
from capagap.triage import (
    TriageError,
    apply_triage,
    build_triage_worksheet,
    load_handoff,
    load_triage,
    render_triage_report,
    write_json,
)
from capagap.workflows import register_commands, run_workflow


def _add_report_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--strict",
        action="store_true",
        help="stop on input-quality or comparison warnings",
    )
    parser.add_argument(
        "--minimum-features",
        type=int,
        default=1,
        help="warn below this extracted-feature count (default: 1)",
    )
    parser.add_argument(
        "--format",
        choices=("text", "markdown", "json", "html"),
        default="text",
        help="report format (default: text)",
    )
    parser.add_argument(
        "--output", type=Path, help="write the report to a file instead of stdout"
    )
    parser.add_argument(
        "--minimum-priority",
        choices=("low", "medium", "high", "critical"),
        default="low",
        help="minimum unobserved priority shown in text/Markdown reports",
    )
    parser.add_argument(
        "--limit", type=int, default=25, help="maximum rows per human report section"
    )
    parser.add_argument(
        "--allow-mismatch",
        action="store_true",
        help="allow different sample hashes (report confidence will be low)",
    )
    parser.add_argument(
        "--include-library",
        action="store_true",
        help="include capa library/helper rules (excluded by default)",
    )
    parser.add_argument(
        "--ruleset-manifest",
        type=Path,
        help="verify compared rules against a CapaGap ruleset manifest",
    )


def _run_argument(value: str) -> tuple[str, Path]:
    label, separator, path = value.partition("=")
    if not separator or not label.strip() or not path.strip():
        raise argparse.ArgumentTypeError("run must use LABEL=PATH syntax")
    return label.strip(), Path(path.strip())


def _condition_argument(value: str) -> tuple[str, str, str]:
    label, separator, assignment = value.partition(":")
    key, equals, condition_value = assignment.partition("=")
    if (
        not separator
        or not equals
        or not label.strip()
        or not key.strip()
        or not condition_value.strip()
    ):
        raise argparse.ArgumentTypeError("condition must use LABEL:KEY=VALUE syntax")
    return label.strip(), key.strip(), condition_value.strip()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="capagap",
        description="Find statically present capa capabilities that one sandbox run did not observe.",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    manifest = subcommands.add_parser(
        "manifest", help="fingerprint a local capa YAML ruleset"
    )
    manifest.add_argument("rules", type=Path, help="root directory of capa YAML rules")
    manifest.add_argument(
        "--output",
        required=True,
        type=Path,
        help="write the manifest JSON to this local path",
    )
    manifest.add_argument(
        "--force", action="store_true", help="overwrite an existing manifest"
    )

    triage = subcommands.add_parser(
        "triage", help="create, summarize, or apply an offline analyst review"
    )
    triage_commands = triage.add_subparsers(dest="triage_command", required=True)

    triage_init = triage_commands.add_parser(
        "init", help="create an editable worksheet from a handoff"
    )
    triage_init.add_argument("handoff", type=Path)
    triage_init.add_argument("--output", required=True, type=Path)
    triage_init.add_argument("--force", action="store_true")

    triage_report = triage_commands.add_parser(
        "report", help="summarize an analyst worksheet"
    )
    triage_report.add_argument("handoff", type=Path)
    triage_report.add_argument("worksheet", type=Path)
    triage_report.add_argument("--format", choices=("text", "markdown"), default="text")
    triage_report.add_argument("--output", type=Path)

    triage_apply = triage_commands.add_parser(
        "apply", help="write a reviewed handoff with triage comments"
    )
    triage_apply.add_argument("handoff", type=Path)
    triage_apply.add_argument("worksheet", type=Path)
    triage_apply.add_argument("--output", required=True, type=Path)
    triage_apply.add_argument("--force", action="store_true")

    compare = subcommands.add_parser(
        "compare", help="compare static and dynamic capa result documents"
    )
    compare.add_argument("static", type=Path, help="capa JSON from static analysis")
    compare.add_argument(
        "dynamic", type=Path, help="capa JSON/JSON.GZ from dynamic analysis"
    )
    _add_report_arguments(compare)
    compare.add_argument(
        "--fail-on-unobserved",
        action="store_true",
        help="return exit code 3 when comparable capabilities are unobserved",
    )

    matrix = subcommands.add_parser(
        "matrix",
        help="compare one static result with multiple labeled dynamic runs",
    )
    matrix.add_argument("static", type=Path, help="capa JSON from static analysis")
    matrix.add_argument(
        "--run",
        action="append",
        required=True,
        type=_run_argument,
        metavar="LABEL=PATH",
        help="labeled dynamic result; repeat at least twice",
    )
    matrix.add_argument(
        "--condition",
        action="append",
        default=[],
        type=_condition_argument,
        metavar="LABEL:KEY=VALUE",
        help="declare an experimental condition; repeat for each run and key",
    )
    _add_report_arguments(matrix)
    matrix.add_argument(
        "--fail-on-never-observed",
        action="store_true",
        help="return exit code 3 when capabilities remain unobserved across all runs",
    )

    handoff = subcommands.add_parser(
        "handoff",
        help="export prioritized gap evidence into Ghidra, IDA, or Binary Ninja",
    )
    handoff.add_argument("static", type=Path, help="capa JSON from static analysis")
    handoff.add_argument(
        "--run",
        action="append",
        required=True,
        type=_run_argument,
        metavar="LABEL=PATH",
        help="labeled dynamic result; repeat for multi-run analysis",
    )
    handoff.add_argument(
        "--condition",
        action="append",
        default=[],
        type=_condition_argument,
        metavar="LABEL:KEY=VALUE",
        help="declare an experimental condition for a multi-run handoff",
    )
    handoff.add_argument(
        "--output",
        required=True,
        type=Path,
        metavar="DIRECTORY",
        help="directory for the JSON bundle and native importer scripts",
    )
    handoff.add_argument(
        "--tool",
        choices=("all", "json", "ghidra", "ida", "binary-ninja"),
        default="all",
        help="importer to include (default: all)",
    )
    handoff.add_argument(
        "--minimum-priority",
        choices=("low", "medium", "high", "critical"),
        default="low",
        help="minimum finding priority exported (default: low)",
    )
    handoff.add_argument(
        "--never-only",
        action="store_true",
        help="for multi-run input, exclude environment-sensitive findings",
    )
    handoff.add_argument(
        "--allow-mismatch",
        action="store_true",
        help="allow different report sample hashes (handoff confidence will be low)",
    )
    handoff.add_argument(
        "--include-library",
        action="store_true",
        help="include capa library/helper rules (excluded by default)",
    )
    handoff.add_argument(
        "--ruleset-manifest",
        type=Path,
        help="verify compared rules against a CapaGap ruleset manifest",
    )
    handoff.add_argument(
        "--force",
        action="store_true",
        help="overwrite handoff files that already exist",
    )
    handoff.add_argument("--strict", action="store_true")
    handoff.add_argument("--minimum-features", type=int, default=1)
    register_commands(
        subcommands, _add_report_arguments, _run_argument, _condition_argument
    )
    return parser


def _render(args: argparse.Namespace, comparison) -> str:
    if args.format == "json":
        return render_json(comparison)
    if args.format == "html":
        return render_html(comparison)
    if args.format == "markdown":
        return render_markdown(
            comparison,
            minimum_priority=args.minimum_priority,
            limit=args.limit,
        )
    return render_text(
        comparison,
        minimum_priority=args.minimum_priority,
        limit=args.limit,
    )


def _render_matrix(args: argparse.Namespace, comparison) -> str:
    if args.format == "json":
        return render_matrix_json(comparison)
    if args.format == "html":
        return render_matrix_html(comparison)
    if args.format == "markdown":
        return render_matrix_markdown(
            comparison,
            minimum_priority=args.minimum_priority,
            limit=args.limit,
        )
    return render_matrix_text(
        comparison,
        minimum_priority=args.minimum_priority,
        limit=args.limit,
    )


def _write_report(args: argparse.Namespace, report: str) -> int:
    if args.output:
        try:
            inputs = [
                getattr(args, "static", None),
                getattr(args, "dynamic", None),
                getattr(args, "ruleset_manifest", None),
            ]
            inputs.extend(path for _, path in getattr(args, "run", []))
            if args.output.resolve() in {
                Path(path).resolve() for path in inputs if path is not None
            }:
                print(
                    "capagap: error: report output would overwrite an input",
                    file=sys.stderr,
                )
                return 2
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(report, encoding="utf-8")
        except OSError as exc:
            print(
                f"capagap: error: could not write {args.output}: {exc}", file=sys.stderr
            )
            return 2
    else:
        try:
            sys.stdout.write(report)
        except BrokenPipeError:
            return 0
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if hasattr(args, "limit") and args.limit < 1:
        parser.error("--limit must be at least 1")
    if hasattr(args, "minimum_features") and args.minimum_features < 1:
        parser.error("--minimum-features must be at least 1")

    try:
        if args.command in {"case", "validate", "diff", "contributions"}:
            return run_workflow(args)
        if args.command == "manifest":
            manifest = build_ruleset_manifest(args.rules)
            destination = write_ruleset_manifest(
                manifest, args.output, force=args.force
            )
            print(
                f"CapaGap manifest: {len(manifest.rules)} rule(s), "
                f"fingerprint {manifest.fingerprint}"
            )
            print(f"  {destination.resolve()}")
            return 0

        if args.command == "triage":
            bundle = load_handoff(args.handoff)
            if args.triage_command == "init":
                destination = write_json(
                    build_triage_worksheet(bundle), args.output, force=args.force
                )
                print(f"CapaGap triage worksheet: {destination.resolve()}")
                return 0
            worksheet = load_triage(args.worksheet)
            if args.triage_command == "report":
                report = render_triage_report(
                    bundle, worksheet, markdown=args.format == "markdown"
                )
                return _write_report(args, report)
            destination = write_json(
                apply_triage(bundle, worksheet), args.output, force=args.force
            )
            print(f"CapaGap reviewed handoff: {destination.resolve()}")
            return 0

        ruleset_manifest = (
            load_ruleset_manifest(args.ruleset_manifest)
            if args.ruleset_manifest
            else None
        )
        static = load_document(
            args.static,
            expected_flavor="static",
            minimum_features=args.minimum_features,
        )
        if args.command == "compare":
            dynamic = load_document(
                args.dynamic,
                expected_flavor="dynamic",
                minimum_features=args.minimum_features,
            )
            comparison = compare_documents(
                static,
                dynamic,
                allow_mismatch=args.allow_mismatch,
                include_library=args.include_library,
                ruleset_manifest=ruleset_manifest,
                strict=args.strict,
            )
            report = _render(args, comparison)
        elif args.command == "matrix":
            dynamic_runs = [
                (
                    label,
                    load_document(
                        path,
                        expected_flavor="dynamic",
                        minimum_features=args.minimum_features,
                    ),
                )
                for label, path in args.run
            ]
            comparison = compare_matrix(
                static,
                dynamic_runs,
                allow_mismatch=args.allow_mismatch,
                include_library=args.include_library,
                ruleset_manifest=ruleset_manifest,
                experiment_conditions=args.condition,
                strict=args.strict,
            )
            report = _render_matrix(args, comparison)
        else:
            dynamic_runs = [
                (
                    label,
                    load_document(
                        path,
                        expected_flavor="dynamic",
                        minimum_features=args.minimum_features,
                    ),
                )
                for label, path in args.run
            ]
            if len(dynamic_runs) == 1:
                if args.never_only:
                    raise HandoffError(
                        "--never-only requires at least two --run inputs"
                    )
                label, dynamic = dynamic_runs[0]
                comparison = compare_documents(
                    static,
                    dynamic,
                    allow_mismatch=args.allow_mismatch,
                    include_library=args.include_library,
                    ruleset_manifest=ruleset_manifest,
                    strict=args.strict,
                )
                bundle = build_single_handoff(
                    comparison,
                    run_label=label,
                    minimum_priority=args.minimum_priority,
                )
            else:
                comparison = compare_matrix(
                    static,
                    dynamic_runs,
                    allow_mismatch=args.allow_mismatch,
                    include_library=args.include_library,
                    ruleset_manifest=ruleset_manifest,
                    experiment_conditions=args.condition,
                    strict=args.strict,
                )
                bundle = build_matrix_handoff(
                    comparison,
                    minimum_priority=args.minimum_priority,
                    never_only=args.never_only,
                )
            written = write_handoff(
                bundle,
                args.output,
                tool=args.tool,
                force=args.force,
            )
            summary = bundle["summary"]
            print(
                "CapaGap handoff: "
                f"{summary['selected_findings']} finding(s), "
                f"{summary['addressable_locations']} address(es)"
            )
            for path in written:
                print(f"  {path.resolve()}")
            return 0
    except ValidationError as exc:
        print(f"capagap: error: {exc}", file=sys.stderr)
        return 4
    except BrokenPipeError:
        return 0
    except (
        DocumentError,
        ComparisonError,
        HandoffError,
        ManifestError,
        TriageError,
        CaseError,
        DiffError,
        OSError,
    ) as exc:
        print(f"capagap: error: {exc}", file=sys.stderr)
        return 2

    write_result = _write_report(args, report)
    if write_result:
        return write_result

    if (
        args.command == "compare"
        and args.fail_on_unobserved
        and comparison.summary.unobserved_rules
    ):
        return 3
    if (
        args.command == "matrix"
        and args.fail_on_never_observed
        and comparison.summary.never_observed_rules
    ):
        return 3
    return 0
