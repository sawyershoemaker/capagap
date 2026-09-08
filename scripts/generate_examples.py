"""Regenerate the synthetic evidence fixtures and checked-in report examples."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from capagap.analysis import compare_documents
from capagap.handoff import build_matrix_handoff, write_handoff
from capagap.html_report import render_html, render_matrix_html
from capagap.io import load_document
from capagap.matrix import compare_matrix
from capagap.render import render_markdown, render_matrix_markdown

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
APIS = {
    "communicate over HTTP": "wininet.HttpSendRequestA",
    "create scheduled task": "taskschd.ITaskService.Connect",
    "inject shellcode into remote process": "kernel32.WriteProcessMemory",
    "check for sandbox process names": "kernel32.Process32FirstW",
    "execute shell command": "kernel32.CreateProcessW",
    "capture screenshot": "gdi32.BitBlt",
    "encrypt data using AES": "advapi32.CryptEncrypt",
}


def evidence_fixture(filename: str) -> dict:
    payload = json.loads((EXAMPLES / filename).read_text(encoding="utf-8"))
    static = payload["meta"]["flavor"] == "static"
    layout = {"functions": []} if static else {"processes": []}
    counts = {"file": 4, "functions" if static else "processes": []}
    for index, (name, rule) in enumerate(payload["rules"].items()):
        api = APIS.get(name, "synthetic.helper")
        for ordinal, match in enumerate(rule["matches"]):
            if static:
                address = match[0]
                location = {"type": "absolute", "value": address["value"] + 16}
                layout["functions"].append(
                    {
                        "address": address,
                        "matched_basic_blocks": [{"address": location}],
                    }
                )
                counts["functions"].append({"address": address, "count": 5})
            else:
                pid, tid = 1000 + index, 2000 + ordinal
                process = {"type": "process", "value": [4, pid]}
                address = {"type": "thread", "value": [4, pid, tid]}
                location = {"type": "call", "value": [4, pid, tid, 1]}
                match[0] = address
                layout["processes"].append(
                    {
                        "address": process,
                        "name": "demo.exe",
                        "matched_threads": [
                            {
                                "address": address,
                                "matched_calls": [
                                    {
                                        "address": location,
                                        "name": api.rsplit(".", 1)[-1]
                                        + "(synthetic arguments)",
                                    }
                                ],
                            }
                        ],
                    }
                )
                counts["processes"].append({"address": process, "count": 5})
            match[1] = {
                "success": True,
                "node": {
                    "type": "statement",
                    "statement": {
                        "type": "or",
                        "description": "Synthetic alternatives for inspecting rule evidence",
                    },
                },
                "children": [
                    {
                        "success": True,
                        "node": {
                            "type": "feature",
                            "feature": {"type": "api", "api": api},
                        },
                        "children": [],
                        "locations": [location],
                        "captures": {},
                    },
                    {
                        "success": False,
                        "node": {
                            "type": "feature",
                            "feature": {
                                "type": "string",
                                "string": "synthetic alternative, not matched",
                            },
                        },
                        "children": [],
                        "locations": [],
                        "captures": {},
                    },
                ],
                "locations": [],
                "captures": {},
            }
    payload["meta"]["analysis"]["layout"] = layout
    payload["meta"]["analysis"]["feature_counts"] = counts
    return payload


def main() -> None:
    directory = EXAMPLES / "evidence"
    directory.mkdir(exist_ok=True)
    documents = []
    for name in ("static.json", "dynamic.json", "dynamic-interactive.json"):
        path = directory / name
        path.write_text(
            json.dumps(evidence_fixture(name), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        documents.append(
            replace(load_document(path), path=Path("examples/evidence") / name)
        )
    static, baseline, interactive = documents
    single = compare_documents(static, baseline)
    matrix = compare_matrix(
        static,
        [("baseline", baseline), ("interactive", interactive)],
        experiment_conditions=[
            ("baseline", "interaction", "off"),
            ("interactive", "interaction", "on"),
        ],
    )
    for name, content in {
        "single-run-dashboard.html": render_html(single),
        "matrix-dashboard.html": render_matrix_html(matrix),
        "demo-report.md": render_markdown(single),
        "matrix-report.md": render_matrix_markdown(matrix),
    }.items():
        (EXAMPLES / name).write_text(content, encoding="utf-8")
    write_handoff(
        build_matrix_handoff(matrix), EXAMPLES / "re-handoff", tool="all", force=True
    )
    print("Regenerated synthetic fixtures, reports, and the example handoff.")


if __name__ == "__main__":
    main()
