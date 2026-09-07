"""Import a CapaGap handoff bundle into the current IDA database."""

from __future__ import annotations

import json

import ida_bytes
import ida_kernwin
import ida_nalt


def _load_bundle(path: str) -> dict:
    with open(path, encoding="utf-8") as stream:
        bundle = json.load(stream)
    if bundle.get("schema") != "capagap-handoff" or bundle.get("schema_version") != 1:
        raise ValueError("unsupported CapaGap handoff schema")
    return bundle


def _group_comments(bundle: dict) -> dict[int, list[str]]:
    grouped: dict[int, list[str]] = {}
    for finding in bundle.get("findings", []):
        comment = finding.get("comment", "")
        if not comment:
            continue
        for location in finding.get("locations", []):
            rva = location.get("rva")
            if isinstance(rva, int) and not isinstance(rva, bool) and rva >= 0:
                comments = grouped.setdefault(rva, [])
                if comment not in comments:
                    comments.append(comment)
    return grouped


def _merge_comment(existing: str | None, incoming: list[str]) -> str:
    lines = (existing or "").splitlines()
    for comment in incoming:
        marker = comment.split("]", 1)[0] + "]"
        replaced = False
        for index, line in enumerate(lines):
            if marker in line:
                lines[index] = comment
                replaced = True
                break
        if not replaced:
            lines.append(comment)
    return "\n".join(lines)


def main() -> None:
    path = ida_kernwin.ask_file(False, "*.json", "Select capagap-handoff.json")
    if not path:
        return
    try:
        bundle = _load_bundle(path)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        ida_kernwin.warning(f"CapaGap: could not load bundle:\n{error}")
        return

    expected_hash = bundle.get("analysis", {}).get("sample", {}).get("sha256", "").lower()
    raw_hash = ida_nalt.retrieve_input_file_sha256()
    actual_hash = raw_hash.hex().lower() if raw_hash else ""
    if expected_hash and actual_hash and expected_hash != actual_hash:
        ida_kernwin.warning(
            "CapaGap: sample SHA-256 mismatch; no comments were imported.\n"
            f"Bundle:  {expected_hash}\nDatabase: {actual_hash}"
        )
        return

    image_base = ida_nalt.get_imagebase()
    imported = 0
    skipped = 0
    for rva, comments in sorted(_group_comments(bundle).items()):
        address = image_base + rva
        if not ida_bytes.is_loaded(address):
            skipped += 1
            continue
        existing = ida_bytes.get_cmt(address, True)
        merged = _merge_comment(existing, comments)
        if merged != (existing or ""):
            ida_bytes.set_cmt(address, merged, True)
        imported += 1

    ida_kernwin.refresh_idaview_anyway()
    ida_kernwin.msg(
        f"CapaGap: imported {imported} address comment(s), "
        f"skipped {skipped} unmapped address(es)\n"
    )


main()
