"""Binary Ninja plugin for importing CapaGap handoff bundles."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from binaryninja import PluginCommand, log_error, log_info, log_warn
from binaryninja.interaction import get_open_filename_input, show_message_box


def _load_bundle(path: str) -> dict:
    with open(path, encoding="utf-8") as stream:
        bundle = json.load(stream)
    if bundle.get("schema") != "capagap-handoff" or bundle.get("schema_version") != 1:
        raise ValueError("unsupported CapaGap handoff schema")
    return bundle


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


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


def import_handoff(binary_view) -> None:
    selected = get_open_filename_input("Select capagap-handoff.json", "*.json")
    if not selected:
        return
    path = selected.decode() if isinstance(selected, bytes) else selected
    try:
        bundle = _load_bundle(path)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        log_error(f"CapaGap: could not load bundle: {error}")
        show_message_box("CapaGap import failed", str(error))
        return

    expected_hash = bundle.get("analysis", {}).get("sample", {}).get("sha256", "").lower()
    original_path = Path(binary_view.file.original_filename)
    if expected_hash and original_path.is_file():
        try:
            actual_hash = _sha256(original_path)
        except OSError as error:
            log_warn(f"CapaGap: could not hash original input: {error}")
        else:
            if expected_hash != actual_hash:
                message = (
                    "Sample SHA-256 mismatch; no comments were imported.\n"
                    f"Bundle: {expected_hash}\nBinary: {actual_hash}"
                )
                log_error("CapaGap: " + message.replace("\n", " "))
                show_message_box("CapaGap import blocked", message)
                return

    image_base = binary_view.start
    imported = 0
    skipped = 0
    for rva, comments in sorted(_group_comments(bundle).items()):
        address = image_base + rva
        if binary_view.get_segment_at(address) is None:
            skipped += 1
            continue
        existing = binary_view.get_comment_at(address)
        merged = _merge_comment(existing, comments)
        if merged != (existing or ""):
            binary_view.set_comment_at(address, merged)
        imported += 1

    message = (
        f"Imported {imported} address comment(s); "
        f"skipped {skipped} unmapped address(es)."
    )
    log_info("CapaGap: " + message)
    show_message_box("CapaGap import complete", message)


PluginCommand.register(
    r"CapaGap\Import handoff",
    "Import address comments from a CapaGap handoff bundle",
    import_handoff,
)
