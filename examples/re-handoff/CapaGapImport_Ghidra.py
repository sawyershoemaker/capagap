# CapaGap handoff importer for Ghidra.
#@category CapaGap
#@menupath Tools.CapaGap.Import Handoff

import json
import numbers

from ghidra.program.model.listing import BookmarkType


def _load_bundle(path):
    stream = open(path, "r")
    try:
        bundle = json.load(stream)
    finally:
        stream.close()
    if bundle.get("schema") != "capagap-handoff" or bundle.get("schema_version") != 1:
        raise ValueError("unsupported CapaGap handoff schema")
    return bundle


def _group_comments(bundle):
    grouped = {}
    for finding in bundle.get("findings", []):
        comment = finding.get("comment", "")
        if not comment:
            continue
        for location in finding.get("locations", []):
            rva = location.get("rva")
            if isinstance(rva, numbers.Integral) and not isinstance(rva, bool) and rva >= 0:
                comments = grouped.setdefault(int(rva), [])
                if comment not in comments:
                    comments.append(comment)
    return grouped


def main():
    bundle_file = askFile("Select capagap-handoff.json", "Open")
    if bundle_file is None:
        println("CapaGap import cancelled")
        return

    try:
        bundle = _load_bundle(bundle_file.getAbsolutePath())
    except Exception as error:
        printerr("CapaGap: could not load bundle: " + str(error))
        return

    expected_hash = bundle.get("analysis", {}).get("sample", {}).get("sha256", "").lower()
    actual_hash = currentProgram.getExecutableSHA256()
    if actual_hash:
        actual_hash = str(actual_hash).lower()
    if expected_hash and actual_hash and expected_hash != actual_hash:
        printerr("CapaGap: sample SHA-256 mismatch; no bookmarks were imported")
        printerr("  bundle:  " + expected_hash)
        printerr("  program: " + actual_hash)
        return

    image_base = currentProgram.getImageBase()
    memory = currentProgram.getMemory()
    bookmarks = currentProgram.getBookmarkManager()
    imported = 0
    skipped = 0

    for rva, comments in sorted(_group_comments(bundle).items()):
        try:
            address = image_base.add(rva)
        except Exception:
            skipped += 1
            continue
        if not memory.contains(address):
            skipped += 1
            continue
        bookmarks.setBookmark(
            address,
            BookmarkType.ANALYSIS,
            "CapaGap",
            "\n".join(comments),
        )
        imported += 1

    println(
        "CapaGap: imported %d bookmark(s), skipped %d unmapped address(es)"
        % (imported, skipped)
    )


main()
