CapaGap RE-tool handoff
=======================

Findings: 3
Addressable locations: 4
Sample SHA-256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

The importers use RVAs from capagap-handoff.json and rebase them against
the image base of the currently open database. Importers reject a known
sample-hash mismatch and skip addresses outside mapped memory.

Analyst review
--------------
Edit capagap-triage.json using one of its documented dispositions. Keep
the original handoff unchanged, then run:
  capagap triage apply capagap-handoff.json capagap-triage.json --output reviewed-handoff.json
Importing the reviewed handoff updates the CapaGap annotation while
preserving unrelated analyst comments.

Ghidra
------
Open the matching sample, then run CapaGapImport_Ghidra.py from
Script Manager (category: CapaGap). Select capagap-handoff.json.
The script creates Analysis bookmarks in category CapaGap.

IDA Pro
-------
Open the matching sample, choose File > Script file, and run
capagap_import_ida.py. Select capagap-handoff.json when prompted.
The script adds repeatable comments and preserves existing text.

Binary Ninja
------------
Install capagap_import_binja.py in your user plugin directory and
restart Binary Ninja. Open the matching sample, then choose
Plugins > CapaGap > Import handoff and select the JSON bundle.
The plugin adds address comments and preserves existing text.

Safety
------
This bundle contains analysis metadata and comments only. It does not
contain or execute the analyzed sample. Review imported findings as
triage leads; an unobserved capability is not proof of non-execution.
