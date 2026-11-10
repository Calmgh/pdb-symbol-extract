#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Prove that a PDB and an exe came from the same link -- before trusting RVAs.

Usage::

    python pdb_check.py target.pdb target.exe

Why this exists: "same file name", "same size", and even "same GUID" are all
insufficient. An incremental rebuild keeps the GUID and bumps the **age**, which
means every RVA shifts by a different amount while the symbol names stay
perfectly valid. Nothing looks wrong until your hook lands in the middle of an
unrelated function.

The only reliable check is **GUID + age**, from both sides:

* exe  -> PE debug directory -> ``RSDS`` record
* PDB  -> Info stream (stream 1) header

Exit codes: ``0`` match, ``1`` mismatch, ``2`` could not determine.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pdbsym import MSF, PE


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 1

    pdb_path, exe_path = argv[1], argv[2]

    with PE(exe_path) as pe:
        cv = pe.codeview()
        exe_info = {
            "guid": cv.guid if cv else None,
            "age": cv.age if cv else None,
            "pdb_path": cv.pdb_path if cv else None,
            "timestamp": pe.timestamp,
            "machine": pe.machine,
            "image_base": pe.image_base,
            "sections": [(s.name, s.va, s.vsize) for s in pe.sections],
        }

    with MSF(pdb_path) as pdb:
        _version, _signature, pdb_age, pdb_guid = pdb.info_stream()
        dbi = pdb.dbi_header()

    print("exe : %s" % exe_path)
    print("  TimeDateStamp : %d (0x%08X)" % (exe_info["timestamp"], exe_info["timestamp"]))
    print("  machine       : %04X" % exe_info["machine"])
    print("  image base    : 0x%X" % exe_info["image_base"])
    print("  CodeView GUID : %s" % (_format_guid(exe_info["guid"]) if exe_info["guid"] else "(none)"))
    print("  CodeView age  : %s" % exe_info["age"])
    print("  embedded path : %s" % (exe_info["pdb_path"] or "(none)"))
    print()

    print("pdb : %s" % pdb_path)
    print("  info GUID     : %s" % _format_guid(pdb_guid))
    print("  info age      : %d" % pdb_age)
    print("  DBI age       : %d" % dbi["age"])
    print("  DBI machine   : %04X" % dbi["machine"])
    print()

    if exe_info["guid"] is None:
        print("RESULT: cannot determine -- exe has no CodeView debug record")
        return 2

    guid_match = exe_info["guid"] == pdb_guid
    age_match = exe_info["age"] == pdb_age
    machine_match = exe_info["machine"] == dbi["machine"]

    print("  GUID    : %s" % ("MATCH" if guid_match else "MISMATCH"))
    print("  age     : %s" % ("MATCH" if age_match else "MISMATCH"))
    print("  machine : %s" % ("MATCH" if machine_match else "MISMATCH"))
    print()

    if guid_match and age_match:
        print("RESULT: same link -- RVAs from this PDB are valid for this exe.")
        if not machine_match:
            print("        (machine mismatch is odd for a real match: verify manually)")
        return 0

    if guid_match and not age_match:
        print("RESULT: DIFFERENT LINK, same GUID.")
        print("        An incremental rebuild: symbol names are still meaningful,")
        print("        but every RVA may have shifted. Do NOT use them as-is;")
        print("        re-derive the shift with a global-symbol delta or AOB.")
        return 1

    print("RESULT: DIFFERENT LINK.")
    print("        Symbol names may still describe the same code structure, but")
    print("        RVAs are not usable for hooks, breakpoints or disassembly.")
    return 1


def _format_guid(guid):
    if guid is None:
        return "(none)"
    d1 = int.from_bytes(guid[0:4], "little")
    d2 = int.from_bytes(guid[4:6], "little")
    d3 = int.from_bytes(guid[6:8], "little")
    return "%08X-%04X-%04X-%s-%s" % (d1, d2, d3,
                                     guid[8:10].hex().upper(),
                                     guid[10:16].hex().upper())


if __name__ == "__main__":
    sys.exit(main(sys.argv))
