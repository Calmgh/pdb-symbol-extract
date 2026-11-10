#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Small x64 disassembler with symbol and IAT annotation.

Requires ``capstone``. If it is missing the rest of :mod:`pdbsym` still works.

Why a bespoke disassembler instead of opening IDA: after you have an RVA from
:mod:`pdbsym.pub`, you usually want to look at 20 instructions and move on.
Opening a multi-hundred-MB IDB for that is minutes of waiting.
"""
import re

from .errors import PdbFormatError

_RIP_RE = re.compile(r"\[rip \+ (0x[0-9a-f]+)\]")
_ADDR_RE = re.compile(r"(0x[0-9a-f]+)")


def _capstone():
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    except ImportError:
        raise PdbFormatError(
            "capstone is required for disassembly: pip install capstone")
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    return md


def disassemble(pe, rva, count=40, symbols=None, imports=None, limit=0x2000):
    """Disassemble *count* instructions starting at *rva*.

    Returns a list of ``(rva, bytes_text, asm_text, note)`` tuples. *symbols*
    is a ``{rva: name}`` map, *imports* a ``{iat_rva: "DLL!Func"}`` map; both
    are optional and only used to annotate.
    """
    offset = pe.rva_to_offset(rva)
    if offset is None:
        raise PdbFormatError("RVA 0x%X is not backed by file data" % rva)

    symbols = symbols or {}
    imports = imports or {}
    image_base = pe.image_base
    md = _capstone()

    with open(pe.path, "rb") as f:
        f.seek(offset)
        code = f.read(limit)

    rows = []
    for ins in md.disasm(code, image_base + rva):
        note = _note_for(ins, image_base, symbols, imports)
        rows.append((
            ins.address - image_base,
            ins.bytes.hex(" "),
            (ins.mnemonic + " " + ins.op_str).strip(),
            note,
        ))
        if len(rows) >= count:
            break
    return rows


def _note_for(ins, image_base, symbols, imports):
    note = ""
    if ins.mnemonic in ("call", "jmp") and "rip" not in ins.op_str:
        m = _ADDR_RE.search(ins.op_str)
        if m:
            target = int(m.group(1), 16) - image_base
            if target in symbols:
                note = "-> %s" % symbols[target]
            else:
                near = [k for k in symbols if abs(k - target) <= 8]
                if near:
                    note = "~> %s" % symbols[near[0]]

    if "rip" in ins.op_str and "[" in ins.op_str:
        for m in _RIP_RE.finditer(ins.op_str):
            disp = int(m.group(1), 16)
            # The IAT slot is addressed relative to the *end* of the instruction.
            target = (ins.address + ins.size + disp) - image_base
            if target in imports:
                note = (note + " " if note else "") + "[IAT] %s" % imports[target]
                break
    return note


def find_section_span(pe, rva):
    """Return the containing section name for *rva*, or ``None``."""
    section = pe.section_for_rva(rva)
    return section.name if section else None


def looks_like_function_start(pe, rva):
    """Heuristic: is *rva* plausibly a function entry (docs/PITFALLS.md #18)?

    True when the byte before *rva* terminates the previous function (``ret`` /
    ``jmp`` / ``int3`` / padding) and the bytes at *rva* are a standard x64
    prologue. Cheap, and it catches the most common cause of "my hook crashed":
    a symbol RVA pointing into the middle of an unrelated function.
    """
    offset = pe.rva_to_offset(rva)
    if offset is None or offset == 0:
        return False
    with open(pe.path, "rb") as f:
        f.seek(offset - 1)
        prev = f.read(1)
        f.seek(offset)
        head = f.read(8)
    if prev not in (b"\xC3", b"\xC2", b"\xCC", b"\x90", b"\xEB", b"\xE9"):
        return False
    prologues = (b"\x48\x8B\xC4",      # mov rax, rsp
                 b"\x48\x89\x5C\x24",  # mov [rsp+x], rbx
                 b"\x40\x55",          # push rbp (with REX)
                 b"\x48\x83\xEC",      # sub rsp, imm8
                 b"\x48\x81\xEC")      # sub rsp, imm32
    return any(head.startswith(p) for p in prologues)
