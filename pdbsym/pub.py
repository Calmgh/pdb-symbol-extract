#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Public symbol extraction (``S_PUB32`` records -> RVA).

Record layout (CodeView, little endian)::

    u16 length        # excludes these 2 bytes; includes the type field
    u16 type          # 0x110E == S_PUB32
    u32 flags
    u32 section_offset
    u16 section_index # 1-based, indexes the PE section table
    char name[]       # NUL terminated, MSVC decorated

``RVA = pe.sections[section_index - 1].va + section_offset``

S_PUB32 covers **public** symbols only: function entry points and file-scope
globals. Static/internal functions are absent -- see docs/PITFALLS.md #6.
"""
import re
import struct

from .errors import PdbFormatError

S_PUB32 = 0x110E

#: Names that usually sit near a network entry point. Pure heuristic sugar.
DEFAULT_RPC_PATTERN = re.compile(
    r"(Server|NotifyServer|Client[A-Z]|_Server|RPC)")


def iter_public_symbols(msf, pe, progress=None):
    """Yield ``(rva, name)`` for every public symbol in *msf*.

    *progress* is an optional callable receiving ``(bytes_read, total_bytes)``.
    Symbols whose section index does not resolve to a real section (absolute
    symbols live in section 0xFFFF, for example) are skipped.
    """
    dbi = msf.dbi_header()
    index = dbi["sym_record_stream"]
    if index == 0xFFFF:
        raise PdbFormatError("DBI header reports no symbol record stream")

    data = msf.stream(index)
    total = len(data)
    n_sections = len(pe.sections)
    section_vas = [s.va for s in pe.sections]

    i = 0
    while i + 4 <= total:
        length = data[i] | (data[i + 1] << 8)
        if length < 2:
            i += 2
            continue
        kind = data[i + 2] | (data[i + 3] << 8)
        if kind == S_PUB32:
            rec = data[i + 4:i + 2 + length]
            if len(rec) >= 10:
                offset, section = _unpack_pub(rec)
                if 0 < section <= n_sections:
                    name = rec[10:].split(b"\0")[0].decode("latin-1", "replace")
                    yield section_vas[section - 1] + offset, name
        i += 2 + length
        if progress is not None and (i & 0x3FFFFF) < 4:
            progress(i, total)


def _unpack_pub(rec):
    # rec layout: flags(4) offset(4) section(2) name...
    return struct.unpack_from("<IH", rec, 4)


def extract_public_symbols(msf, pe, progress=None):
    """Like :func:`iter_public_symbols` but returns a list sorted by RVA."""
    out = list(iter_public_symbols(msf, pe, progress=progress))
    out.sort()
    return out


def filter_symbols(symbols, pattern=None):
    """Keep symbols whose name matches *pattern* (a compiled regex)."""
    rx = pattern if pattern is not None else DEFAULT_RPC_PATTERN
    return [(rva, name) for rva, name in symbols if rx.search(name)]


def write_tsv(path, symbols):
    """Write the ``# rva\\tsize\\ttag\\tname`` table used by the CLI tools."""
    with open(path, "w", encoding="utf-8") as f:
        f.write("# rva\tsize\ttag\tname\n")
        for rva, name in symbols:
            f.write("0x%X\t0\t5\t%s\n" % (rva, name))


def read_tsv(path):
    """Load a symbol table written by :func:`write_tsv`."""
    symbols = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.startswith("#"):
                continue
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 4:
                try:
                    symbols[int(parts[0], 16)] = parts[3]
                except ValueError:
                    pass
    return symbols


def describe_rpc_surface(symbols, pattern=None):
    """Return a ``{prefix: count}`` histogram to eyeball an RPC surface.

    Useful as a first pass when you have no idea what a build exposes: the
    buckets with the highest counts are usually the object classes.
    """
    rx = pattern if pattern is not None else DEFAULT_RPC_PATTERN
    buckets = {}
    for _rva, name in symbols:
        if not rx.search(name):
            continue
        key = _rpc_bucket(name)
        buckets[key] = buckets.get(key, 0) + 1
    return dict(sorted(buckets.items(), key=lambda kv: -kv[1]))


def _rpc_bucket(name):
    # "?ServerFoo@AActor@@..." -> "ServerFoo@AActor"
    body = name.lstrip("?")
    if "@" in body:
        return body.split("@@")[0]
    return body
