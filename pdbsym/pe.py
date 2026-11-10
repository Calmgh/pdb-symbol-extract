#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Minimal PE reader: everything needed to turn PDB section offsets into RVAs.

Deliberately small -- this is not a general-purpose PE library. It answers
three questions:

1. What are the sections, and what RVA does ``section:N + offset`` map to?
2. What is ``ImageBase``, so an RVA can become a runtime address?
3. Which CodeView record (GUID + age) does this binary claim, so we can prove
   the PDB on disk was produced by the same link?
"""
import collections
import struct

from .errors import PdbFormatError

#: IMAGE_DIRECTORY_ENTRY_DEBUG
DIR_DEBUG = 6
#: IMAGE_DEBUG_TYPE_CODEVIEW
DEBUG_TYPE_CODEVIEW = 2

Section = collections.namedtuple(
    "Section", "name va vsize raw_size raw_ptr characteristics")

CodeView = collections.namedtuple("CodeView", "guid age pdb_path")


class PE(object):
    def __init__(self, path, header_size=0x2000):
        self.path = path
        self._f = open(path, "rb")
        try:
            self._data_header = self._f.read(header_size)
            self._parse()
        except Exception:
            self._f.close()
            raise

    def _parse(self):
        d = self._data_header
        if len(d) < 0x40 or d[:2] != b"MZ":
            raise PdbFormatError("not a PE file (no MZ header): %s" % self.path)

        e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
        if d[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            raise PdbFormatError("not a PE file (no PE signature): %s" % self.path)

        coff = e_lfanew + 4
        self.machine, self.num_sections = struct.unpack_from("<HH", d, coff)
        self.timestamp, = struct.unpack_from("<I", d, coff + 4)

        opt = coff + 20              # SizeOfOptionalHeader is not needed: the
        self.opt_offset = opt        # magic tells us which variant we have.
        magic = struct.unpack_from("<H", d, opt)[0]
        if magic == 0x20B:           # PE32+
            self.is_64 = True
            self.image_base, = struct.unpack_from("<Q", d, opt + 24)
            self.data_dirs = opt + 112
        elif magic == 0x10B:         # PE32
            self.is_64 = False
            self.image_base, = struct.unpack_from("<I", d, opt + 28)
            self.data_dirs = opt + 96
        else:
            raise PdbFormatError("unknown optional header magic 0x%X" % magic)

        size_of_optional_header, = struct.unpack_from("<H", d, coff + 16)
        sec_off = opt + size_of_optional_header
        self.sections = []
        for i in range(self.num_sections):
            o = sec_off + i * 40
            name = d[o:o + 8].rstrip(b"\0").decode("latin-1", "replace")
            vsize, va, raw_size, raw_ptr = struct.unpack_from("<4I", d, o + 8)
            (chars,) = struct.unpack_from("<I", d, o + 36)
            self.sections.append(
                Section(name, va, vsize, raw_size, raw_ptr, chars))
        if not self.sections:
            raise PdbFormatError("PE has no sections")

    # ------------------------------------------------------------------ RVA

    def rva_to_offset(self, rva):
        """Map an RVA to a file offset, or ``None`` if it is not backed by file."""
        for s in self.sections:
            if s.va <= rva < s.va + s.vsize:
                delta = rva - s.va
                if delta >= s.raw_size:
                    return None          # zero-filled (.bss-like) tail
                return s.raw_ptr + delta
        return None

    def section_for_rva(self, rva):
        for s in self.sections:
            if s.va <= rva < s.va + max(s.vsize, s.raw_size):
                return s
        return None

    def section_index_for_rva(self, rva):
        """1-based section index, matching the numbering used by S_PUB32."""
        for i, s in enumerate(self.sections):
            if s.va <= rva < s.va + max(s.vsize, s.raw_size):
                return i + 1
        return None

    def read_rva(self, rva, size):
        off = self.rva_to_offset(rva)
        if off is None:
            return b""
        self._f.seek(off)
        return self._f.read(size)

    # -------------------------------------------------------------- CodeView

    def codeview(self):
        """Return the :class:`CodeView` record from the debug directory.

        This is the exe half of the "same link?" check: compare it against
        :meth:`pdbsym.msf.MSF.info_stream`.
        """
        rva, size = struct.unpack_from("<II", self._data_header, self.data_dirs + DIR_DEBUG * 8)
        if not rva or not size:
            return None
        raw = self.read_rva(rva, size)
        for i in range(len(raw) // 28):
            o = i * 28
            (kind,) = struct.unpack_from("<I", raw, o + 12)
            data_size, data_rva, data_ptr = struct.unpack_from("<III", raw, o + 16)
            if kind != DEBUG_TYPE_CODEVIEW or not data_size:
                continue
            blob = self.read_rva_any(data_rva, data_ptr, data_size)
            if len(blob) < 24 or blob[:4] != b"RSDS":
                continue
            guid = blob[4:20]
            age, = struct.unpack_from("<I", blob, 20)
            path = blob[24:].split(b"\0")[0].decode("latin-1", "replace")
            return CodeView(guid, age, path)
        return None

    def read_rva_any(self, rva, file_offset, size):
        if file_offset:
            self._f.seek(file_offset)
            return self._f.read(size)
        return self.read_rva(rva, size)

    # --------------------------------------------------------------- imports

    def imports(self):
        """Map IAT slot RVA -> ``"DLL!Function"`` (see docs/PITFALLS.md #17)."""
        mapping = {}
        imp_rva, _ = struct.unpack_from("<II", self._data_header, self.data_dirs + 8)
        if not imp_rva:
            return mapping
        pos = self.rva_to_offset(imp_rva)
        if pos is None:
            return mapping

        while True:
            self._f.seek(pos)
            ent = self._f.read(20)
            if len(ent) < 20 or ent == b"\0" * 20:
                break
            original_first_thunk, _ts, _fwd, name_rva, first_thunk = struct.unpack_from(
                "<5I", ent, 0)
            if name_rva:
                dll = self._cstr(self.rva_to_offset(name_rva))
                # Code references the IAT (FirstThunk); the *names* live in the
                # INT (OriginalFirstThunk).
                name_src = self.rva_to_offset(
                    original_first_thunk if original_first_thunk else first_thunk)
                iat_rva = first_thunk if first_thunk else original_first_thunk
                if name_src is not None and iat_rva:
                    k = 0
                    while True:
                        self._f.seek(name_src + k * 8)
                        v, = struct.unpack("<Q", self._f.read(8))
                        if v == 0:
                            break
                        if v & 0x8000000000000000:
                            fn = "ord#%d" % (v & 0xFFFF)
                        else:
                            # Skip the 2-byte hint that precedes the name.
                            name_off = self.rva_to_offset(v)
                            fn = self._cstr(name_off + 2) if name_off is not None else "?"
                        mapping[iat_rva + k * 8] = dll + "!" + fn
                        k += 1
            pos += 20
        return mapping

    def _cstr(self, offset):
        if offset is None:
            return ""
        self._f.seek(offset)
        chunk = self._f.read(512)
        return chunk.split(b"\0")[0].decode("latin-1", "replace")

    # ------------------------------------------------------------- lifecycle

    def close(self):
        if not self._f.closed:
            self._f.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def __repr__(self):
        return "<PE %s %s sections=%d>" % (
            self.path, "x64" if getattr(self, "is_64", False) else "x86",
            len(getattr(self, "sections", ())))
