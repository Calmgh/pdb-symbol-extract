#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Type Record stream (TPI, stream 2) parsing: struct members and offsets.

Why this exists: before you can hook a function or walk an object you need the
field offset of -- say -- ``UObject::Name``. Guessing is expensive; the PDB
already knows, offline, with no debugger attached.

Four layout traps live in here (see docs/PITFALLS.md #9-#15):

* TPI record ``Length`` **includes** the leaf field (``off+2 .. off+2+Length``)
* ``LF_CLASS``/``LF_STRUCTURE`` ``Size`` is a plain ``u16``, not a Numeric
* ``LF_MEMBER`` offsets use a "hybrid Numeric": ``u16 < 0x8000`` is a literal
* ``LF_PAD0..LF_PAD3`` are **single bytes** -- read them as u16 and the whole
  member chain silently truncates at the first padding byte
"""
import struct

from .errors import PdbFormatError

# ---- CodeView leaf kinds -------------------------------------------------
LF_STRUCTURE = 0x1505
LF_CLASS = 0x1504
LF_INTERFACE = 0x1519
LF_UNION = 0x1506
LF_FIELDLIST = 0x1203
LF_MEMBER = 0x150D
LF_BCLASS = 0x1400
LF_INDEX = 0x1404
LF_ENUM = 0x1507
LF_ENUMERATE = 0x1502
LF_METHOD = 0x150E
LF_ONEMETHOD = 0x1511
LF_NESTTYPE = 0x1510
LF_VFUNCTAB = 0x1409
LF_STMEMBER = 0x150C
LF_PAD0 = 0xF0

CLASS_LEAVES = (LF_STRUCTURE, LF_CLASS, LF_INTERFACE, LF_UNION)

NUMERIC_KINDS = {
    0x8000: ("i8", 1), 0x8001: ("i16", 2), 0x8002: ("u16", 2),
    0x8003: ("i32", 4), 0x8004: ("u32", 4), 0x8009: ("i64", 8),
    0x800A: ("u64", 8), 0x8005: ("f32", 4), 0x8006: ("f64", 8),
}
_NUMERIC_FMT = {"i8": "<b", "i16": "<h", "u16": "<H", "i32": "<i",
                "u32": "<I", "i64": "<q", "u64": "<Q", "f32": "<f", "f64": "<d"}


class TPI(object):
    """Parsed type records, addressable by type index."""

    def __init__(self, data):
        self.data = data
        if len(data) < 20:
            raise PdbFormatError("TPI stream too short (%d bytes)" % len(data))
        (self.version, self.header_size, self.ti_begin,
         self.ti_end, self.record_bytes) = struct.unpack_from("<IIIII", data, 0)
        self.records = {}       # type_index -> record bytes (leaf included)
        self._parse()

    def _parse(self):
        off = self.header_size
        ti = self.ti_begin
        data = self.data
        n = len(data)
        while off + 4 <= n and ti <= self.ti_end:
            length = struct.unpack_from("<H", data, off)[0]
            if length < 2:
                break
            # Length includes the 2-byte leaf field. See docs/PITFALLS.md #9.
            self.records[ti] = data[off + 2: off + 2 + length]
            off += 2 + length
            ti += 1

    # ------------------------------------------------------------------ utils

    def kind(self, ti):
        rec = self.records.get(ti & 0x7FFFFFFF)
        if not rec or len(rec) < 2:
            return None
        return struct.unpack_from("<H", rec, 0)[0]

    def numeric(self, rec, off):
        """Read a Numeric: ``(value, new_offset)``. ``leaf < 0x8000`` = TypeIndex."""
        if off + 2 > len(rec):
            raise PdbFormatError("numeric read out of bounds")
        leaf = struct.unpack_from("<H", rec, off)[0]
        if leaf < 0x8000:
            if off + 4 > len(rec):
                raise PdbFormatError("numeric read out of bounds")
            return struct.unpack_from("<I", rec, off)[0], off + 4
        name, size = NUMERIC_KINDS.get(leaf, ("u32", 4))
        if off + 2 + size > len(rec):
            raise PdbFormatError("numeric read out of bounds")
        value = struct.unpack_from(_NUMERIC_FMT[name], rec, off + 2)[0]
        return value, off + 2 + size

    def numeric_or_u16(self, rec, off):
        """MSVC's hybrid Numeric (docs/PITFALLS.md #11).

        ``u16 >= 0x8000`` is a Numeric leaf; anything smaller is a literal u16.
        Treating it as a plain Numeric shifts every following field by 2 bytes,
        which truncates member names and turns offsets into absurd numbers.
        """
        if off + 2 > len(rec):
            raise PdbFormatError("read out of bounds")
        value = struct.unpack_from("<H", rec, off)[0]
        if value >= 0x8000:
            return self.numeric(rec, off)
        return value, off + 2

    @staticmethod
    def _cstr(rec, off):
        end = rec.find(b"\0", off)
        if end < 0:
            return "", off
        return rec[off:end].decode("latin-1", "replace"), end + 1

    # ---------------------------------------------------------------- records

    def parse_class(self, ti):
        """``LF_CLASS``/``LF_STRUCTURE`` -> ``{name, size, field_ti}``.

        Observed layout (docs/PITFALLS.md #10)::

            +0x00 u16 leaf
            +0x02 u16 member_count
            +0x04 u16 properties
            +0x06 u32 field_list
            +0x0A u32 derived_from
            +0x0E u32 vshape
            +0x12 u16 size            <-- plain u16, NOT a Numeric
            +0x14     name (NUL terminated)
        """
        rec = self.records.get(ti)
        if not rec or len(rec) < 22:
            return None
        field_ti, = struct.unpack_from("<I", rec, 6)
        size = struct.unpack_from("<H", rec, 18)[0]
        off = 20
        if size >= 0x8000:      # huge struct: genuinely a Numeric
            size, off = self.numeric(rec, 18)
        name, _ = self._cstr(rec, off)
        return {"name": name, "size": size, "field_ti": field_ti & 0x7FFFFFFF}

    def parse_fieldlist(self, ti, out, depth=0):
        """Walk an ``LF_FIELDLIST``, following ``LF_INDEX`` continuations.

        Fills ``out["members"]`` and ``out["bases"]`` in place. Unknown leaves
        are handled by bounded resynchronisation rather than precise length
        derivation -- good enough for most types, still lossy for
        ``UObject``/``UFunction``/``UProperty``/``FArchive``
        (docs/PITFALLS.md #15).
        """
        ti = ti & 0x7FFFFFFF
        seen = out.setdefault("_seen", set())
        if ti in seen or depth > 32:
            return
        seen.add(ti)

        rec = self.records.get(ti)
        if not rec or struct.unpack_from("<H", rec, 0)[0] != LF_FIELDLIST:
            return

        off = 2
        n = len(rec)
        while off + 2 <= n:
            # PAD leaves are ONE byte. Reading them as u16 makes `F2 F1` decode
            # to 0xF1F2, the check fails, and the member chain stops early.
            if LF_PAD0 <= rec[off] <= LF_PAD0 + 3:
                off += 1
                continue

            leaf = struct.unpack_from("<H", rec, off)[0]
            if leaf == 0:
                break

            if leaf == LF_MEMBER:
                off += 4                                    # leaf + attr
                type_index, = struct.unpack_from("<I", rec, off); off += 4
                value, off = self.numeric_or_u16(rec, off)
                name, off = self._cstr(rec, off)
                off = (off + 3) & ~3                        # name padded to 4
                out["members"].append({
                    "name": name,
                    "offset": value if value < (1 << 31) else None,
                    "type": type_index & 0x7FFFFFFF,
                })

            elif leaf == LF_BCLASS:
                off += 4
                type_index, = struct.unpack_from("<I", rec, off); off += 4
                value, off = self.numeric_or_u16(rec, off)
                out["bases"].append({"type": type_index & 0x7FFFFFFF,
                                     "offset": value})

            elif leaf == LF_INDEX:
                off += 4
                nxt, = struct.unpack_from("<I", rec, off); off += 4
                self.parse_fieldlist(nxt, out, depth + 1)

            elif leaf == LF_ENUMERATE:
                off += 4
                _value, off = self.numeric_or_u16(rec, off)
                _name, off = self._cstr(rec, off)
                off = (off + 3) & ~3

            elif leaf in (LF_ONEMETHOD, LF_METHOD, LF_STMEMBER, LF_VFUNCTAB,
                          LF_NESTTYPE):
                off += 4
                if off + 4 > n:
                    break
                off += 4
                if leaf in (LF_ONEMETHOD, LF_METHOD, LF_STMEMBER, LF_NESTTYPE):
                    _name, off = self._cstr(rec, off)
                    off = (off + 3) & ~3

            else:
                # Unknown leaf: its length depends on attr bits we do not model.
                # Resync by scanning forward (bounded) for the next plausible
                # leaf on an even boundary. Better to lose a few members than to
                # emit wrong offsets.
                resynced = False
                for probe in range(off + 2, min(off + 96, n - 2), 2):
                    nxt = struct.unpack_from("<H", rec, probe)[0]
                    if nxt in (LF_MEMBER, LF_BCLASS, LF_INDEX):
                        off = probe
                        resynced = True
                        break
                if not resynced:
                    break

    # --------------------------------------------------------------- helpers

    def iter_classes(self):
        """Yield ``(type_index, {name, size, field_ti})`` for every class-like type."""
        for ti in list(self.records.keys()):
            if self.kind(ti) in CLASS_LEAVES:
                try:
                    info = self.parse_class(ti)
                except PdbFormatError:
                    info = None
                if info and info["name"]:
                    info["ti"] = ti
                    yield ti, info

    def collect_structs(self, only=None):
        """Return ``(members, structs)`` rows ready for TSV output.

        *only* is an optional iterable of names to keep (substring match).
        Same-name duplicates (forward declarations, template instantiations)
        collapse to the largest size; see docs/PITFALLS.md #13 for why that is
        a heuristic and not a rule.
        """
        best = {}
        for ti, info in self.iter_classes():
            name = info["name"]
            current = best.get(name)
            if current is None or (info["size"], ti) > (current["size"], current["ti"]):
                best[name] = info

        if only:
            wanted = [w.lower() for w in only]
            names = [n for n in best if any(w in n.lower() for w in wanted)]
        else:
            names = list(best)

        members, structs = [], []
        for name in names:
            info = best[name]
            fields = {"members": [], "bases": []}
            try:
                self.parse_fieldlist(info["field_ti"], fields)
            except PdbFormatError:
                pass
            structs.append((name, info["size"], len(fields["members"]),
                            len(fields["bases"])))
            emitted = set()
            for m in fields["members"]:
                key = (m["name"], m["offset"])
                if key in emitted:
                    continue
                emitted.add(key)
                members.append((name, info["size"], m["name"], m["offset"], m["type"]))
        return members, structs
