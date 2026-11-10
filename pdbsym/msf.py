#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""MSF 7.0 container reader.

A PDB file is a tiny read-only filesystem:

    superblock (block 0)
      -> block map  -> list of directory blocks
      -> directory   -> stream count + stream sizes + per-stream block lists
      -> stream N    -> actual payload (stream 3 = DBI, stream 2 = TPI, ...)

Everything is addressed in fixed-size blocks. There are no offsets in the
directory: a stream's block list is a **bare array of u32**, and its length is
derived from the stream size, not read from the file. See docs/PITFALLS.md #2.

Typical use::

    with MSF("target.pdb") as m:
        dbi = m.stream(3)
        tpi = m.stream(2)
"""
import struct

from .errors import PdbFormatError

MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0"
MAGIC_MSF2 = b"Microsoft C/C++ program database 2.00\r\n\x1aJG\0\0"

#: A stream size of 0xFFFFFFFF means "empty stream", not "4 GB".
EMPTY_STREAM = 0xFFFFFFFF


class MSF(object):
    """Read-only view over an MSF 7.0 container."""

    def __init__(self, path):
        self.path = path
        self._f = open(path, "rb")
        try:
            self._parse_superblock()
            self._parse_directory()
        except Exception:
            self._f.close()
            raise
        #: Optional cache for small, frequently-read streams (see stream()).
        self._cache = {}

    # ------------------------------------------------------------------ parse

    def _parse_superblock(self):
        hdr = self._f.read(64)
        if len(hdr) < 56:
            raise PdbFormatError("file too short to be a PDB: %s" % self.path)
        if hdr[:32] == MAGIC_MSF2:
            raise PdbFormatError(
                "this is an MSF 2.0 (old-style) PDB; only MSF 7.0 is supported"
            )
        if hdr[:32] != MAGIC:
            raise PdbFormatError("not an MSF 7.0 container: %s" % self.path)

        (self.block_size,     # BlockSize
         self.free_block_map,  # FreeBlockMapBlock
         self.num_blocks,     # NumBlocks
         self.dir_bytes,      # NumDirectoryBytes
         self.unknown,        # Unknown
         self.block_map_addr,  # BlockMapAddr
         ) = struct.unpack_from("<6I", hdr, 32)

        if self.block_size == 0:
            raise PdbFormatError("block size is 0")

    def _parse_directory(self):
        bs = self.block_size

        # The block map is a contiguous run of blocks holding the *directory's*
        # block indices -- one more level of indirection than the name suggests.
        n_dir_blocks = -(-self.dir_bytes // bs)
        n_map_blocks = -(-(n_dir_blocks * 4) // bs)
        block_map = b"".join(
            self._block(self.block_map_addr + i) for i in range(n_map_blocks)
        )
        self.dir_blocks = struct.unpack_from("<%dI" % n_dir_blocks, block_map, 0)

        directory = b"".join(self._block(b) for b in self.dir_blocks)

        self.num_streams = struct.unpack_from("<I", directory, 0)[0]
        self.stream_sizes = list(
            struct.unpack_from("<%dI" % self.num_streams, directory, 4)
        )

        # Per-stream block lists. NOTE: no count prefix -- the number of block
        # indices is ceil(size / block_size). Reading a count here is the single
        # most common way to derail the parser. See docs/PITFALLS.md #2.
        pos = 4 + self.num_streams * 4
        self.stream_blocks = []
        for i in range(self.num_streams):
            size = self.stream_sizes[i]
            if size == EMPTY_STREAM:
                size = 0
            n = -(-size // bs)
            if n:
                blocks = struct.unpack_from("<%dI" % n, directory, pos)
            else:
                blocks = ()
            self.stream_blocks.append(blocks)
            pos += n * 4

        # Self-check: the block lists must consume the directory exactly.
        expected_blocks = n_dir_blocks
        used_blocks = -(-pos // bs)
        if used_blocks > expected_blocks:
            raise PdbFormatError(
                "directory under-sized: stream block lists need %d blocks, "
                "directory only has %d (parser is out of sync)"
                % (used_blocks, expected_blocks)
            )

    # ------------------------------------------------------------------- read

    def _block(self, index):
        self._f.seek(index * self.block_size)
        data = self._f.read(self.block_size)
        if len(data) != self.block_size:
            raise PdbFormatError("truncated block %d" % index)
        return data

    def stream(self, index, limit=None, cache=False):
        """Return the full payload of stream *index* (or its first *limit* bytes).

        Streams can be hundreds of MB (TPI on a large game build), so the whole
        payload is materialised in memory unless *limit* is given. Pass
        ``cache=True`` only for small streams you will read repeatedly.
        """
        if cache and index in self._cache:
            return self._cache[index]
        if index >= self.num_streams:
            raise PdbFormatError(
                "stream %d out of range (container has %d streams)"
                % (index, self.num_streams)
            )
        size = self.stream_sizes[index]
        if size == EMPTY_STREAM:
            size = 0
        blocks = self.stream_blocks[index]
        if limit is not None:
            size = min(size, limit)
            blocks = blocks[: -(-size // self.block_size)]
        data = b"".join(self._block(b) for b in blocks)[:size]
        if cache:
            self._cache[index] = data
        return data

    def info_stream(self):
        """Return ``(version, signature, age, guid_bytes)`` from stream 1.

        This is the authoritative link identity: an exe and a PDB belong to the
        same link only if **both** the CodeView GUID and the age match.
        """
        data = self.stream(1, limit=28, cache=True)
        version, signature, age = struct.unpack_from("<III", data, 0)
        return version, signature, age, data[12:28]

    def dbi_header(self):
        """Parse the DBI header (stream 3) into a dict."""
        data = self.stream(3, limit=64, cache=True)
        if len(data) < 64:
            raise PdbFormatError("DBI stream too short")
        (version_signature, version_header, age) = struct.unpack_from("<III", data, 0)
        (global_stream, build_number, public_stream, pdb_dll_version,
         sym_record_stream, pdb_dll_rbld) = struct.unpack_from("<6H", data, 12)
        (mod_info_size, section_contrib_size, section_map_size, source_info_size,
         type_server_map_size, mfc_type_server_map_size, optional_dbg_header_size,
         ec_substream_size) = struct.unpack_from("<8I", data, 24)
        flags, machine = struct.unpack_from("<HH", data, 56)
        return {
            "version_signature": version_signature,
            "version_header": version_header,
            "age": age,
            "global_stream": global_stream,
            "build_number": build_number,
            "public_stream": public_stream,
            "pdb_dll_version": pdb_dll_version,
            "sym_record_stream": sym_record_stream,
            "pdb_dll_rbld": pdb_dll_rbld,
            "mod_info_size": mod_info_size,
            "section_contrib_size": section_contrib_size,
            "section_map_size": section_map_size,
            "source_info_size": source_info_size,
            "type_server_map_size": type_server_map_size,
            "mfc_type_server_map_size": mfc_type_server_map_size,
            "optional_dbg_header_size": optional_dbg_header_size,
            "ec_substream_size": ec_substream_size,
            "flags": flags,
            "machine": machine,
        }

    def check(self):
        """Return a list of human-readable consistency findings (empty = OK).

        The strongest cheap invariant is ``block_size * num_blocks == filesize``.
        If that fails, every offset computed later is garbage.
        """
        problems = []
        size = self.filesize()
        if self.block_size * self.num_blocks != size:
            problems.append(
                "block_size(%d) * num_blocks(%d) = %d != file size %d"
                % (self.block_size, self.num_blocks,
                   self.block_size * self.num_blocks, size)
            )
        return problems

    def filesize(self):
        self._f.seek(0, 2)
        return self._f.tell()

    # ---------------------------------------------------------------- lifecycle

    def close(self):
        if not self._f.closed:
            self._f.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def __repr__(self):
        return "<MSF %s block_size=%d streams=%d>" % (
            self.path, self.block_size, self.num_streams)
