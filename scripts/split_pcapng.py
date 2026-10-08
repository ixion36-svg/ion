#!/usr/bin/env python3
"""Split a pcapng capture into independently-readable chunks.

A pcapng file is not a flat packet stream: it opens with a Section Header
Block and one Interface Description Block per capture interface, and every
Enhanced Packet Block refers to an interface *by index into that IDB list*.
Cutting the file at an arbitrary byte offset therefore produces chunks that
no reader can open, and cutting it after the headers produces chunks whose
packets reference interfaces that are not declared.

So each chunk here is written as: the original SHB, every IDB that preceded
the first packet, then a run of packet blocks. Each chunk is a valid pcapng
in its own right, which is what Arkime's `capture -r` and ION's PCAP job
both need.

Why split at all: ION's upload cap is 100 MB per job, Arkime ingests per
file, and a single multi-gigabyte capture is a poor unit of analysis
regardless -- an analyst wants the five minutes around an alert, not the
whole shift.

Usage:
    split_pcapng.py capture.pcapng --size-mb 20
    split_pcapng.py capture.pcapng --packets 5000 --out-dir chunks/
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

#: Block types we must carry into every chunk for it to be readable.
SHB = 0x0A0D0D0A  # Section Header Block
IDB = 0x00000001  # Interface Description Block

#: Byte-Order Magic inside an SHB, used to detect endianness.
BOM_LE = 0x1A2B3C4D

#: Blocks that carry packets. Everything else (name resolution, statistics,
#: custom blocks) is preserved in the preamble if it appears before the first
#: packet, and otherwise passed through into the current chunk.
PACKET_BLOCKS = {
    0x00000006,  # Enhanced Packet Block
    0x00000003,  # Simple Packet Block
    0x00000002,  # obsolete Packet Block, still emitted by some writers
}


class PcapngError(Exception):
    pass


def _read_block(fh) -> tuple | None:
    """Return ``(block_type, raw_bytes)`` or None at clean EOF.

    Reads the 4-byte type and 4-byte total length, then the remainder. The
    trailing length field is included in ``raw_bytes`` so a block can be
    written back verbatim.
    """
    head = fh.read(8)
    if not head:
        return None
    if len(head) < 8:
        raise PcapngError(f"truncated block header: {len(head)} bytes")

    # Endianness is resolved from the SHB before any other block is read, so
    # a single struct format is safe from here on. The SHB itself is read
    # with the detected order by _detect_endianness.
    block_type, total_len = struct.unpack(_ENDIAN + "II", head)
    if total_len < 12:
        raise PcapngError(f"implausible block length {total_len}")

    body = fh.read(total_len - 8)
    if len(body) != total_len - 8:
        raise PcapngError("truncated block body; capture ends mid-block")
    return block_type, head + body


_ENDIAN = "<"


def _detect_endianness(path: Path) -> str:
    """Read the SHB's byte-order magic.

    Getting this wrong does not fail loudly -- it yields absurd block
    lengths -- so it is resolved once, up front, from the file itself rather
    than assumed.
    """
    with path.open("rb") as fh:
        head = fh.read(12)
    if len(head) < 12:
        raise PcapngError("file is too short to be a pcapng")
    if struct.unpack("<I", head[:4])[0] != SHB:
        raise PcapngError(
            "not a pcapng (no Section Header Block). A classic .pcap starts "
            "0xa1b2c3d4 and needs a different splitter."
        )
    if struct.unpack("<I", head[8:12])[0] == BOM_LE:
        return "<"
    if struct.unpack(">I", head[8:12])[0] == BOM_LE:
        return ">"
    raise PcapngError("unrecognised byte-order magic in the Section Header Block")


def split(path: Path, out_dir: Path, size_bytes: int | None,
          packet_limit: int | None) -> list:
    global _ENDIAN
    _ENDIAN = _detect_endianness(path)

    out_dir.mkdir(parents=True, exist_ok=True)
    stem = path.stem

    preamble: list = []
    chunks: list = []
    chunk_index = 0
    out = None
    written = 0
    packets = 0

    def _open_chunk():
        nonlocal out, written, packets, chunk_index
        chunk_index += 1
        target = out_dir / f"{stem}-{chunk_index:03d}.pcapng"
        out = target.open("wb")
        for blk in preamble:
            out.write(blk)
        written = sum(len(b) for b in preamble)
        packets = 0
        return target

    def _close_chunk(target):
        nonlocal out
        if out is None:
            return
        out.close()
        out = None
        chunks.append((target, packets, written))

    target = None
    with path.open("rb") as fh:
        while True:
            try:
                block = _read_block(fh)
            except PcapngError as exc:
                # A capture stopped mid-write ends mid-block. Everything
                # already split is still valid, so report and keep it.
                print(f"  warning: {exc}; keeping {len(chunks)} complete chunk(s)",
                      file=sys.stderr)
                break
            if block is None:
                break
            block_type, raw = block

            if block_type in (SHB, IDB) and out is None:
                preamble.append(raw)
                continue

            if out is None:
                target = _open_chunk()

            # A new section mid-file means the writer restarted; begin a new
            # chunk so the old section's interface indices do not leak in.
            if block_type == SHB:
                _close_chunk(target)
                preamble.clear()
                preamble.append(raw)
                continue
            if block_type == IDB:
                preamble.append(raw)

            out.write(raw)
            written += len(raw)
            if block_type in PACKET_BLOCKS:
                packets += 1

            full = (size_bytes is not None and written >= size_bytes) or \
                   (packet_limit is not None and packets >= packet_limit)
            if full:
                _close_chunk(target)

    _close_chunk(target)
    return chunks


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("capture", type=Path)
    ap.add_argument("--out-dir", type=Path, default=None)
    ap.add_argument("--size-mb", type=float, default=None,
                    help="start a new chunk past this size (default 20)")
    ap.add_argument("--packets", type=int, default=None,
                    help="start a new chunk after this many packets")
    args = ap.parse_args()

    if args.size_mb is None and args.packets is None:
        args.size_mb = 20.0
    size_bytes = int(args.size_mb * 1024 * 1024) if args.size_mb else None

    if not args.capture.is_file():
        print(f"no such capture: {args.capture}", file=sys.stderr)
        return 2

    out_dir = args.out_dir or args.capture.with_suffix("").parent / f"{args.capture.stem}-chunks"

    try:
        chunks = split(args.capture, out_dir, size_bytes, args.packets)
    except PcapngError as exc:
        print(f"cannot split: {exc}", file=sys.stderr)
        return 1

    total_packets = sum(c[1] for c in chunks)
    print(f"{args.capture.name} -> {len(chunks)} chunk(s) in {out_dir}")
    for target, packets, written in chunks:
        print(f"  {target.name:<34}{packets:>7} packets  {written/1048576:>7.1f} MB")
    print(f"  {'total':<34}{total_packets:>7} packets")
    return 0


if __name__ == "__main__":
    sys.exit(main())
