"""Catalogue every datalibrary (DL) instance inside a .dl_bin blob.

Helldivers 2 serializes its gameplay settings with wc-duck/datalibrary. Each
instance is prefixed by a 24-byte header:

    +0   u32  0x444C444C  'LDLD' magic
    +4   u32  version                 (1 on this build)
    +8   u32  root_instance_type      type id -- what this blob IS
    +12  u32  instance_size           payload bytes following the header
    +16  u32  is_64_bit_ptr           (1)
    +20  u32  reserved                (0)

BetterStratagemBounce's in-memory stratagem buffer is 11 such instances of type
0x30EB6399 laid end to end, so the same walk works on the file and in memory.

Usage:
    py -3 -B tools/dl_scan.py <file.dl_bin> [--limit N] [--type 0xHASH]
"""
import argparse
from collections import defaultdict
from pathlib import Path
import struct
import sys

MAGIC = 0x444C444C
HEADER = 24
STRATAGEM_TYPE = 0x30EB6399


def walk(blob, strict=True):
    """Yield (offset, type_id, size, version) for each well-formed instance.

    strict follows the chain head to tail the way the game's loader does; a
    single bad link ends the walk, which is how we detect where the format
    assumption breaks rather than silently resyncing past it.
    """
    offset = 0
    while offset + HEADER <= len(blob):
        magic, version, type_id, size, wide, reserved = struct.unpack_from('<6I', blob, offset)
        if magic != MAGIC:
            if strict:
                return
            offset += 4
            continue
        if offset + HEADER + size > len(blob):
            return
        yield offset, type_id, size, version, wide, reserved
        offset += HEADER + size


def scan_all(blob):
    """Find every LDLD header anywhere, not just the ones on the chain."""
    found = []
    cursor = blob.find(b'LDLD')
    while cursor != -1:
        if cursor + HEADER <= len(blob):
            magic, version, type_id, size, wide, reserved = struct.unpack_from('<6I', blob, cursor)
            if magic == MAGIC and cursor + HEADER + size <= len(blob):
                found.append((cursor, type_id, size, version, wide, reserved))
        cursor = blob.find(b'LDLD', cursor + 1)
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('path', type=Path)
    parser.add_argument('--limit', type=int, default=40, help='instances to print')
    parser.add_argument('--type', help='only show this type id, e.g. 0x30EB6399')
    parser.add_argument('--chain', action='store_true',
                        help='follow the header chain instead of scanning for every magic')
    args = parser.parse_args()

    blob = args.path.read_bytes()
    print('%s  %d bytes' % (args.path.name, len(blob)))

    instances = list(walk(blob)) if args.chain else scan_all(blob)
    if not instances:
        print('no DL instances found')
        return

    wanted = int(args.type, 0) if args.type else None
    by_type = defaultdict(list)
    for offset, type_id, size, version, wide, reserved in instances:
        by_type[type_id].append((offset, size, version, wide, reserved))

    print('\n== %d instance(s), %d distinct type id(s) ==' % (len(instances), len(by_type)))
    ordered = sorted(by_type.items(), key=lambda kv: -sum(s for _, s, _, _, _ in kv[1]))
    print('  %-12s %7s %14s %10s  %s' % ('type id', 'count', 'total bytes', 'max bytes', 'note'))
    for type_id, entries in ordered[:args.limit]:
        total = sum(size for _, size, _, _, _ in entries)
        largest = max(size for _, size, _, _, _ in entries)
        note = 'STRATAGEMS (known)' if type_id == STRATAGEM_TYPE else ''
        print('  0x%08X   %7d %14d %10d  %s' % (type_id, len(entries), total, largest, note))
    if len(ordered) > args.limit:
        print('  ... %d more type id(s)' % (len(ordered) - args.limit))

    if wanted is not None:
        entries = by_type.get(wanted, [])
        print('\n== 0x%08X: %d instance(s) ==' % (wanted, len(entries)))
        for offset, size, version, wide, reserved in entries[:args.limit]:
            print('  offset 0x%08X  size %8d  version %d  wide %d  reserved %d'
                  % (offset, size, version, wide, reserved))
        print('  total payload %d bytes' % sum(size for _, size, _, _, _ in entries))


if __name__ == '__main__':
    main()
