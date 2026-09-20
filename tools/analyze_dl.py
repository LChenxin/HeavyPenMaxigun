"""Work out the record layout of a settings buffer dumped by mods/hpmg/dl_dump.

The dump is the decrypted datalibrary blob exactly as it sits in the game's
heap, prefixed with a 32-byte header that records the base address. The base
matters: datalibrary fixes up its pointers to absolute addresses at load time,
so turning them back into offsets needs the address the buffer was living at.

What this does:
  1. walks the instance chain and finds each instance's record array
  2. infers the record stride, scoring candidates by how many 8-byte lanes hold
     nothing but zeros and valid in-buffer pointers -- real structs carry
     pointer fields, random misalignment does not
  3. profiles every 4-byte lane across all records and flags the ones that look
     like small enumerations (armour penetration) or damage-shaped integers
  4. resolves pointer lanes that land on printable text, which is how records
     get their names

Ground truth: stratagem_settings must come out as 147 records of 400 bytes with
lane 0x170 holding BetterStratagemBounce's 147 published flag values, 101 of
them with bit 1 set. --selftest checks the stride inference against a synthetic
buffer without needing a dump at all.

Usage:
    py -3 -B tools/analyze_dl.py <dump.bin> [--records N] [--lane 0x170]
    py -3 -B tools/analyze_dl.py --selftest
"""
import argparse
from collections import Counter
from pathlib import Path
import random
import struct
import sys

HEADER_MAGIC = b'HPMGDUMP'
HEADER_SIZE = 32
DL_MAGIC = 0x444C444C

# navigation_patch.lua's published vanilla flags, in stratagem-id order.
STRATAGEM_VANILLA_FLAGS = [
    2, 2, 0, 0, 2, 2, 0, 2, 2, 0, 2, 2, 2, 2, 2, 2, 0, 2, 3, 0, 2,
    2, 2, 2, 2, 0, 0, 2, 0, 2, 2, 2, 0, 1, 2, 1, 0, 2, 1, 0, 2, 2,
    2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 0, 2, 2, 0,
    2, 2, 2, 3, 2, 0, 0, 2, 0, 2, 2, 2, 2, 2, 2, 2, 3, 0, 2, 3, 2,
    2, 0, 2, 3, 0, 2, 1, 0, 2, 2, 2, 1, 2, 2, 2, 0, 2, 2, 2, 0, 0,
    2, 3, 2, 0, 2, 2, 2, 2, 2, 2, 0, 2, 2, 2, 2, 0, 0, 0, 0, 2, 0,
    2, 2, 2, 0, 0, 2, 2, 0, 2, 0, 2, 0, 2, 2, 3, 2, 0, 0, 2, 0, 2,
]


# Published in-game stats, used to find a specific record without field names.
# Every number a weapon shows in the armoury is a value that must appear
# somewhere in its record, so a handful of them together identify it.
PROFILES = {
    'maxigun': {
        'label': 'M-1000 Maxigun (support weapon, Python Commandos warbond)',
        # value -> what it is. Every entry is tried BOTH as a 32-bit integer and
        # as a float: the engine stores damage as 80.0f, whose raw u32 is
        # 0x42A00000, so an int-only search misses it completely. Derived forms
        # are included because a stat is rarely stored in the unit the UI shows.
        'values': {
            80: 'damage',
            18: 'durable damage',
            1000: 'capacity (backpack)',
            500: 'capacity from supply box',
            250: 'capacity from ammo box',
            1500: 'fire rate rpm',
            25: 'fire rate rounds/sec (1500/60)',
            2000: 'DPS',
            17.5: 'recoil horizontal',
            21.25: 'recoil combined',
            0.5: 'spin-up seconds',
            0.04: 'shot period seconds (60/1500)',
            22.5: 'durable damage percent (18/80)',
            0.225: 'durable damage fraction',
            40: 'sustained fire seconds',
            4: 'ergonomics',
        },
    },
}


def float_at(dump, offset):
    return struct.unpack_from('<f', dump.data, offset)[0]


def fingerprint(dump, items, count, stride, profile, top=8):
    """Score every record by how many of the profile's published values it holds.

    Each lane is read twice, as u32 and as float, because there is no way to
    know up front which way a given stat is stored. Only whole-number targets
    are tried as integers; 17.5 can never be an int lane.
    """
    values = profile['values']
    as_int = {int(v): name for v, name in values.items() if float(v).is_integer()}
    scored = []
    for index in range(count):
        record = items + index * stride
        matched = {}
        for lane in range(0, stride - 3, 4):
            raw = dump.u32(record + lane)
            if raw in as_int:
                matched.setdefault(as_int[raw], []).append((lane, 'int %d' % raw))
            shown = float_at(dump, record + lane)
            if shown == shown and abs(shown) < 1e9:
                for target, name in values.items():
                    if abs(shown - target) < 1e-6 * max(1.0, abs(target)):
                        matched.setdefault(name, []).append((lane, 'float %g' % shown))
        if matched:
            scored.append((len(matched), index, matched))
    scored.sort(key=lambda row: (-row[0], row[1]))
    return scored[:top], len(scored)


def penetration_quads(dump, items, count, stride):
    """Find 4 consecutive small-int lanes shaped like HD2 angle-based armour penetration.

    The wiki lists the Maxigun as Medium for direct, slight and large angles and
    Unarmored at extreme angle, so the stored quad should be three equal values
    followed by a smaller one.
    """
    found = []
    for lane in range(0, stride - 15, 4):
        shaped = 0
        samples = []
        for index in range(count):
            record = items + index * stride
            quad = [dump.u32(record + lane + step * 4) for step in range(4)]
            if any(value > 12 for value in quad):
                shaped = -1
                break
            if quad[0] == quad[1] == quad[2] and quad[3] <= quad[0] and quad[0] > 0:
                shaped += 1
                if len(samples) < 6:
                    samples.append((index, quad))
        if shaped > 0:
            found.append((lane, shaped, count, samples))
    found.sort(key=lambda row: -row[1])
    return found


class Dump:
    def __init__(self, blob):
        if not blob.startswith(HEADER_MAGIC):
            raise ValueError('not an HPMGDUMP file')
        version, type_id = struct.unpack_from('<II', blob, 8)
        base, = struct.unpack_from('<Q', blob, 16)
        size, instances = struct.unpack_from('<II', blob, 24)
        if version != 1:
            raise ValueError('unsupported dump version %d' % version)
        self.type_id = type_id
        self.base = base
        self.size = size
        self.declared_instances = instances
        self.data = blob[HEADER_SIZE:HEADER_SIZE + size]
        if len(self.data) != size:
            raise ValueError('truncated dump: %d of %d bytes' % (len(self.data), size))

    def u32(self, offset):
        return struct.unpack_from('<I', self.data, offset)[0]

    def u64(self, offset):
        return struct.unpack_from('<Q', self.data, offset)[0]

    def to_offset(self, pointer):
        """Absolute pointer -> buffer offset, or None if it points elsewhere."""
        if pointer == 0:
            return None
        delta = pointer - self.base
        if 0 <= delta < self.size:
            return delta
        return None

    def instances(self):
        """Yield (root_offset, payload_end, type_id, item_offset, item_count)."""
        count = self.u32(0)
        offset = 4
        for _ in range(count):
            magic, version, type_id, payload = struct.unpack_from('<IIII', self.data, offset)
            if magic != DL_MAGIC or version != 1:
                raise ValueError('broken instance chain at 0x%X' % offset)
            root = offset + 24
            end = root + payload
            items = self.to_offset(self.u64(root))
            item_count = self.u32(root + 8)
            yield root, end, type_id, items, item_count
            offset = end

    def cstring(self, offset, limit=128):
        end = self.data.find(b'\0', offset, min(offset + limit, self.size))
        if end <= offset:
            return None
        raw = self.data[offset:end]
        try:
            text = raw.decode('utf-8')
        except UnicodeDecodeError:
            return None
        if not all(32 <= ord(c) < 127 or c in '\t' for c in text):
            return None
        return text


def score_stride(dump, start, count, stride):
    """How many 8-byte lanes hold only zeros and valid in-buffer pointers."""
    if count < 2 or stride < 8 or stride % 8:
        return -1
    if start + count * stride > dump.size:
        return -1
    lanes = 0
    for lane in range(0, stride, 8):
        zeros = 0
        pointers = 0
        for index in range(count):
            value = dump.u64(start + index * stride + lane)
            if value == 0:
                zeros += 1
            elif dump.to_offset(value) is not None:
                pointers += 1
            else:
                break
        else:
            # A lane of all zeros proves nothing; require real pointers in it.
            if pointers >= max(2, count // 4):
                lanes += 1
    return lanes


def infer_stride(dump, start, count, span):
    """Pick the record stride that best explains the array."""
    if count < 1:
        return None, []
    ceiling = span // count
    candidates = []
    for stride in range(8, ceiling + 1, 8):
        score = score_stride(dump, start, count, stride)
        if score > 0:
            waste = span - count * stride
            candidates.append((score, -waste, stride))
    if not candidates:
        # No pointer lanes: fall back to the tightest exact fit.
        if ceiling >= 8:
            return (ceiling // 8) * 8, []
        return None, []
    candidates.sort(reverse=True)
    best = candidates[0][2]
    return best, [(s, st) for s, _, st in candidates[:6]]


def profile_lanes(dump, start, count, stride, top=None):
    """Describe every 4-byte lane across the record array."""
    rows = []
    for lane in range(0, stride, 4):
        values = [dump.u32(start + index * stride + lane) for index in range(count)]
        distinct = len(set(values))
        low = min(values)
        high = max(values)
        floats = struct.unpack('<%df' % count, b''.join(struct.pack('<I', v) for v in values))
        finite = [f for f in floats if f == f and abs(f) < 1e12]
        kind = []
        if distinct == 1:
            kind.append('constant')
        if high <= 32 and distinct > 1:
            kind.append('SMALL-ENUM')
        if 1 <= low and high <= 5000 and distinct > 4 and high > 32:
            kind.append('int-range')
        if len(finite) == count and any(abs(f) > 1e-6 for f in finite) and all(abs(f) < 1e6 for f in finite):
            kind.append('float-like')
        if distinct == count and count > 4:
            kind.append('unique')
        rows.append({'lane': lane, 'distinct': distinct, 'low': low, 'high': high,
                     'kind': kind, 'values': values, 'floats': floats})
    if top:
        rows = [r for r in rows if r['kind']]
    return rows


def pointer_lanes(dump, start, count, stride, samples=6):
    """Pointer lanes and any text they resolve to."""
    found = []
    for lane in range(0, stride, 8):
        texts = []
        valid = 0
        for index in range(count):
            value = dump.u64(start + index * stride + lane)
            if value == 0:
                continue
            target = dump.to_offset(value)
            if target is None:
                valid = -1
                break
            valid += 1
            if len(texts) < samples:
                text = dump.cstring(target)
                if text:
                    texts.append(text)
        if valid > 0:
            found.append((lane, valid, texts))
    return found


def analyse(dump, args):
    print('type 0x%08X  base 0x%012X  size %d  declared instances %d'
          % (dump.type_id, dump.base, dump.size, dump.declared_instances))

    total_records = 0
    arrays = []
    for root, end, type_id, items, item_count in dump.instances():
        span = end - items if items is not None else 0
        print('\ninstance root 0x%06X..0x%06X  type 0x%08X  items @0x%06X  count %d  span %d'
              % (root, end, type_id, items if items is not None else -1, item_count, span))
        if items is None or item_count == 0:
            print('  no record array')
            continue
        stride, ranked = infer_stride(dump, items, item_count, span)
        if stride is None:
            print('  could not infer a stride')
            continue
        used = item_count * stride
        print('  stride %d  -> %d records, %d of %d bytes used (%d trailing)'
              % (stride, item_count, used, span, span - used))
        if ranked:
            print('  stride candidates (pointer-lane score): '
                  + ', '.join('%d:%d' % (st, sc) for sc, st in ranked))
        total_records += item_count
        arrays.append((items, item_count, stride))

    print('\ntotal records across instances: %d' % total_records)

    if not arrays:
        return

    # Profile the largest array; that is where the interesting fields live.
    items, count, stride = max(arrays, key=lambda a: a[1] * a[2])
    print('\n== lane profile: array @0x%06X, %d records x %d bytes ==' % (items, count, stride))
    rows = profile_lanes(dump, items, count, stride, top=not args.all_lanes)
    print('  %-8s %8s %12s %12s  %s' % ('lane', 'distinct', 'min', 'max', 'looks like'))
    for row in rows[:args.max_lanes]:
        print('  +0x%04X  %8d %12d %12d  %s'
              % (row['lane'], row['distinct'], row['low'], row['high'], ', '.join(row['kind'])))
    if len(rows) > args.max_lanes:
        print('  ... %d more lanes (use --max-lanes)' % (len(rows) - args.max_lanes))

    pointers = pointer_lanes(dump, items, count, stride)
    if pointers:
        print('\n== pointer lanes ==')
        for lane, valid, texts in pointers:
            sample = ('  e.g. ' + ', '.join(repr(t) for t in texts)) if texts else ''
            print('  +0x%04X  %d/%d non-null resolve inside the buffer%s' % (lane, valid, count, sample))

    if args.fingerprint:
        profile = PROFILES[args.fingerprint]
        hits, total = fingerprint(dump, items, count, stride, profile)
        print('\n== fingerprint: %s ==' % profile['label'])
        print('  %d of %d records hold at least one published value' % (total, count))
        if not hits:
            print('  no record matched; this buffer probably does not hold this weapon')
        for score, index, matched in hits:
            print('  record [%3d]  %d distinct stat(s) matched' % (index, score))
            for name, places in sorted(matched.items()):
                spots = ", ".join("+0x%04X=%s" % (lane, value) for lane, value in places[:4])
                print('      %-32s %s' % (name, spots))

    if args.ap:
        quads = penetration_quads(dump, items, count, stride)
        print('\n== angle-based penetration quad candidates ==')
        if not quads:
            print('  none found')
        for lane, shaped, total, samples in quads[:args.max_lanes]:
            print('  +0x%04X  %d/%d records shaped [a,a,a,b<=a]' % (lane, shaped, total))
            for index, quad in samples:
                print('      [%3d] %s' % (index, quad))

    if args.record is not None:
        wanted = [int(v) for v in args.record.split(',')]
        print('\n== records %s, every lane ==' % wanted)
        lanes = list(range(0, stride, 4))
        header = '  %-8s' % 'lane' + ''.join('%22s' % ('[%d]' % i) for i in wanted)
        print(header)
        for lane in lanes:
            cells = []
            interesting = False
            for index in wanted:
                offset = items + index * stride + lane
                raw = dump.u32(offset)
                value = float_at(dump, offset)
                target = dump.to_offset(dump.u64(offset)) if lane % 8 == 0 else None
                text = dump.cstring(target) if target is not None else None
                if text:
                    cell = repr(text)[:20]
                elif raw == 0:
                    cell = '.'
                elif 1e-4 < abs(value) < 1e7:
                    cell = '%g' % value if value != int(value) else '%d/%gf' % (raw, value)
                    interesting = True
                else:
                    cell = '%d' % raw
                    interesting = True
                cells.append('%22s' % cell[:22])
            if interesting or args.all_lanes:
                print('  +0x%04X ' % lane + ''.join(cells))

    if args.lane is not None:
        lane = args.lane
        values = [dump.u32(items + index * stride + lane) for index in range(count)]
        print('\n== lane +0x%04X across %d records ==' % (lane, count))
        print('  histogram: %s' % dict(sorted(Counter(values).items())))
        print('  first %d: %s' % (min(args.records, count), values[:args.records]))

    if args.records:
        print('\n== first %d records, leading %d bytes ==' % (min(args.records, count), args.width))
        for index in range(min(args.records, count)):
            chunk = dump.data[items + index * stride: items + index * stride + args.width]
            print('  [%3d] %s' % (index, chunk.hex(' ', 4)))


def check_ground_truth(dump):
    """stratagem_settings has a published answer; verify against it."""
    records = []
    for root, end, type_id, items, item_count in dump.instances():
        if items is None:
            continue
        for index in range(item_count):
            offset = items + index * 400
            if offset + 400 > dump.size:
                return False, 'record %d runs past the buffer' % index
            records.append(offset)
    if len(records) != 147:
        return False, 'expected 147 records, found %d' % len(records)
    flags = {}
    for offset in records:
        kind = dump.u32(offset)
        if not 1 <= kind <= len(STRATAGEM_VANILLA_FLAGS):
            return False, 'stratagem id %d out of range' % kind
        flags[kind] = dump.data[offset + 0x170]
    if len(flags) != 147:
        return False, 'duplicate stratagem ids'
    mismatches = [k for k, v in flags.items() if v != STRATAGEM_VANILLA_FLAGS[k - 1]]
    if mismatches:
        return False, '%d flag(s) differ from the published values: %s' % (len(mismatches), mismatches[:8])
    navmesh = sum(1 for v in flags.values() if v & 2)
    if navmesh != 101:
        return False, 'expected 101 records with bit 1 set, found %d' % navmesh
    return True, ('147 records of 400 bytes, lane 0x170 matches all 147 published flags, '
                  '101 with the navigation bit set')


def selftest():
    """Stride inference has to work before any real dump is trusted."""
    random.seed(20260920)
    base = 0x1CFB4E20000
    stride, count = 400, 147
    header_size = 4 + 24
    items = header_size + 64
    names_at = items + count * stride
    names = b''.join(('projectile_%d' % i).encode() + b'\0' for i in range(count))
    size = names_at + len(names)
    data = bytearray(size)

    struct.pack_into('<I', data, 0, 1)
    struct.pack_into('<IIII', data, 4, DL_MAGIC, 1, 0xBD4042C2, size - header_size)
    struct.pack_into('<II', data, 20, 1, 0)
    struct.pack_into('<Q', data, 28, base + items)
    struct.pack_into('<I', data, 36, count)

    # One record is given the Maxigun's published numbers; the rest get
    # plausible but different ones, so the fingerprint has to actually
    # discriminate rather than match everything.
    planted = 42
    cursor = names_at
    for index in range(count):
        record = items + index * stride
        struct.pack_into('<I', data, record, index + 1)
        if index == planted:
            struct.pack_into('<IIII', data, record + 8, 80, 18, 1000, 1500)
            struct.pack_into('<IIII', data, record + 32, 3, 3, 3, 0)
            struct.pack_into('<fff', data, record + 48, 17.5, 25.0, 0.5)
        else:
            struct.pack_into('<IIII', data, record + 8,
                             random.choice([55, 60, 70, 150, 200]),
                             random.choice([10, 12, 30, 45]),
                             random.choice([30, 45, 100, 275]),
                             random.choice([200, 640, 900, 1100]))
            armour = random.choice([2, 3, 4, 5])
            struct.pack_into('<IIII', data, record + 32, armour, armour, armour,
                             random.choice([0, 1, armour]))
            struct.pack_into('<fff', data, record + 48,
                             random.uniform(5, 40), random.uniform(5, 40), random.uniform(0.1, 2.0))
        struct.pack_into('<Q', data, record + 24, base + cursor)
        cursor += len('projectile_%d' % index) + 1
    data[names_at:names_at + len(names)] = names

    blob = (HEADER_MAGIC + struct.pack('<II', 1, 0xBD4042C2)
            + struct.pack('<Q', base) + struct.pack('<II', size, 1) + bytes(data))
    dump = Dump(blob)
    root, end, type_id, found_items, found_count = next(iter(dump.instances()))
    assert found_items == items, 'items offset %d != %d' % (found_items, items)
    assert found_count == count, 'count %d != %d' % (found_count, count)
    inferred, ranked = infer_stride(dump, found_items, found_count, end - found_items)
    print('selftest: items @0x%X count %d -> inferred stride %s (expected %d)'
          % (found_items, found_count, inferred, stride))
    assert inferred == stride, 'stride inference returned %s' % inferred
    lanes = pointer_lanes(dump, found_items, found_count, stride)
    assert any(lane == 24 and texts for lane, _, texts in lanes), 'name lane not resolved'
    print('selftest: name lane resolved, e.g. %s'
          % next(texts[:2] for lane, _, texts in lanes if lane == 24))

    hits, total = fingerprint(dump, found_items, found_count, stride, PROFILES['maxigun'])
    assert hits, 'fingerprint found nothing'
    top_score, top_index, matched = hits[0]
    print('selftest: fingerprint top record [%d] with %d stat(s); %d records matched anything'
          % (top_index, top_score, total))
    assert top_index == planted, 'fingerprint picked record %d, planted %d' % (top_index, planted)
    assert top_score >= 6, 'expected at least 6 matching stats, got %d' % top_score
    runner_up = hits[1][0] if len(hits) > 1 else 0
    assert top_score > runner_up, 'planted record did not stand out (%d vs %d)' % (top_score, runner_up)

    quads = penetration_quads(dump, found_items, found_count, stride)
    assert quads, 'no penetration quad found'
    assert quads[0][0] == 32, 'quad detector picked lane 0x%X, planted at 0x20' % quads[0][0]
    print('selftest: penetration quad found at +0x%04X in %d/%d records'
          % (quads[0][0], quads[0][1], quads[0][2]))
    print('selftest OK')


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('path', nargs='?', type=Path)
    parser.add_argument('--records', type=int, default=8, help='records to hex dump')
    parser.add_argument('--width', type=int, default=64, help='bytes per record in the hex dump')
    parser.add_argument('--lane', type=lambda v: int(v, 0), help='histogram this 4-byte lane')
    parser.add_argument('--max-lanes', type=int, default=40)
    parser.add_argument('--all-lanes', action='store_true', help='include unremarkable lanes')
    parser.add_argument('--fingerprint', choices=sorted(PROFILES),
                        help='rank records against a weapon\'s published stats')
    parser.add_argument('--ap', action='store_true',
                        help='look for angle-based armour penetration quads')
    parser.add_argument('--record', help='print every lane of these record indices, e.g. 17,18,19,20')
    parser.add_argument('--selftest', action='store_true')
    args = parser.parse_args()

    if args.selftest:
        selftest()
        return
    if not args.path:
        parser.error('give a dump path, or --selftest')

    dump = Dump(args.path.read_bytes())
    analyse(dump, args)

    if 'stratagem' in args.path.name:
        ok, note = check_ground_truth(dump)
        print('\n== ground truth ==')
        print('  %s  %s' % ('PASS' if ok else 'FAIL', note))
        if not ok:
            sys.exit(1)


if __name__ == '__main__':
    main()
