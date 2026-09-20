"""Inspect what is actually deployed in the game's data directory, and why.

Usage:  py -3 -B tools/inspect_patches.py [--game-dir <path>] [--no-logs]

Answers the three questions that matter after a Deploy:
  1. Is the installed build the one the sample mods' hardcoded RVAs target?
  2. Which Lua resources are deployed, in which patch, and who owns them?
  3. What did the loader say about each of them on the last run?
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_ID = '9ba626afa44a3aa3'

# The build BetterStratagemBounce / ControllableHoverPack / KnowYourConstellation
# pinned their RVAs to. A mismatch means every offset in those mods is suspect.
SUPPORTED = {
    'bin/helldivers2.exe': 'A09FF52663E73B94FB0CAC0DCB5BA84FFD10ECF44F74A8921AC66AF923988CC3',
    'data/game/game.dll': 'CC75948D90FDFDE259DCB519E9933DB7FFA3CCB281CE4FB89E6B1B011557470C',
}

REGISTERED = [
    'core/wwise/lua/wwise_flow_callbacks', 'boot',
    'mods/cowboybingus/vanilla_plus_megapack', 'mods/cowboybingus/better_stratagem_bounce',
    'mods/cowboybingus/hellpod_steering_unlocked', 'mods/cowboybingus/wide_angle_stratagems',
    'mods/cowboybingus/reinforcement_beacon_fix_data', 'mods/cowboybingus/consistent_vaulting',
    'mods/cowboybingus/shallow_water_dive', 'mods/cowboybingus/sentry_aim_retention',
    'mods/cowboybingus/corpse_collision_repair', 'mods/cowboybingus/vehicle_stability',
    'mods/cowboybingus/hover_pack_cancel', 'mods/cowboybingus/enemy_intelligence',
    'mods/cowboybingus/armory_preview_cache', 'mods/codex/gun_calibration',
    'mods/codex/loader', 'mods/codex/pickup_icons',
    'mods/example_author/example_mod',
]


def load_packer():
    scripts = str(ROOT / 'vendor' / 'BingusSharedLoader' / 'scripts')
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    import archive
    return archive


def read_config():
    config_path = ROOT / 'mods.json'
    if not config_path.is_file():
        return [], None
    config = json.loads(config_path.read_text(encoding='utf-8'))
    names = ['mods/%s/%s' % (config['namespace'], mod['id']) for mod in config['mods']]
    return names, config.get('game_dir')


def sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest().upper()


def check_build(game_dir):
    print('== Installed build ==')
    for relative, expected in SUPPORTED.items():
        path = game_dir / relative
        if not path.is_file():
            print('  %-22s MISSING (%s)' % (relative, path))
            continue
        actual = sha256(path)
        if actual == expected:
            verdict = 'matches the build the sample mods target'
        else:
            verdict = 'DIFFERENT -> every hardcoded RVA in the samples is invalid'
        print('  %-22s %s...  %s' % (relative, actual[:16], verdict))


def parse_archive(blob):
    """Stingray patch archive: 72-byte header, 32-byte type records, 80-byte file records."""
    if len(blob) < 72:
        return None
    magic, num_types, num_files = struct.unpack_from('<III', blob, 0)
    if magic != 0xF0000011:
        return None
    base = 72 + 32 * num_types
    files = []
    for index in range(num_files):
        record = base + 80 * index
        if record + 80 > len(blob):
            break
        name, type_hash, offset = struct.unpack_from('<QQQ', blob, record)
        size = struct.unpack_from('<I', blob, record + 56)[0]
        files.append((name, type_hash, offset, size))
    return num_types, files


def describe_body(blob, offset, size):
    body = blob[offset:offset + size]
    if len(body) < 9:
        return 'unreadable'
    length, version = struct.unpack_from('<II', body, 0)
    payload = body[8:]
    if payload.startswith(b'\x1bLJ'):
        kind = 'compiled LuaJIT bytecode'
    elif payload.startswith(b'-- HD2-Addon:'):
        declared = payload.split(b'\n', 1)[0].decode('utf-8', 'replace')
        kind = 'plaintext, declares "%s"' % declared[len('-- HD2-Addon: '):].strip()
    else:
        kind = 'plaintext, no addon declaration'
    return 'envelope len=%d ver=%d, %s' % (length, version, kind)


def loader_version(blob):
    found = re.findall(rb'loader-v[0-9]+', blob)
    return found[0].decode('ascii') if found else None


def scan(game_dir, archive):
    known = {archive.resource_hash(name): name for name in REGISTERED}
    mine, _ = read_config()
    for name in mine:
        known[archive.resource_hash(name)] = name + '   <-- YOURS'
    lua_type = archive.resource_hash('lua')

    data_dir = game_dir / 'data'
    patches = [p for p in data_dir.glob(ARCHIVE_ID + '.patch_*')
               if re.fullmatch(r'\.patch_\d+', p.suffix)]
    patches.sort(key=lambda p: int(p.suffix.split('_')[-1]))

    print('\n== Deployed %s archives (higher index wins) ==' % ARCHIVE_ID)
    if not patches:
        print('  none found in %s' % data_dir)
        return
    for path in patches:
        blob = path.read_bytes()
        parsed = parse_archive(blob)
        if not parsed:
            print('  %s  not a patch archive' % path.name)
            continue
        num_types, files = parsed
        version = loader_version(blob)
        suffix = '   [%s]' % version if version else ''
        print('  %s  %d B  types=%d files=%d%s'
              % (path.name, len(blob), num_types, len(files), suffix))
        for name, type_hash, offset, size in files:
            label = known.get(name, '(unrecognized resource)')
            type_label = 'lua' if type_hash == lua_type else '0x%016X' % type_hash
            print('      %016x  %-6s %7d B  %s' % (name, type_label, size, label))
            print('          %s' % describe_body(blob, offset, size))


def show_logs():
    base = os.environ.get('LOCALAPPDATA')
    if not base:
        return
    log_dir = Path(base) / 'CowboyBingus' / 'Helldivers2' / 'Logs'
    print('\n== %s ==' % log_dir)
    if not log_dir.is_dir():
        print('  not created yet - the loader makes it on first run (v14+)')
        return
    logs = sorted(log_dir.glob('*.log'))
    if not logs:
        print('  empty')
    for log in logs:
        print('  --- %s (%d B) ---' % (log.name, log.stat().st_size))
        for line in log.read_text(encoding='utf-8', errors='replace').splitlines():
            print('      ' + line)


def main():
    _, configured = read_config()
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--game-dir', type=Path,
                        default=Path(configured) if configured else None)
    parser.add_argument('--no-logs', action='store_true')
    args = parser.parse_args()
    if args.game_dir is None:
        parser.error('no game_dir in mods.json; pass --game-dir')
    if not args.game_dir.is_dir():
        parser.error('game directory not found: %s' % args.game_dir)

    archive = load_packer()
    check_build(args.game_dir)
    scan(args.game_dir, archive)
    if not args.no_logs:
        show_logs()


if __name__ == '__main__':
    main()
