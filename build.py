"""Build this project's HD2 addons into manager-importable ZIPs.

Usage:  py -3 -B build.py [--only <mod id>] [--config mods.json]

Packaging is delegated to BingusSharedLoader's own scripts/build_addon.py so the
archive format always matches whatever loader release we target. That source is
bootstrapped into vendor/ from samplefile/ on first run; vendor/ is not tracked.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import sys
import zipfile

ROOT = Path(__file__).resolve().parent
VENDOR = ROOT / 'vendor' / 'BingusSharedLoader'
LOADER_SOURCE_ZIP = ROOT / 'samplefile' / 'BingusSharedLoader-main.zip'


BOOTSTRAP_HELP = """\
Cannot bootstrap the packer: %s is missing.

Packaging is delegated to Bingus Shared Loader's own scripts/build_addon.py so
the archive format always matches the loader release being targeted. That source
is not vendored into this repository.

Get it either way:
  * download the BingusSharedLoader source zip and drop it at the path above, or
  * clone https://github.com/CowboyBingus/BingusSharedLoader and point at it:
        set HPMG_BSL_SOURCE=C:\\path\\to\\BingusSharedLoader
"""


def ensure_vendor():
    if (VENDOR / 'scripts' / 'build_addon.py').is_file():
        return
    external = os.environ.get('HPMG_BSL_SOURCE')
    if external:
        candidate = Path(external)
        if (candidate / 'scripts' / 'build_addon.py').is_file():
            VENDOR.parent.mkdir(parents=True, exist_ok=True)
            if VENDOR.exists():
                shutil.rmtree(VENDOR)
            shutil.copytree(candidate, VENDOR)
            print('Bootstrapped %s from HPMG_BSL_SOURCE' % VENDOR.relative_to(ROOT))
            return
        sys.exit('HPMG_BSL_SOURCE=%s has no scripts/build_addon.py' % external)
    if not LOADER_SOURCE_ZIP.is_file():
        sys.exit(BOOTSTRAP_HELP % LOADER_SOURCE_ZIP)
    VENDOR.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(LOADER_SOURCE_ZIP) as package:
        package.extractall(VENDOR.parent)
    extracted = VENDOR.parent / 'BingusSharedLoader-main'
    if extracted.is_dir():
        if VENDOR.exists():
            shutil.rmtree(VENDOR)
        extracted.rename(VENDOR)
    print('Bootstrapped %s from %s' % (VENDOR.relative_to(ROOT), LOADER_SOURCE_ZIP.name))


def load_packer():
    ensure_vendor()
    scripts = str(VENDOR / 'scripts')
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    import archive
    import build_addon
    return build_addon, archive


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--config', type=Path, default=ROOT / 'mods.json')
    parser.add_argument('--only', action='append', metavar='ID',
                        help='build only this mod id; repeatable')
    args = parser.parse_args()

    config = json.loads(args.config.read_text(encoding='utf-8'))
    namespace = config['namespace']
    build_addon, archive = load_packer()

    built = []
    for mod in config['mods']:
        if not mod.get('enabled', True):
            continue
        if args.only and mod['id'] not in args.only:
            continue
        name = 'mods/%s/%s' % (namespace, mod['id'])
        entry = ROOT / mod['entry']
        if not entry.is_file():
            sys.exit('%s: entry %s not found' % (mod['id'], entry))
        source = entry.read_bytes()
        output = ROOT / mod['output']
        # build_addon rejects a mismatched or malformed first-line declaration,
        # which is exactly the failure we want surfaced at build time.
        build_addon.build_addon(name, source, mod['guid'], output, mod['display_name'])
        built.append((name, archive.resource_hash(name), len(source), output))

    if not built:
        sys.exit('Nothing to build: check "enabled" in %s' % args.config.name)

    width = max(len(name) for name, _, _, _ in built)
    for name, digest, size, output in built:
        print('%-*s  %016x  %5d B lua  ->  %s'
              % (width, name, digest, size, output.relative_to(ROOT)))
    print('\n%d package(s) ready. Import them into Arsenal or HD2MM, enable, then Purge / Deploy.'
          % len(built))


if __name__ == '__main__':
    main()
