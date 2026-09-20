"""Run every tests/*.lua file in an embedded LuaJIT 2.1 runtime.

The game runs LuaJIT, so the offline suite has to as well: the probe relies on
FFI, 64-bit integer literals and LuaJIT's cdata arithmetic, none of which behave
the same under stock Lua.

    .venv/Scripts/python.exe tests/run.py [name ...]
"""
from pathlib import Path
import sys

from lupa.luajit21 import LuaRuntime

ROOT = Path(__file__).resolve().parents[1]


def run(path):
    print('=' * 70)
    print(path.relative_to(ROOT))
    print('=' * 70)
    lua = LuaRuntime(unpack_returned_tuples=True)
    # Tests load module sources with paths relative to the project root.
    lua.execute('package.path = [[%s/?.lua;]] .. package.path' % ROOT.as_posix())
    exit_code = {'value': 0}

    def fake_exit(code=0):
        exit_code['value'] = int(code or 0)
        raise RuntimeError('__lua_exit__%d' % exit_code['value'])

    lua.globals().os.exit = fake_exit
    source = path.read_text(encoding='utf-8')
    try:
        lua.execute(source)
    except Exception as error:
        if '__lua_exit__' in str(error):
            return exit_code['value']
        print('LUA ERROR: %s' % error)
        return 1
    return exit_code['value']


def cross_language_check():
    """The Lua dumper and the Python analyser share a file format; prove it.

    test_dl_dump.lua writes a complete dump with the same writer the mod uses.
    If the analyser cannot read it, the two sides have drifted apart -- which is
    the kind of mismatch that otherwise only shows up as quiet nonsense in a
    later analysis.
    """
    artifact = ROOT / 'tests' / '_artifacts' / 'lua_dump.bin'
    if not artifact.is_file():
        return True
    sys.path.insert(0, str(ROOT / 'tools'))
    from analyze_dl import Dump

    print('=' * 70)
    print('cross-language: tools/analyze_dl.py reads the Lua-written dump')
    print('=' * 70)
    try:
        dump = Dump(artifact.read_bytes())
        instances = list(dump.instances())
    except Exception as error:
        print('  FAIL %s: %s' % (type(error).__name__, error))
        return False
    problems = []
    if dump.type_id != 0xBD4042C2:
        problems.append('type id 0x%08X' % dump.type_id)
    if dump.base != 0x1000000:
        problems.append('base 0x%X' % dump.base)
    if dump.declared_instances != 1 or len(instances) != 1:
        problems.append('instances %d/%d' % (dump.declared_instances, len(instances)))
    if problems:
        print('  FAIL ' + ', '.join(problems))
        return False
    print('  OK  type 0x%08X, base 0x%X, %d instance, %d bytes'
          % (dump.type_id, dump.base, len(instances), dump.size))
    return True


def main():
    wanted = sys.argv[1:]
    tests = sorted((ROOT / 'tests').glob('test_*.lua'))
    if wanted:
        tests = [t for t in tests if any(w in t.name for w in wanted)]
    if not tests:
        raise SystemExit('no tests matched')

    import os
    (ROOT / 'tests' / '_artifacts').mkdir(exist_ok=True)
    os.chdir(ROOT)

    failed = []
    for path in tests:
        if run(path) != 0:
            failed.append(path.name)
        print()

    if not cross_language_check():
        failed.append('cross-language dump format')
    print()

    if failed:
        raise SystemExit('FAILED: ' + ', '.join(failed))
    print('all %d test file(s) passed' % len(tests))


if __name__ == '__main__':
    main()
