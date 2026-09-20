# Building from source

## Requirements

- Python 3.11 or newer. On Windows invoke it as `py -3`.
- Packaging itself needs only the standard library — no LuaJIT, no game files.
- Tests and the offline analysis tools need a virtual environment:

```powershell
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install capstone pefile lupa
```

`lupa` supplies the embedded LuaJIT 2.1 the test suite runs under, which is the
same runtime the game uses. Stock Lua will not do: the modules rely on FFI,
64-bit integer literals and cdata arithmetic.

## The packer

Archives are built by Bingus Shared Loader's own `scripts/build_addon.py` rather
than a copy of it, so the archive format always matches the loader release being
targeted. That source is not vendored here. Supply it either way:

- place the BingusSharedLoader source zip at
  `samplefile/BingusSharedLoader-main.zip`, or
- clone it and point at the checkout:

```powershell
set HPMG_BSL_SOURCE=C:\path\to\BingusSharedLoader
```

`build.py` extracts it into `vendor/` on first run. Both `samplefile/` and
`vendor/` are untracked; third-party archives are not redistributed from this
repository.

## Build

```powershell
py -3 -B build.py
py -3 -B build.py --only heavy_pen_maxigun
```

Output lands in `dist/`. Each line reports the game resource name and its
seed-zero MurmurHash64A, which is the identifier the archive stores and what
`tools/inspect_patches.py` prints back from a deployed game.

`mods.json` holds the namespace, each module's stable GUID and its output path.
**A published GUID must never change** — managers identify a mod by it.

## Test

```powershell
.venv\Scripts\python.exe tests\run.py
.venv\Scripts\python.exe tests\run.py heavy_pen
```

Every module exposes its internals on its global state table so the suite can
drive them against synthetic buffers without attaching to the game.

Two properties are worth preserving when adding tests:

- **Anything that touches real memory must be exercised for real.** Stubbing the
  Win32 layer once let a `void *` arithmetic fault pass the whole suite and fail
  in-game. `tests/test_heavy_pen_maxigun.lua` drives the actual API against the
  test process's own memory.
- **Cross-format contracts need a round trip.** The Lua dump writer and the
  Python analyser share a header layout; drift between them produces wrong
  analysis rather than an error, so `tests/run.py` parses a Lua-written file
  with the Python reader.

## Offline analysis tools

| Tool | Purpose |
|---|---|
| `tools/inspect_patches.py` | what is deployed in the game's data directory, plus loader logs |
| `tools/analyze_dl.py` | record stride inference, lane profiling, stat fingerprinting on a dump |
| `tools/dl_scan.py` | datalibrary instances inside a `.dl_bin` |
| `tools/gen_fingerprints.py` | regenerate the decrypted-size lookup table |
| `tools/pe_probe.py` | `game.dll` section table and entropy |

`tools/analyze_dl.py --selftest` checks stride inference and fingerprinting
against a synthetic buffer without needing a dump.

## When the game updates

The executable and `game.dll` SHA-256 in `mods/hpmg/heavy_pen_maxigun.lua` pin
the supported build. After an update the mod refuses to write and logs the
mismatch. Revalidating means re-running discovery and re-deriving the record
offsets; see [docs/TECHNICAL.md](docs/TECHNICAL.md) for what has to hold.
