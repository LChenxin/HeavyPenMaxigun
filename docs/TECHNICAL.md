# How Heavy Penetration Maxigun works

Armour penetration is not stored in the projectile record. A projectile's field
`+0x3C` names a damage-info id, and that id selects a 40-byte run inside the
`damage_settings` buffer. The mod raises three dwords in one such run.

## Runtime scope

`damage_settings` is reached through the pointer at `game.dll+0x02791748`. On the
supported build the decrypted buffer is 48,664 bytes, root type `0xEB1433DA`,
two instances. The M-1000 Maxigun's damage-info record is id 123 at buffer offset
`0x02664`:

| Record offset | Field | Stock | Applied |
|---:|---|---:|---:|
| `+0x00` | damage-info id | 123 | 123 |
| `+0x04` | damage | 80 | 80 |
| `+0x08` | durable damage | 18 | 18 |
| `+0x0C` | penetration, direct | 3 | **4** |
| `+0x10` | penetration, slight angle | 3 | **4** |
| `+0x14` | penetration, large angle | 3 | **4** |
| `+0x18` | penetration, extreme angle | 0 | 0 |
| `+0x1C` | demolition | 10 | 10 |
| `+0x20` | stagger | 15 | 15 |
| `+0x24` | push | 12 | 12 |

Twelve bytes are written. The extreme-angle slot is left at 0, matching both
reference records below. Instance 0 of the buffer holds the angle thresholds as
floats `[25, 60, 80, 90]`, repeated.

Exactly one projectile record references damage-info 123, so the change does not
reach another weapon. That is not true of every record in this table: shared
projectile and damage records exist and are the reason a record-level edit needs
checking before it is made.

## Record identity

The layout above is derived from two records whose values were published
independently with the HMG/AMR ammunition mod, both of which reproduce
byte-exactly on this build:

| Buffer offset | Id | Damage | Durable | Penetration | Demo/stagger/push | Weapon |
|---:|---:|---:|---:|---|---|---|
| `0x03B2C` | 199 | 150 | 35 | 4/4/4/0 | 15/25/20 | MG-206 HMG |
| `0x03B78` | 200 | 450 | 225 | 4/4/4/0 | 20/25/25 | APW-1 AMR |
| `0x02664` | 123 | 80 | 18 | 3/3/3/0 | 10/15/12 | M-1000 Maxigun |

The Maxigun record is identified by its values, not by a name: `damage_settings`
contains no strings. Damage 80, durable damage 18 and Medium/Medium/Medium/
Unarmored penetration match the weapon's published statistics, and the adjacent
pair (80, 18) occurs exactly once in the 48,664-byte buffer. A stat combination
being unique is weaker evidence than a name match, and firing the weapon is the
only confirmation that the engine consumes this record.

Confirmed fields of the 272-byte projectile record, cross-checked against the
same published analysis:

| Offset | Field |
|---:|---|
| `+0x00` | projectile type id |
| `+0x20` | speed |
| `+0x24` | mass |
| `+0x28` | drag |
| `+0x2C` | gravity multiplier |
| `+0x3C` | damage-info id |
| `+0xA8` | surface impact |
| `+0xAC` | ricochet impact |
| `+0xE8` | hit-effect damage type |

## Settings storage

`data/game/*.dl_bin` are datalibrary blobs, encrypted on disk. Decrypted into the
heap they carry a plain header:

```
base +0   u32  instance count
     +4   u32  0x444C444C  'LDLD'
     +8   u32  version (1)
     +12  u32  root type id
     +16  u32  payload size
     +20  u32  is_64_bit_ptr (1)
     +24  u32  reserved (0)
     +28  root: [ptr to items][u32 item count]
```

Decrypted size equals the shipped file size minus 48 bytes of crypto framing.
That equation names any buffer found in memory by size alone; it holds for every
buffer this project has located, with no unmatched sizes. `tools/gen_fingerprints.py`
regenerates the table.

`game.dll` is Themida/WinLicense packed — `.winlice` section, entry point inside
`.boot`, every data section at entropy 8.0, no plaintext strings. Offsets in this
document are runtime values and cannot be recovered from the file on disk.
`tools/pe_probe.py` reproduces the section table.

Sixteen settings buffers are reachable from pointers in the writable globals
section at `0x02394000`. The remaining shipped settings files, including the
45.6 MB `generated_entities`, are not referenced from there. Weapon component
data — magazine capacity, reload, rate of fire — was not found in readable
runtime memory and is not modifiable by this technique.

## Startup and lifecycle

The module is a plaintext Lua resource, `mods/hpmg/heavy_pen_maxigun`, started by
Bingus Shared Loader's addon discovery. It contains no Wwise or boot override.
It wraps the `update` callback, preserves the previous owner, and returns
ownership once it has finished.

Before writing, it verifies the executable and `game.dll` SHA-256, the buffer's
instance count, magic, version and root type, both reference records above, and
the target record in its stock state. A mismatch on any of these writes nothing
and is logged. Writes are accepted only into committed, private, read/write
pages; executable pages and mapped module images are refused. The record is read
back after writing and any partial edit is reverted.

The mod re-verifies every 600 ticks and reapplies if the game has reloaded its
settings. The process owns the changed memory; removing the package prevents the
edit on the next launch.

Logs are written to
`%LOCALAPPDATA%/CowboyBingus/Helldivers2/Logs/HeavyPenMaxigun.log`.

## Tests and evidence

183 offline checks run under embedded LuaJIT 2.1 (`tests/run.py`). The runtime
suite uses synthetic buffers to verify layout rejection, anchor mismatch
rejection, idempotence, the exact twelve-byte write scope, refusal on
non-private pages, and rollback after a failed readback. A further group drives
the actual Win32 layer against this process's own memory, covering region
classification, module-memory refusal, and read/write round-trips.

The offline record analyser is validated against a published answer: it must
reproduce all 147 stratagem navigation flags from the Better Stratagem Bounce
data set, 101 of them with the navigation bit set, before its output on any
other table is used.

A cross-language check confirms the dump header written by the Lua module parses
in the Python analyser, since a format drift between the two would produce wrong
analysis rather than an error.

In-game validation has been performed on the supported build. Multiplayer
host/client behaviour has not been characterised separately.

The module and game fingerprints are in `mods/hpmg/heavy_pen_maxigun.lua`. They
must be revalidated together when the game updates; until then the mod refuses
to write.
