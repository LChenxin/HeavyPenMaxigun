# Heavy Penetration Maxigun

> [!IMPORTANT]
> **Bingus Shared Loader v15 or newer / API 1 is a required separate download.**
> Import `Heavy-Pen-Maxigun.zip` and the loader into **HDArsenal** or **HD2MM**,
> enable both, then click **Deploy**. Mod managers do not install the dependency
> automatically.
>
> **Arsenal (default priority): place Bingus Shared Loader LAST, at the bottom of
> the load order**, then **Purge / Deploy**. If you enabled first-mod priority,
> place the loader first instead.

Raises the **M-1000 Maxigun**'s armour penetration from Medium to the tier the
MG-206 HMG and APW-1 AMR already use, at every impact angle the weapon already
penetrates. Extreme-angle hits stay unarmored, as in the stock weapon.

Damage, durable damage, magazine, fire rate, recoil, handling and every other
weapon value are unchanged. No other weapon is affected.

**Install:** Close Helldivers 2. Import `Bingus-Shared-Loader-v15.zip` and
`Heavy-Pen-Maxigun.zip` into **HDArsenal** or **HD2MM**, enable both, and deploy.
Use one manager. See [installation](INSTALL.txt).

Supported: Steam build **24826606** / EXE **1.8.45317.0**. The mod verifies the
executable and `game.dll` before doing anything and applies no change on any
other build. It modifies process memory only; no game file is written, and
removing the package restores stock values on the next launch.

Single-player or private lobbies are recommended. Host/client behaviour in
multiplayer has not been characterised.

## Source

- `mods/hpmg/`: the runtime module, plus the read-only discovery and dump tools
  used to locate its target.
- `tests/`: offline checks run under embedded LuaJIT 2.1.
- `tools/`: offline analysis — record layout, PE/entropy probing, deployment
  inspection, fingerprint generation.
- `build.py`: packaging.

[Build instructions](CONTRIBUTING.md) · [Technical notes](docs/TECHNICAL.md) ·
[Installation](INSTALL.txt)

**AI disclosure:** Claude Opus 5 assisted with research, implementation,
debugging and documentation.
