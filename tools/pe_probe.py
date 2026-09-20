"""Describe game.dll's PE layout and locate the sample mods' known RVAs.

Run with the project venv (it needs pefile):
    .venv/Scripts/python.exe tools/pe_probe.py
"""
import collections
import math
from pathlib import Path
import sys

import pefile

GAME_DLL = Path(r'D:\SteamLibrary\steamapps\common\Helldivers 2\data\game\game.dll')

# Addresses the sample mods hardcode, so we can see which section they land in.
KNOWN_RVAS = [
    ('stratagem buffer ptr', 0x2791F68, 'BetterStratagemBounce'),
    ('stratagem table', 0x2ACD110, 'BetterStratagemBounce'),
    ('navmesh flag test', 0x69CD25, 'BetterStratagemBounce'),
    ('mission global', 0x276C3D0, 'ControllableHoverPack'),
    ('player manager', 0x276C190, 'ControllableHoverPack'),
    ('entity owner', 0x276F0C0, 'ControllableHoverPack'),
    ('avatar manager', 0x276CA30, 'ControllableHoverPack'),
    ('equipment manager', 0x276C468, 'ControllableHoverPack'),
    ('jump pack manager', 0x276C8D0, 'ControllableHoverPack'),
    ('attachment manager', 0x276CAD0, 'ControllableHoverPack'),
]


def entropy(data):
    if not data:
        return 0.0
    counts = collections.Counter(data)
    total = len(data)
    return -sum(n / total * math.log2(n / total) for n in counts.values())


def section_name(section):
    return section.Name.rstrip(b'\x00').decode('ascii', 'replace')


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else GAME_DLL
    pe = pefile.PE(str(path), fast_load=True)
    print('%s' % path)
    print('  machine 0x%04X  image base 0x%X  entry RVA 0x%X  image size 0x%X'
          % (pe.FILE_HEADER.Machine, pe.OPTIONAL_HEADER.ImageBase,
             pe.OPTIONAL_HEADER.AddressOfEntryPoint, pe.OPTIONAL_HEADER.SizeOfImage))

    print('\n%-10s %10s %12s %12s %9s  %s' % ('section', 'VA', 'virt size', 'raw size', 'entropy', 'characteristics'))
    for section in pe.sections:
        print('%-10s 0x%08X %12d %12d %9.4f  0x%08X'
              % (section_name(section), section.VirtualAddress, section.Misc_VirtualSize,
                 section.SizeOfRawData, entropy(section.get_data()), section.Characteristics))

    print('\nWhere the sample mods point:')
    for label, rva, owner in KNOWN_RVAS:
        hit = None
        for section in pe.sections:
            span = max(section.Misc_VirtualSize, section.SizeOfRawData)
            if section.VirtualAddress <= rva < section.VirtualAddress + span:
                hit = section
                break
        where = section_name(hit) if hit else 'NOT MAPPED IN THE FILE'
        raw = ''
        if hit and rva - hit.VirtualAddress < hit.SizeOfRawData:
            offset = hit.PointerToRawData + (rva - hit.VirtualAddress)
            raw = '  file offset 0x%X' % offset
        print('  %-22s 0x%08X  %-10s %-22s%s' % (label, rva, where, owner, raw))


if __name__ == '__main__':
    main()
