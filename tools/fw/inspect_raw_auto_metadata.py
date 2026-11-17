"""Extract original startup constants and bounded string clues for RAW parameters."""
from pathlib import Path
import argparse
import hashlib
import json
import re
import struct
import capstone

ROOT = Path(__file__).resolve().parents[2]
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--output', type=Path, default=ROOT / 'analysis/raw-auto-2026-11-03/static-metadata.json')
OUT = p.parse_args().output
BASE = 0x10020000
blob = (ROOT / 'firmware/decoded/eg1620_038000.bi').read_bytes()
digest = hashlib.sha256(blob).hexdigest()
assert digest == '1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'


def initial(address, size):
    for off in range(0x14000, 0x14120, 16):
        src, dst, length, handler = struct.unpack_from('<4I', blob, off)
        if handler == 0x1002006c and dst <= address and address + size <= dst + length:
            rom = src + address - dst
            data = blob[rom - BASE:rom - BASE + size]
            return dict(ram=hex(address), rom=hex(rom), copy_record_offset=hex(off),
                        bytes=data.hex(), words=[hex(v[0]) for v in struct.iter_unpack('<I', data[:size // 4 * 4])])
    raise AssertionError(hex(address))


properties = {
    'provider_10186428': initial(0xc1884508 + 0x48, 12),
    'provider_10186484': initial(0xc1884508 + 0x54, 20),
    'provider_101c1266': initial(0xc18846bc, 4),
    'mode_scale_10112ffe': initial(0xc1884d53, 9),
}
# Only ASCII strings of >=5 characters are scanned. Absence is not proof that
# no equivalent UTF-16 string, numeric property or unnamed implementation exists.
terms = ('pupil', 'shading', 'blacklevel', 'black_level', 'darkcurrent', 'dark_current',
         'vignet', 'pdaf', 'defect', 'lens', 'opticalblack', 'optical_black')
hits = {term: [] for term in terms}
for match in re.finditer(rb'[\x20-\x7e]{5,}', blob):
    value = match.group().decode('ascii')
    lower = value.lower()
    for term in terms:
        if term in lower:
            hits[term].append(dict(address=hex(BASE + match.start()), text=value[:400]))
md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
md.detail = True
routes = []
for prop, packet_offset, getter in ((0x3076, 0x11, 0x10078c64), (0x3079, 0x1f, 0x10078df2),
                                  (0x307a, 0x1d, 0x10078dd0), (0x3072, 0x5f, 0x1007933a),
                                  (0x3073, 0x5d, 0x10079310)):
    entry = 0x1015c388 + (prop - 0x3000) * 4
    relative = struct.unpack_from('<I', blob, entry - BASE)[0]
    target = 0x1015c388 + relative
    code = list(md.disasm(blob[target - BASE:target - BASE + 8], target))
    calls = [i for i in code if i.mnemonic == 'bl']
    assert len(calls) == 1 and calls[0].operands[0].imm == getter
    routes.append(dict(property_id=hex(prop), table_entry=hex(entry), relative_offset=hex(relative),
                       case_target=hex(target), getter=hex(getter), packet_halfword_offset=hex(packet_offset),
                       case_bytes=blob[target - BASE:target - BASE + 8].hex()))
report = dict(firmware_sha256=digest, startup_values=properties, ascii_clues=hits,
              property_getters=routes,
              pdaf_string_reference=dict(adr_instruction='0x100a0ea0', immediate='0x118',
                                         resolved_string='0x100a0fbc', text='A:\\PdAf%03d.bin',
                                         observation='Adjacent service code; not proof that 0x29c modifies or only modifies AF pixels.'),
              scope='ROM startup bytes and limited ASCII search; names are not assigned to target functions from these hits alone.')
assert not OUT.exists()
OUT.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
print(json.dumps(dict(startup_values=properties, ascii_match_counts={k: len(v) for k, v in hits.items()}), indent=2))
