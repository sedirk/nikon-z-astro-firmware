"""Read-only bounded ASCII and descriptor clues; no inferred pixel semantics."""
from pathlib import Path
import argparse
import hashlib
import json
import re
import struct

ROOT = Path(__file__).resolve().parents[2]
BASE = 0x10020000
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
blob = (ROOT / 'firmware/decoded/eg1620_038000.bi').read_bytes()
digest = hashlib.sha256(blob).hexdigest()
assert digest == '1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
terms = ('nef', 'raw', 'black', 'shading', 'vignet', 'defect', 'dark', 'noise', 'prepro', 'pdaf')
hits = {term: [] for term in terms}
for match in re.finditer(rb'[\x20-\x7e]{5,}', blob):
    value = match.group().decode('ascii')
    lower = value.lower()
    for term in terms:
        if term in lower:
            hits[term].append(dict(address=hex(BASE + match.start()), text=value[:400]))
report = dict(firmware_sha256=digest, ascii_clues=hits,
              scope='ASCII >=5 characters only. String addresses are clues, not function identification; '
                    'absence does not rule out unnamed code or hardware processing.')
anchors = {}
for term in ('IMPRAWRS', 'IMPRAW', 'STGRAW', 'PREPRO'):
    offset = blob.find(term.encode() + b'\0')
    assert offset >= 0
    rom = BASE + offset
    for scatter in range(0x14000, 0x14120, 16):
        src, dst, size, handler = struct.unpack_from('<4I', blob, scatter)
        if handler == 0x1002006c and src <= rom < src + size:
            ram = dst + rom - src
            # Table bases independently recovered from native getters and the
            # saved native-pdaf session, not inferred from textual proximity.
            table = 0xc18fd93c if ram < 0xc18fe870 else 0xc18fe870
            index, rem = divmod(ram - table, 0x1c)
            assert rem == 0x10  # Name starts at descriptor+0x10 (10170d18).
            anchors[term] = dict(rom=hex(rom), ram=hex(ram), scatter_record=hex(scatter),
                table_base=hex(table), metadata_id=hex(index + (0x10000 if table == 0xc18fe870 else 0)),
                descriptor_address=hex(ram-0x10),
                descriptor_bytes=blob[offset-0x10:offset+0xc].hex())
            break
    assert term in anchors
report['task_anchors'] = anchors
assert not a.output.exists()
a.output.parent.mkdir(parents=True, exist_ok=True)
a.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
print(json.dumps(dict(counts={k: len(v) for k, v in hits.items()}, task_anchors=anchors), indent=2))
