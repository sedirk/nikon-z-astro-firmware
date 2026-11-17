"""Read-only config immediate and string candidates; not an authoritative code map."""
from pathlib import Path
import argparse, hashlib, json, re, struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
ROOT=Path(__file__).resolve().parents[2]
BASE=0x10020000
ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
blob=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
assert hashlib.sha256(blob).hexdigest()=='1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);rows=[]
targets={0x3d2,0x3d8,0x3d9,0x3dc,0x3df,0x29f}
for off in range(0,0x500000,2):
    h,k=struct.unpack_from('<HH',blob,off)
    if h&0xfbf0!=0xf240:continue
    value=((h&15)<<12)|((h>>10&1)<<11)|((k>>12&7)<<8)|(k&255)
    if value not in targets:continue
    ins=list(md.disasm(blob[off:off+24],BASE+off))
    rows.append(dict(value=hex(value),pc=hex(BASE+off),instructions=[dict(pc=hex(i.address),bytes=i.bytes.hex(),text=i.mnemonic+' '+i.op_str) for i in ins]))
strings=[]
pattern=re.compile(r'(shad|vign|defect|dpc|front|blem|black|raw|correc|nonuni|fisheye)',re.I)
for match in re.finditer(rb'[ -~]{5,}',blob):
    text=match.group().decode('ascii')
    if len(text)<=300 and pattern.search(text):strings.append(dict(address=hex(BASE+match.start()),text=text))
report=dict(scope=__doc__,firmware_sha256=hashlib.sha256(blob).hexdigest(),config_immediates=rows,strings=strings)
a.output.parent.mkdir(parents=True,exist_ok=True);assert not a.output.exists()
a.output.write_text(json.dumps(report,indent=2),encoding='utf8')
print(json.dumps(report,indent=2))
