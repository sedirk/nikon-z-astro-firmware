"""Resolve the camera-matched PTP tables through the ROM scatter-copy map.

Read-only firmware analysis; writes new evidence, never camera commands.
"""
from pathlib import Path
import datetime,hashlib,json,struct,subprocess
import numpy as np
ROOT=Path(__file__).resolve().parents[2];BASE=0x10020000
OUT=ROOT/'analysis/raw-calibration-access-2026-11-10'
EXPECTED='1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
def sha(b):return hashlib.sha256(b).hexdigest()
def write(p,x):
    assert not p.exists(),p
    p.write_text(json.dumps(x,ensure_ascii=False,indent=2),encoding='utf8')

def main():
    OUT.mkdir(parents=True,exist_ok=True)
    backup=OUT/'progress-before';backup.mkdir(exist_ok=False)
    for name in ('README.md','docs/PROJECT_GOALS.md','docs/NEXT_STEPS.md'):
        (backup/name.replace('/','-')).write_bytes((ROOT/name).read_bytes())
    (OUT/'git-status-before.txt').write_bytes(subprocess.run(['git','status','--short'],cwd=ROOT,capture_output=True,check=True).stdout)
    b=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes();assert sha(b)==EXPECTED
    scatter=[]
    for off in range(0x14000,0x14120,16):
        src,dst,n,handler=struct.unpack_from('<4I',b,off)
        scatter.append(dict(record=hex(BASE+off),source=hex(src),destination=hex(dst),length=n,handler=hex(handler)))
    refs=[];words=np.frombuffer(b[:len(b)//4*4],dtype='<u4')
    # Tables and their surrounding descriptor area, including runtime aliases.
    regions=[(0x11f7a400,0x11f7a700)]
    mappings=[]
    for s in scatter:
        src,dst,n=int(s['source'],16),int(s['destination'],16),s['length']
        if src<=0x11f7a49c<src+n and int(s['handler'],16)==0x1002006c:
            mappings.append(dict(**s,matched_rom_table='0x11f7a49c',runtime_table=hex(dst+0x11f7a49c-src)))
            regions.append((dst+0x11f7a400-src,dst+0x11f7a700-src))
    for lo,hi in regions:
        hits=np.flatnonzero((words>=lo)&(words<hi))
        for i in hits:
            refs.append(dict(pointer_at=hex(BASE+int(i)*4),value=hex(int(words[i])),region_start=hex(lo)))
    write(OUT/'ptp-table-aliases.json',dict(ok=True,firmware_sha256=EXPECTED,scatter=scatter,mappings=mappings,
        pointer_candidates=refs,scope='Scatter initialization mapping; pointer candidates require native consumer confirmation.'))
    write(OUT/'round-inputs.json',dict(local_date='2026-11-10',started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        inherited_round='raw-front-completion-2026-11-10',firmware_sha256=EXPECTED,
        goal='Preserve dark current, disable static pre-NEF RAW corrections, remove rings.',
        recalled_modified5=True,menu_baseline='All three correction menus OFF per user report.',
        initial_task='Resolve native PTP dispatch and authenticated calibration/resource read routes; retain mandatory frontend transfers.'))
    print(json.dumps(dict(mappings=mappings,pointer_candidates=refs),indent=2))

if __name__=='__main__':main()
