"""Initialize the stock companion MCU data using its native decompressor."""
from pathlib import Path
import argparse,hashlib,json,struct,subprocess,importlib.util
ROOT=Path(__file__).resolve().parents[2]
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    a.output.mkdir(parents=True,exist_ok=False)
    source='/home/z6lab/z6lab/z6-qemu/tools/shoulder_display.py'
    r=subprocess.run(['wsl','-d','Ubuntu-24.04','--','cat',source],capture_output=True)
    (a.output/'source-read.stderr').write_bytes(r.stderr);assert r.returncode==0
    file=a.output/'shoulder_display.py';file.write_bytes(r.stdout)
    spec=importlib.util.spec_from_file_location('stock_shoulder_data',file);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    h=mod.ShoulderDisplay(ROOT/'firmware/decoded/ex1620_037000.bi')
    (a.output/'initialized-data.bin').write_bytes(h.data)
    needle=struct.pack('<I',0x080274bd);off=h.data.index(needle)
    lo=max(0,off-0x90);hi=min(len(h.data),off+0xb0)
    words=[dict(address=hex(0x2000d000+i),value=hex(struct.unpack_from('<I',h.data,i)[0])) for i in range(lo,hi,4)]
    report=dict(ok=True,source=source,source_sha256=hashlib.sha256(r.stdout).hexdigest(),
                data_evidence=h.evidence(),known_channel8_function_pointer=hex(0x2000d000+off),surrounding_words=words,
                hardware_access=False,limitations='Only original native data initialization; table interpretation requires native dispatch validation.')
    (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
