"""Create separate modified5 review tools; preserve all prior tool snapshots."""
from pathlib import Path
import ast,json

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'analysis/id35-preflash-2026-11-09'
NEW=((0x10179d54,'0020','0420'),
 (0x1011c756,'05460e464ff6ff77','074620f004050e46'),
 (0x1011c764,'b8420ed0','1c280ed2'),
 (0x1011c78a,'526900eb8000484902eb0010843990f84025ca6190f8412581f8202090f8422581f8262090f84305c8670846f4f727fa2fe0',
  '526950235843121802f5a86247488438137807b1234600bf00bfc361537880f82030937880f82630d378c367f4f727fa2fe0'))

def save(name,text):
    p=ROOT/'tools/fw'/name
    if p.exists():raise FileExistsError(p)
    ast.parse(text);p.write_bytes(text.encode('utf8'));return str(p.relative_to(ROOT))

def main():
    outputs=[]
    s=(ROOT/'tools/fw/verify_front_preflash_kit.py').read_text(encoding='utf8')
    s=s.replace('modified4','modified5').replace('modified3','modified4').replace('MODIFIED4','MODIFIED5').replace('MODIFIED3','MODIFIED4')
    s=s.replace('bdf30026dc9d18b09a5ca9332369d126729d63a36013e94b8b20cf6638a4ef1b','76474a8977a3bf4b456fe68f9594110714a04c09b4ec575f019ba27fadd0d2d7')
    s=s.replace('a8ec90a9b55b2eefcd46e13b0f6acd0b7aa1bc4d9d127d701dee89154b8b04bd','bdf30026dc9d18b09a5ca9332369d126729d63a36013e94b8b20cf6638a4ef1b')
    s=s.replace("SUPPORT={'START_HERE.txt'",'EDITS = EDITS + '+repr(NEW)+"\nSUPPORT={'START_HERE.txt'")
    s=s.replace('# Fixed independently of the delivered recipe/manifest. Slots may be 2 or 4 bytes.','# Fixed independently of the delivered recipe/manifest; exact in-place blocks.')
    s=s.replace("len(old) in (2,4)","len(old) in (2,4,8,50) and 0<=off<=SIZE-2-len(old)")
    s=s.replace("manifest['schema']==4","manifest['schema']==5")
    s=s.replace("('modified4',9),('test',10)","('modified4',10),('test',14)")
    s=s.replace('Select test, modified4, modified1 or stock','Select test, modified4, modified1 or stock')
    outputs.append(save('verify_id35_preflash_kit.py',s))
    s=(ROOT/'tools/fw/probe_front_preflash_updater.py').read_text(encoding='utf8')
    s=s.replace('modified4','modified5').replace('modified3','modified4')
    s=s.replace('review_front_preflash','review_id35_preflash').replace('verify_front_preflash_kit','verify_id35_preflash_kit')
    s=s.replace("broken[0xd64b4]","broken[0x159d54]")
    outputs.append(save('probe_id35_preflash_updater.py',s))
    s=(ROOT/'tools/fw/test_front_preflash_verifier.py').read_text(encoding='utf8')
    s=s.replace('verify_front_preflash_kit','verify_id35_preflash_kit').replace('review_front_preflash','review_id35_preflash')
    s=s.replace("broken[0xd64b4]","broken[0x159d54]")
    outputs.append(save('test_id35_preflash_verifier.py',s))
    s=(ROOT/'tools/fw/qemu_front_preflash.py').read_text(encoding='utf8')
    s=s.replace('modified3/4','modified4/5').replace('modified4','modified5').replace('modified3','modified4')
    s=s.replace('bdf30026dc9d18b09a5ca9332369d126729d63a36013e94b8b20cf6638a4ef1b','76474a8977a3bf4b456fe68f9594110714a04c09b4ec575f019ba27fadd0d2d7')
    s=s.replace('a8ec90a9b55b2eefcd46e13b0f6acd0b7aa1bc4d9d127d701dee89154b8b04bd','bdf30026dc9d18b09a5ca9332369d126729d63a36013e94b8b20cf6638a4ef1b')
    s=s.replace("expected=2 if a.variant=='modified5' else 0","expected=2  # Both inherit modified4's earlier static override.")
    s=s.replace("0x100bd8ec:'raw_destination'}","0x100bd8ec:'raw_destination',0x1011c750:'id35_dispatch',0x10179d5a:'id35_return',0x10179dd4:'temporary_exit'}")
    s=s.replace("if pc in (0x10179962,0x1017c020):", "if pc in (0x1011c750,0x10179d5a,0x10179dd4):row['global_packet']=remote.memory(0xc29a3230,0x84).hex()\n        if pc in (0x10179962,0x1017c020):")
    s=s.replace("report['static_control']=dict(expected=expected,input_count=len(inputs),builder_count=len(builders),raw_destination_count=len(dest))", """report['static_control']=dict(expected=expected,input_count=len(inputs),builder_count=len(builders),raw_destination_count=len(dest))
            kinds=[int(e['registers']['r0'],16) for e in report['events'] if e['phase']=='static_settle' and e['event']=='id35_dispatch']
            assert kinds==([4,1,2] if a.variant=='modified5' else [0,1,2]),kinds
            returns=[e for e in report['events'] if e['phase']=='static_settle' and e['event']=='id35_return']
            assert len(returns)==1 and int(returns[0]['registers']['r0'],16)==0
            assert any(e['event']=='temporary_exit' and e['phase']=='static_settle' for e in report['events'])
            report['id35_dispatch_kinds']=kinds""")
    s=s.replace('Exact modified5/5 startup','Exact modified4/5 startup')
    outputs.append(save('qemu_id35_preflash.py',s))
    OUT.mkdir(parents=True,exist_ok=True)
    (OUT/'tools-prepared.json').write_text(json.dumps(dict(outputs=outputs,method='Separate copies with explicit substitutions, followed by syntax checks; prior tools unchanged.'),indent=2),encoding='utf8')
    print(json.dumps(dict(created=len(outputs),files=outputs)))

if __name__=='__main__':main()
