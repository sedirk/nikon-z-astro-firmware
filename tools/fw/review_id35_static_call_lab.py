"""Independent exact-byte and native-evidence review; not a flash/install approval."""
from pathlib import Path
import argparse,binascii,hashlib,json,struct
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB
from verify_front_preflash_kit import EDITS as INHERITED,reconstruct
ROOT=Path(__file__).resolve().parents[2];BASE=0x10020000
ROUND=ROOT/'analysis/raw-fixed-operators-2026-11-09'
EXPECTED='76474a8977a3bf4b456fe68f9594110714a04c09b4ec575f019ba27fadd0d2d7'
NEW=(
 (0x10179d54,'0020','0420'),
 (0x1011c756,'05460e464ff6ff77','074620f004050e46'),
 (0x1011c764,'b8420ed0','1c280ed2'),
 (0x1011c78a,'526900eb8000484902eb0010843990f84025ca6190f8412581f8202090f8422581f8262090f84305c8670846f4f727fa2fe0',
  '526950235843121802f5a86247488438137807b1234600bf00bfc361537880f82030937880f82630d378c367f4f727fa2fe0'))

def sha(b):return hashlib.sha256(b).hexdigest()
def read(p):return json.loads(Path(p).read_text(encoding='utf8'))
def write(p,v):Path(p).write_text(json.dumps(v,indent=2,ensure_ascii=False),encoding='utf8')

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    stock=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    m4=(ROOT/'outputs/Z6-C380-front-bit11-reviewed-2026-11-09/01_TEST_MODIFIED4/EG162080.BIN').read_bytes()
    lab=(ROUND/'static-call-lab/modified4-id35-static-call-off-lab.bi').read_bytes()
    assert reconstruct(stock,INHERITED)==m4
    rebuilt=bytearray(m4);allowed=set()
    for address,old,new in NEW:
        old,new=bytes.fromhex(old),bytes.fromhex(new);n=address-BASE
        assert len(old)==len(new) and m4[n:n+len(old)]==old
        rebuilt[n:n+len(old)]=new;allowed.update(range(n,n+len(old)))
    rebuilt[-2:]=binascii.crc_hqx(rebuilt[:-2],0).to_bytes(2,'big');allowed.update((len(lab)-2,len(lab)-1))
    assert rebuilt==lab and sha(lab)==EXPECTED and binascii.crc_hqx(lab,0)==0 and len(lab)==33502842
    changes=[i for i,(x,y) in enumerate(zip(m4,lab)) if x!=y]
    assert len(changes)==53 and set(changes)<=allowed
    restored=bytearray(lab)
    for i in allowed:restored[i]=m4[i]
    assert restored==m4
    for address,old,new in INHERITED:
        n=address-BASE;assert lab[n:n+len(bytes.fromhex(new))]==bytes.fromhex(new)
    protected=[]
    for name,lo,hi in [('startup',BASE,BASE+0x15000),('updater',0x101b4000,0x101ba000),
        ('flash_veneers',0x1014a674,0x1014a6a4),('resource_directory',0x11f15000,0x11f17000),
        ('table33_selector_and_copy',0x1011e23e,0x1011e36a),('table33_upload',0x1010b1c0,0x1010b45e)]:
        assert stock[lo-BASE:hi-BASE]==m4[lo-BASE:hi-BASE]==lab[lo-BASE:hi-BASE]
        protected.append(dict(name=name,start=hex(lo),end=hex(hi),sha256=sha(lab[lo-BASE:hi-BASE])))
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);disassembly=[]
    for address,old,new in NEW:
        code=bytes.fromhex(new);ins=list(md.disasm(code,address))
        assert sum(i.size for i in ins)==len(code)
        disassembly.extend(dict(pc=hex(i.address),bytes=i.bytes.hex(),mnemonic=i.mnemonic,operands=i.op_str) for i in ins)
    scope=read(ROUND/'temporary-scope/result.json');callers=[]
    for c in scope['callers']:
        pc=int(c['pc'],16)
        before=[i for i in c['window'] if int(i['pc'],16)<pc]
        assignment=next(i for i in reversed(before) if i['operands'].startswith('r0, #') and i['mnemonic']=='movs')
        value=int(assignment['operands'].split('#')[1],0);assert value in (0,1,2)
        between=[i for i in before if int(i['pc'],16)>int(assignment['pc'],16)]
        assert all(i['mnemonic'] in ('ldr','adds','add.w') and i['operands'].startswith('r1,') for i in between),(c,between)
        n=int(assignment['pc'],16)-BASE
        actual=list(md.disasm(lab[n:n+2],BASE+n))[0]
        assert actual.mnemonic=='movs'
        after=int(actual.op_str.split('#')[1],0)
        assert after==(4 if pc==0x10179d56 else value)
        callers.append(dict(call=hex(pc),argument_instruction=assignment['pc'],original_kind=value,lab_kind=after))
    assert len(callers)==49 and sum(c['lab_kind']==4 for c in callers)==1
    indirect=read(ROUND/'dispatch-indirect-scope.json');assert not indirect['literals'][0]['occurrences']
    assert not scope['odd_pointer_candidates']
    assert [e['pc'] for e in scope['replacement_entries']]==['0x1011c77a']

    native=read(ROUND/'native-static-call-v3/result.json');extra=read(ROUND/'native-submode-supplement/result.json')
    assert native['ok'] and extra['ok'] and native['sources_unchanged'] and extra['sources_unchanged']
    assert len(native['rows'])==224 and len(extra['rows'])==20
    for row in native['rows']+extra['rows']:
        x,y=row['variants']['modified4'],row['variants']['lab']
        assert x['context']==y['context'] and x['sp']==y['sp'] and x['cpsr']==y['cpsr']
        assert x['call']['registers']['r0']==y['call']['registers']['r0']
        assert all(x['call']['registers'][f'r{i}']==y['call']['registers'][f'r{i}'] for i in range(4,12))
    for row in extra['selector_domain']:assert row['values']==list(range(28))+[65535]
    for seq in native['restoration']:
        assert [r['gate'] for r in seq['sequence']]==([17,0,17] if seq['variant']=='lab' else [17,17,17])
    x,y=native['builder_rows']
    assert len(x['writes'])==len(y['writes'])==507
    for key in ('packet','table','front_registers','writes'):assert x[key]==y[key]
    qemus={n:read(ROUND/f'qemu-static-call-{n}/result.json') for n in ('m4','lab')}
    assert all(j['ok'] and j['firmware_unchanged'] for j in qemus.values())
    assert qemus['m4']['model_sha256']==qemus['lab']['model_sha256']
    assert qemus['m4']['native_dispatch_kinds']==[0,1,2] and qemus['lab']['native_dispatch_kinds']==[4,1,2]
    qcompare={}
    for event in ('raw_destination_ready','global_parameter_upload','static_kind0_return','static_front_builder','table33_record','temporary_exit'):
        pair=[next(e for e in j['events'] if e['phase']=='native-settle' and e['event']==event) for j in qemus.values()]
        # This fixture starts with a zero CAL gate; it verifies control flow,
        # not the gate's physical pixel effect. Retain cross-run address fields.
        x,y=pair[0]['memory'],pair[1]['memory']
        if event=='raw_destination_ready':
            assert pair[0]['registers']==pair[1]['registers']
            for key in ('context','global_packet','state'):assert x[key]==y[key]
            assert x['raw_destination']['address']==y['raw_destination']['address']=='0xc25ee224'
            xb,yb=(bytes.fromhex(v['raw_destination']['bytes']) for v in (x,y))
            assert len(xb)==len(yb)==0x44 and xb[:0x28]==yb[:0x28]
            assert struct.unpack_from('<I',xb,0x24)[0]==int(pair[0]['registers']['r0'],16)==0xa448e000
            differences=[dict(offset=hex(i),modified4=hex(struct.unpack_from('<I',xb,i)[0]),
                              lab=hex(struct.unpack_from('<I',yb,i)[0]))
                         for i in range(0x28,len(xb),4) if xb[i:i+4]!=yb[i:i+4]]
            assert [int(d['offset'],16) for d in differences]==list(range(0x28,0x44,4))
            qcompare[event]=dict(registers_identical=True,context_global_state_identical=True,
                raw_parameter_prefix_0x28_identical=True,raw_pointer_at_0x24='0xa448e000',
                differing_captured_tail=differences,
                interpretation='Seven address-like words differ before the tagged call. Their full ownership is unresolved; this is not full-buffer equality or a saved-NEF comparison.')
        else:
            assert x==y,event
            qcompare[event]='Captured memory snapshots identical in the disclosed zero-calibration fixture.'
    write(a.output/'result.json',dict(ok=True,status='OFFLINE_CANDIDATE_REVIEW_PASSED_NOT_INSTALL_KIT',
        sha256=EXPECTED,bytes=len(lab),changed_code_bytes=51,changed_crc_bytes=2,same_size=True,
        independent_reconstruction=True,exact_restore_to_modified4=True,inherited_edits_preserved=len(INHERITED),
        protected=protected,callers=callers,instructions=disassembly,native_pairs=244,
        full_selector_domain=list(range(28))+[65535],full_selector_domain_test_calls=2048,
        untouched_front_upload_writes=507,qemu_events={n:len(j['events']) for n,j in qemus.items()},qemu_comparison=qcompare,
        scope_limit='Direct callers and odd-pointer literal scan, plus native/QEMU execution; not exhaustive indirect-flow proof.',
        unsupported_api_inputs='Only ordinary kinds0..2 plus private kind4 reviewed; arbitrary private/corrupt arguments are outside the defined contract.',
        hardware_pixel_operation=None,physical_ring_effect_verified=False,preflash_updater_rehearsal_for_new_hash=False))
    (a.output/Path(__file__).name).write_bytes(Path(__file__).read_bytes())
    print(json.dumps(dict(ok=True,sha256=EXPECTED,native_pairs=244,direct_callers=49,changed_code_bytes=51,preflash_review=False)))

if __name__=='__main__':main()
