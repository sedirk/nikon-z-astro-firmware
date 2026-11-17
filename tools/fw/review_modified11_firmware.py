"""Independent byte/CRC and native parameter-publication review; no camera access.

Unicorn executes actual instructions with synthetic inputs and RAM-backed MMIO.
It implements neither sensor pixels nor physical flash programming.
"""
from pathlib import Path
import argparse, binascii, hashlib, json, shutil, struct
import numpy as np
import unicorn as un
from unicorn.arm_const import *
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

ROOT=Path(__file__).resolve().parents[2]
BASE=0x10020000;BUF=0xc29a3868;DESC=0xc29a34c0;CTX=0xc18fa844;STATE=0xc18fa954
DATA=0x50000000;STACK=0x52000000;STOP=0x53000000;CAL=0x54000000
REGS=[UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R4,UC_ARM_REG_R5,
      UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11,UC_ARM_REG_R12]
def sha(b):return hashlib.sha256(b).hexdigest()
def dump(p,v):p.write_text(json.dumps(v,indent=2,ensure_ascii=False),encoding='utf8')

def run_native(blob, label):
    u=un.Uc(un.UC_ARCH_ARM,un.UC_MODE_THUMB);length=(len(blob)+4095)&~4095
    u.mem_map(BASE,length);u.mem_write(BASE,blob);u.mem_protect(BASE,length,un.UC_PROT_READ|un.UC_PROT_EXEC)
    for addr,size in [(DATA,0x2000),(STACK,0x10000),(STOP,0x1000),(CAL,0xc0000),
                      (0xc18fa000,0x2000),(0xc29a3000,0x1000),(0x20068000,0x2000)]:u.mem_map(addr,size)
    def put(addr,val,fmt='I'):u.mem_write(addr,struct.pack('<'+fmt,val))
    writes=[]
    def on_write(uc,kind,addr,size,value,_):writes.append(dict(pc=hex(uc.reg_read(UC_ARM_REG_PC)),address=hex(addr),size=size,value=value))
    u.hook_add(un.UC_HOOK_MEM_WRITE,on_write,begin=0x20068000,end=0x20069fff)
    def call(entry,args):
        writes.clear()
        for i,reg in enumerate(REGS):u.reg_write(reg,0x71000000+i)
        for reg,value in zip(REGS,args):u.reg_write(reg,value)
        saved=[u.reg_read(r) for r in REGS[4:12]]
        u.reg_write(UC_ARM_REG_SP,STACK+0xf000);u.reg_write(UC_ARM_REG_LR,STOP|1)
        u.emu_start(entry|1,STOP,count=50000)
        assert u.reg_read(UC_ARM_REG_PC)==STOP
        assert u.reg_read(UC_ARM_REG_SP)==STACK+0xf000
        assert [u.reg_read(r) for r in REGS[4:12]]==saved
        return dict(entry=hex(entry),arguments=list(map(hex,args)),mmio_writes=list(writes),abi_preserved=True)
    u.mem_write(DATA,struct.pack('<5H',1,2,3,4,5))
    old=[7001,7002,7003,7004];synthetic=[5305,4176,4180,5171]
    cases=[]
    for coeffs,control in [(None,0),(None,0x4d),([4096]*4,0x12),(synthetic,0x4d),([8192,4096,4096,2048],255)]:
        u.mem_write(BUF-4,b'BEGN'+struct.pack('<4I',*old)+bytes([0xa5])*16+b'END!')
        put(BUF+0x18,77,'B')
        if coeffs is not None:u.mem_write(DATA+0x100,struct.pack('<4I',*coeffs))
        pub=call(0x10122ca2,[DATA,DATA+0x100 if coeffs is not None else 0,control])
        buf=bytes(u.mem_read(BUF,32));out=list(struct.unpack_from('<4I',buf))
        assert out==([4096]*4 if label=='modified11' else coeffs if coeffs is not None else old)
        assert buf[0x18]==(control if label=='modified11' or coeffs is not None else 77)
        assert bytes(u.mem_read(BUF-4,4))==b'BEGN' and bytes(u.mem_read(BUF+32,4))==b'END!'
        assert struct.unpack('<I',u.mem_read(DESC+0x38,4))[0]==BUF
        uploader=call(0x1010b298,[0,BUF])
        actual=list(struct.unpack('<8I',u.mem_read(0x200687d8,32)))
        assert actual==out+[1+(2<<16),4+(3<<16),buf[0x18],5]
        assert len(writes)==8
        cases.append(dict(input_coefficients=coeffs,synthetic_input=True,input_control=control,
                          result_coefficients=out,result_control=buf[0x18],published_packet=buf.hex(),
                          publisher=pub,uploader=uploader,mmio_values=actual))
    # Exercise actual caller's publish/no-publish branches for every mode enum.
    modes=[]
    put(STATE+0x14,CAL)
    u.mem_write(CAL+0xbe820,bytes([2])*15)
    u.mem_write(CAL+0xbbd70,struct.pack('<6H',11,22,33,44,55,66)*256)
    for mode in range(15):
        for publish in (0,1):
            u.mem_write(CTX,bytes(0xe4));put(CTX,mode,'B');put(CTX+0x14,-1,'h')
            put(CTX+0xac,4096);u.mem_write(CTX+0xc4,struct.pack('<4I',*synthetic));put(CTX+0xd4,0x4d)
            u.mem_write(BUF,struct.pack('<4I',*old)+bytes(16));put(BUF+0x18,77,'B')
            caller=call(0x1011e940,[CTX,publish])
            out=list(struct.unpack('<4I',u.mem_read(BUF,16)));control=u.mem_read(BUF+0x18,1)[0]
            if label=='modified11':assert out==[4096]*4 and control==0x4d
            elif publish==0:assert out==old and control==77
            else:assert out==[v+8 for v in synthetic] and control==0x4d
            modes.append(dict(mode=mode,publish=publish,result_coefficients=out,result_control=control,caller=caller))
    return dict(publisher_and_upload_cases=cases,caller_modes=modes)

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    out=args.output;out.mkdir(parents=True,exist_ok=False);shutil.copy2(__file__,out/Path(__file__).name)
    kit=ROOT/'outputs/Z6-C380-modified11-reviewed-2026-11-14'
    paths={'stock':ROOT/'firmware/decoded/eg1620_038000.bi',
           'modified10':ROOT/'outputs/Z6-C380-modified10-reviewed-2026-11-13/01_TEST_MODIFIED10/EG162080.BIN',
           'modified11':kit/'01_TEST_MODIFIED11/EG162080.BIN'}
    blobs={k:p.read_bytes() for k,p in paths.items()}
    expected={'stock':'1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c',
              'modified10':'85b1889bb82c81cdd42cfa4358e72cab12598882f7453a8dbea70ffe9ef6deb4',
              'modified11':'4b6b8989d1f18f20fd1a6e86c99b885eeab2bad88c4310fe144be3620970df7a'}
    res=dict(ok=False,scope=__doc__,files={},patches=[],native={},kit_files=[])
    for label,b in blobs.items():
        assert sha(b)==expected[label] and len(b)==33502842 and binascii.crc_hqx(b,0)==0
        res['files'][label]=dict(path=str(paths[label]),sha256=sha(b),length=len(b),crc_residue=0,crc_bytes=b[-2:].hex())
    original=ROOT/'firmware/original/Z_6_0380.bin'
    res['original_container']=dict(path=str(original),sha256=sha(original.read_bytes()))
    assert res['original_container']['sha256']=='ff978ffdf77c58c0b861a06e16d432d5886969f3cdd05d62f6c8e82e8a4cea54'
    recipe=ROOT/'patches/z6-c380-modified11-production-convergence.json'
    reconstruction=bytearray(blobs['stock']);allowed=np.zeros(len(reconstruction),dtype=bool)
    edits=json.loads(recipe.read_text())['candidates'][0]['edits']
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);listing=[]
    for e in edits:
        addr=int(e['address'],16);off=addr-BASE;before=bytes.fromhex(e['before']);after=bytes.fromhex(e['after'])
        assert len(before)==len(after) and reconstruction[off:off+len(before)]==before
        reconstruction[off:off+len(before)]=after;allowed[off:off+len(before)]=True
        res['patches'].append(dict(address=e['address'],span=len(after),changed_bytes=sum(a!=b for a,b in zip(before,after)),group=e['group']))
    reconstruction[-2:]=binascii.crc_hqx(reconstruction[:-2],0).to_bytes(2,'big');allowed[-2:]=True
    assert bytes(reconstruction)==blobs['modified11']
    diff=np.flatnonzero(np.frombuffer(blobs['stock'],dtype=np.uint8)!=np.frombuffer(blobs['modified11'],dtype=np.uint8))
    assert allowed[diff].all()
    parentdiff=np.flatnonzero(np.frombuffer(blobs['modified10'],dtype=np.uint8)!=np.frombuffer(blobs['modified11'],dtype=np.uint8))
    assert all(0x10122cba-BASE<=p<0x10122ccc-BASE or p>=len(reconstruction)-2 for p in parentdiff)
    res['diffs']=dict(stock_changed_bytes=len(diff),m10_changed_bytes=len(parentdiff),m10_changed_offsets=parentdiff.tolist(),complete_reconstruction_matches=True)
    for label,b in blobs.items():
        listing.append(f'\n; {label}')
        for start,end in [(0x10122ca2,0x10122cd4),(0x1010b298,0x1010b2d6)]:
            listing.extend(f'{i.address:08x} {i.mnemonic} {i.op_str}' for i in md.disasm(b[start-BASE:end-BASE],start))
        res['native'][label]=run_native(b,label)
    for p in sorted(kit.glob('*/EG162080.BIN')):
        b=p.read_bytes();assert len(b)==33502842 and binascii.crc_hqx(b,0)==0
        res['kit_files'].append(dict(path=str(p),sha256=sha(b),length=len(b),crc_residue=0))
    for label,p in paths.items():assert sha(p.read_bytes())==expected[label]
    res['ok']=True;dump(out/'assessment.json',res)
    (out/'native-disassembly.txt').write_text('\n'.join(listing),encoding='utf8')
    print(json.dumps(dict(ok=True,diffs=res['diffs'],native_cases=3*(5+30),physical_pixel_or_flash_emulation=False)))

if __name__=='__main__':main()
