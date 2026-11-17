"""Execute ORIGINAL Z6 C3.80 module-discovery and integrity code, offline.

Only filesystem, OS synchronization/notification and a display configuration
query are host adapters. Filename matching, header/version reading, route
selection, CRC of the complete 33 MB image and update descriptors run as
original instructions. No flash functions are invoked. This is not a physical
camera install, recovery, power-loss, or RAW-pixel test.
"""
from pathlib import Path
import argparse, binascii, collections, hashlib, json, struct, time, traceback
import unicorn as un
from unicorn.arm_const import *

ROOT=Path(__file__).resolve().parents[2]
BASE=0x10020000; RAM=0x50000000; STACK=0x52000000; STOP=0x53000000; BUFFER=0x60000000
STATE=0xc18d1c94; RESOURCE=0xc252628c; LIST=0xc25268d4
SOURCE_SHA='1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
CANDIDATE_SHA='eeded80d4009204ba9760b6e20436aea3f6a37ce4ed6331ca662b839164a8875'
REGS=[UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R4,
      UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,
      UC_ARM_REG_R10,UC_ARM_REG_R11,UC_ARM_REG_R12]
SERVICES={0x10290bbe:'directory_open',0x10290cb2:'directory_next',0x10290cd0:'directory_close',
    0x102da87e:'file_open',0x102da9f0:'file_read',0x102da9fe:'file_seek',0x102da90a:'file_close',
    0x102eaf4c:'lock',0x102eaf96:'unlock',0x100362c0:'os_time',0x10035e48:'os_notification',
    0x101f596a:'progress_notification',0x101cb734:'display_configuration'}
WATCH={0x101b87d8,0x101b86d8,0x101b79de,0x101b7780,0x101b9f48,0x101b88f6,
       0x101b4bb4,0x101b8ae4,0x101c3bba,0x101b8c40,0x101b8a6a,0x101b8a40}

def sha(data):return hashlib.sha256(data).hexdigest()

class Rig:
    def __init__(self,rom):
        self.rom=rom;self.u=un.Uc(un.UC_ARCH_ARM,un.UC_MODE_THUMB)
        self.u.mem_map(BASE,(len(rom)+4095)&~4095);self.u.mem_write(BASE,rom)
        self.u.mem_protect(BASE,(len(rom)+4095)&~4095,un.UC_PROT_READ|un.UC_PROT_EXEC)
        self.regions=((RAM,0x10000),(STACK,0x10000),(STOP,0x1000),(0xc1800000,0x4000000),(BUFFER,0x2941000))
        for addr,n in self.regions:self.u.mem_map(addr,n)
        # Narrow block hooks avoid a Python callback per byte in native CRC.
        for pc in sorted(set(SERVICES)|WATCH):
            self.u.hook_add(un.UC_HOOK_BLOCK,self.hook,begin=pc,end=pc)
        self.events=[];self.calls=[];self.hits=collections.Counter()

    def put(self,addr,value,fmt='I'):self.u.mem_write(addr,struct.pack('<'+fmt,value))
    def get(self,addr,fmt='I'):return struct.unpack('<'+fmt,self.u.mem_read(addr,struct.calcsize(fmt)))[0]
    def string(self,addr,n=256):return bytes(self.u.mem_read(addr,n)).split(b'\0')[0].decode('ascii')
    def hook(self,u,pc,size,_):
        self.hits[hex(pc)]+=1
        if pc in SERVICES:self.u.emu_stop()

    def reset(self,data,filename,display=0,reported_size=None):
        for addr,n in self.regions:self.u.mem_write(addr,bytes(n))
        for off in range(0x14000,0x14120,16):
            src,dst,n,handler=struct.unpack_from('<4I',self.rom,off)
            if handler==0x1002006c and 0xc1800000<=dst<dst+n<=0xc5800000:
                self.u.mem_write(dst,self.rom[src-BASE:src-BASE+n])
        self.data=data;self.filename=filename;self.display=display;self.offset=0;self.next_index=0
        self.reported_size=len(data) if reported_size is None else reported_size
        self.events=[];self.calls=[];self.hits.clear()
        self.u.mem_write(RAM,b'A:\\\0');self.u.mem_write(RAM+0x100,b'B:\\\0')
        self.put(STATE+0x48,RAM);self.put(STATE+0x4c,RAM+0x100)
        self.put(STATE+4,RAM+0x1000)
        # Execute the real C-library ctype initialization, not a host-made table.
        self.call(0x10053046,until=0x10053058)
        # Resolve the installed resource from the original scatter-loaded ROM tables.
        assert self.call(0x101f620e,[2,RESOURCE])==1
        assert self.get(RESOURCE+4)==BASE and self.get(RESOURCE+0x10)==0x2940000

    def adapter(self,pc):
        a=[self.u.reg_read(r) for r in REGS[:4]];event=dict(pc=hex(pc),name=SERVICES[pc],args=[hex(x) for x in a])
        ret=0
        if pc==0x10290bbe:
            event['path']=self.string(a[0]);self.next_index=0;self.put(a[1],0x1234)
        elif pc==0x10290cb2:
            if self.next_index:ret=1
            else:
                self.u.mem_write(a[1],bytes(0x220));self.u.mem_write(a[1],self.filename.encode('ascii')+b'\0')
                self.put(a[1]+0x218,self.reported_size);self.next_index+=1
                event['filename']=self.filename;event['reported_size']=self.reported_size
        elif pc==0x102da87e:
            path=self.string(self.get(a[0]));event['path']=path
            assert path.upper()=='A:\\'+self.filename.upper(),path
            self.offset=0;ret=0x4390080
        elif pc==0x102da9fe:
            assert a[2]==0,a
            self.offset=a[1];self.put(a[3],self.offset);ret=1;event['offset']=self.offset
        elif pc==0x102da9f0:
            chunk=self.data[self.offset:self.offset+a[2]]
            self.u.mem_write(a[1],chunk);self.put(a[3],len(chunk));ret=0x4390080
            event.update(offset=self.offset,size=len(chunk),sha256=sha(chunk));self.offset+=len(chunk)
        elif pc==0x100362c0:self.u.mem_write(a[1],bytes(8))
        elif pc==0x101cb734:
            assert a[0]==0x111,a
            ret=self.display
        elif pc in (0x10290cd0,0x102da90a,0x102eaf4c,0x102eaf96,0x10035e48,0x101f596a):pass
        else:raise AssertionError(hex(pc))
        event['return']=hex(ret);self.events.append(event)
        self.u.reg_write(UC_ARM_REG_R0,ret);return self.u.reg_read(UC_ARM_REG_LR)

    def call(self,entry,args=(),until=STOP,initial=None):
        for reg in REGS:self.u.reg_write(reg,0)
        for reg,value in zip(REGS,args):self.u.reg_write(reg,value)
        for index,value in (initial or {}).items():self.u.reg_write(REGS[index],value)
        self.u.reg_write(UC_ARM_REG_SP,STACK+0xf000);self.u.reg_write(UC_ARM_REG_LR,STOP|1)
        self.u.ctl_flush_tb();pc=entry|1;started=time.monotonic();event_start=len(self.events);slices=[]
        while True:
            self.u.emu_start(pc,until,timeout=5000000,count=500000000)
            pc=self.u.reg_read(UC_ARM_REG_PC)
            if pc==until:break
            if pc in SERVICES:pc=self.adapter(pc)
            else:
                slices.append(hex(pc));pc|=1 if self.u.reg_read(UC_ARM_REG_CPSR)&32 else 0
            if time.monotonic()-started>180:raise RuntimeError(f'native timeout {hex(pc)}')
        result=dict(entry=hex(entry),args=[hex(x) for x in args],until=hex(until),
            initial=initial or {},seconds=round(time.monotonic()-started,3),
            r0=self.u.reg_read(UC_ARM_REG_R0),r0_hex=hex(self.u.reg_read(UC_ARM_REG_R0)),
            cooperative_slices=slices,adapter_events=self.events[event_start:])
        self.calls.append(result);return result['r0']

def run(rig,label,data,filename='EG162080.BIN',display=0,reported_size=None):
    rig.reset(data,filename,display,reported_size)
    discovery=rig.call(0x101b87d8,[0])
    row=dict(label=label,file=filename,sha256=sha(data),size=len(data),host_crc=binascii.crc_hqx(data,0),
        discovery_return=discovery,display_configuration=display,
        file_kind=rig.get(STATE,'B'),component_count=rig.get(LIST+8),component=rig.get(LIST+0xc,'B'),
        displayed_version=rig.string(LIST+0xd,16),raw_version=bytes(rig.u.mem_read(LIST+0x64,8)).hex())
    row['native_resource_descriptor']=bytes(rig.u.mem_read(RESOURCE,20)).hex()
    if discovery==0: # Discovery wrapper uses zero as success, leaf uses one.
        route=rig.call(0x101b9f48);row['whole_container_selected']=bool(route)
        assert route==0
        # Actual original dispatch instructions, stop before the selected function.
        rig.call(0x101f5db4,until=0x101b88f6,initial={7:BUFFER})
        assert rig.u.reg_read(UC_ARM_REG_R0)==BUFFER
        validity=rig.call(0x101b88f6,[BUFFER]);row['integrity_return']=validity
        row['loaded_buffer_sha256']=sha(bytes(rig.u.mem_read(BUFFER,len(data))))
        row['update_pointer']=hex(rig.get(LIST+0x38));row['update_length']=rig.get(LIST+0x48)
        if validity==0:
            row['component_precheck_return']=rig.call(0x101b8c40,[BUFFER])
            # Separate bounded segment: prepare the original flash-write buffer,
            # stop BEFORE the flash primitive. No erase/write/completion is modeled.
            capacity=rig.get(RESOURCE+0x10);canary=b'END-OF-REGION!!!'
            rig.u.mem_write(BUFFER+capacity,canary)
            rig.call(0x101b8f44,[BUFFER,len(data)-2,0,0],until=0x1014a674)
            expected=data[:-2]+b'\xff'*(capacity-len(data)+2)
            actual=bytes(rig.u.mem_read(BUFFER,capacity))
            assert actual==expected
            assert bytes(rig.u.mem_read(BUFFER+capacity,len(canary)))==canary
            assert rig.u.reg_read(UC_ARM_REG_R0)==BUFFER
            assert rig.u.reg_read(UC_ARM_REG_R1)==len(data)-2
            row['preflash']=dict(stopped_before='0x1014a674',flash_primitive_executed=False,
                scope='Separate original buffer-preparation segment; no physical flash or complete UI transaction.',
                capacity=capacity,payload_bytes=len(data)-2,padding_bytes=capacity-len(data)+2,
                prepared_buffer_sha256=sha(actual),padding_byte='ff',end_canary_preserved=True,
                r0=hex(rig.u.reg_read(UC_ARM_REG_R0)),r1=rig.u.reg_read(UC_ARM_REG_R1),
                descriptor=bytes(rig.u.mem_read(rig.u.reg_read(UC_ARM_REG_R2),12)).hex())
    row.update(calls=rig.calls,visited_entries=dict(rig.hits),adapter_events=rig.events)
    return row

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--smoke',action='store_true');a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    rom=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes();assert sha(rom)==SOURCE_SHA
    mod=(ROOT/'analysis/raw-control-convergence-2026-11-09/module/still-neighborhood-gates-off.bi').read_bytes()
    assert sha(mod)==CANDIDATE_SHA
    rig=Rig(rom);report=dict(ok=False,scope=__doc__,original_updater_sha256=sha(rom),cases=[])
    try:
        cases=[('original',rom,'EG162080.BIN',0,None),('candidate',mod,'EG162080.BIN',0,None)]
        if not a.smoke:
            bad=bytearray(mod);bad[0xa2654]^=1
            cases += [('candidate_full_display',mod,'eg162080.bin',1,None),
                ('damaged_crc',bytes(bad),'EG162080.BIN',0,None),
                ('wrong_model_name',mod,'EG172080.BIN',0,None),
                ('oversize_header',mod,'EG162080.BIN',0,0x2940001)]
        for label,data,filename,display,size in cases:
            row=run(rig,label,data,filename,display,size);report['cases'].append(row)
            print(json.dumps({k:v for k,v in row.items() if k not in ('calls','visited_entries','adapter_events')}),flush=True)
            if label in ('original','candidate','candidate_full_display'):
                assert row['discovery_return']==0,row
                assert row['file_kind']==2 and row['component']==3 and row['component_count']==1
                assert row['integrity_return']==0 and row['component_precheck_return']==0,row
                assert row['update_pointer']==hex(BUFFER) and row['update_length']==len(data)-2
                assert row['loaded_buffer_sha256']==sha(data)
                assert '0x101b4bb4' in row['visited_entries']
            elif label=='damaged_crc':assert row['discovery_return']==0 and row['integrity_return']==3
            else:assert row['discovery_return']!=0
            assert not set(('0x101b8ae4','0x101c3bba')) & row['visited_entries'].keys()
        report['ok']=True
    except Exception:
        report.update(error=traceback.format_exc(),pc=hex(rig.u.reg_read(UC_ARM_REG_PC)),
            failing_events=rig.events,failing_calls=rig.calls,failing_hits=dict(rig.hits))
        raise
    finally:
        (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
        (a.output/Path(__file__).name).write_bytes(Path(__file__).read_bytes())
    print(json.dumps(dict(ok=report['ok'],cases=len(report['cases']))))

if __name__=='__main__':main()
