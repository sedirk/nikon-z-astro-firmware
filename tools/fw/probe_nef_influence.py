"""Bounded original Z6 instructions: config, offsets, RAW handles and packaging.

Private synthetic RAM and nonzero calibration, immutable original code. Calls
are separate experiments, NOT a replay of a completed exposure. In particular,
the post-processor swap block is entered separately without inventing hardware
completion. MMIO is RAM, all pixel/payload addresses are unmapped.
"""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import traceback
import unicorn as un
from unicorn.arm_const import *

ROOT = Path(__file__).resolve().parents[2]
BASE, RAM, STACK, STOP, CAL = 0x10020000, 0x50000000, 0x52000000, 0x53000000, 0x54000000
OWNER, OBJ, STAGE = RAM, RAM+0x4000, RAM+0x5000
SOURCE, SELECTORS, PROPERTIES, CONTEXT = RAM+0x10000, RAM+0x10100, RAM+0x11000, RAM+0x12000
PACKET, STORAGE, TABLES, FLAGS, DRIVER = RAM+0x13000, RAM+0x14000, RAM+0x16000, RAM+0x1a000, RAM+0x1a100
INPUT, OUTPUT, ENCODED, PREVIEW = RAM+0x1b000, RAM+0x1b100, RAM+0x1b200, RAM+0x1b400
HEADER_HANDLE, HEADER_ADDRESS_SLOT, PACKAGE = RAM+0x1c000, RAM+0x1c100, RAM+0x1c200
PARAM, REQ = OWNER+0x394, 0xc233525c
CONFIG, INIT, CALCTX, SOURCECTX, SOURCEPACKET = 0xc20aa7c8, 0xc18812b4, 0xc18fa954, 0xc18fa844, 0xc29a34c0
MODE, MMIO = 0xc188d8c4, 0x20380000
SHA = '1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
a.output.mkdir(parents=True, exist_ok=False)
source = Path(__file__).read_bytes()
(a.output/'probe-source.py').write_bytes(source)
firmware = ROOT/'firmware/decoded/eg1620_038000.bi'
blob = firmware.read_bytes()
assert hashlib.sha256(blob).hexdigest() == SHA
uc = un.Uc(un.UC_ARCH_ARM, un.UC_MODE_THUMB)
size = (len(blob)+4095)&~4095
uc.mem_map(BASE, size)
uc.mem_write(BASE, blob)
uc.mem_protect(BASE, size, un.UC_PROT_READ | un.UC_PROT_EXEC)
for addr, size in ((RAM, 0x40000), (STACK, 0x10000), (STOP, 0x1000),
                   (CAL, 0xc0000), (0xc1800000, 0x2000000),
                   (MMIO, 0x10000), (MMIO+0x40000, 0x10000), (0x20068000,0x1000)):
    uc.mem_map(addr, size)
trace = []
def block(_uc, pc, size, _data):
    trace.append(hex(pc))
    if len(trace) > 20000:
        raise RuntimeError('Block trace cap exceeded')
uc.hook_add(un.UC_HOOK_BLOCK, block)
REGS = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
        UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
        UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
        UC_ARM_REG_R12]

def put(addr, value, fmt='I'):
    uc.mem_write(addr, struct.pack('<'+fmt, value))
def get(addr, fmt='I'):
    return struct.unpack('<'+fmt, uc.mem_read(addr, struct.calcsize(fmt)))[0]
def memory(addr, size):
    data = bytes(uc.mem_read(addr, size))
    return dict(address=hex(addr), size=size, bytes=data.hex(), sha256=hashlib.sha256(data).hexdigest())
def execute(entry, args=(), until=STOP, regs=None, stack_args=(), allow_return=False):
    trace.clear()
    for reg in REGS:
        uc.reg_write(reg, 0)
    for reg, val in zip(REGS, args):
        uc.reg_write(reg, val)
    for index, val in (regs or {}).items():
        uc.reg_write(REGS[index], val)
    uc.reg_write(UC_ARM_REG_SP, STACK+0xf000)
    uc.reg_write(UC_ARM_REG_LR, STOP|1)
    for index, val in enumerate(stack_args):
        put(STACK+0xf000+index*4, val)
    # A code hook is deliberately not used: prior work found hook-sensitive
    # IT/memset behavior in this installed Unicorn build.
    uc.emu_start(entry|1, until, count=200000)
    pc = uc.reg_read(UC_ARM_REG_PC)
    assert pc == until or (allow_return and pc == STOP), hex(pc)
    return dict(entry=hex(entry), args=[hex(x) for x in args], until=hex(until),
                initial_registers={str(k):hex(v) for k,v in (regs or {}).items()},
                stack_arguments=[hex(x) for x in stack_args], stopped_at=hex(pc),
                r0=hex(uc.reg_read(UC_ARM_REG_R0)), r1=hex(uc.reg_read(UC_ARM_REG_R1)),
                r2=hex(uc.reg_read(UC_ARM_REG_R2)), blocks=list(trace))

def reset():
    uc.mem_write(RAM, bytes(0x40000))
    uc.mem_write(STACK, bytes(0x10000))
    # No synthetic reset is asserted to be equivalent to a camera reboot.
    for addr, size in ((REQ, 0x400), (SOURCECTX, 0xe0), (SOURCEPACKET, 0x60),
                       (0xc29a3888, 0x20), (MMIO, 0x10000), (MMIO+0x40000, 0x10000),
                       (0x20068000,0x1000)):
        uc.mem_write(addr, bytes(size))
    put(INIT, 1)
    put(CONFIG+0x3e1, 0, 'B')
    put(CALCTX+0x14, CAL)
    # Same recognizable record in every group/bin; not real calibration.
    uc.mem_write(CAL+0xbc7f0, struct.pack('<6H', 101, 202, 303, 300, 405, 606)*(7*33))
    put(STAGE+0xc, OBJ)
    put(OBJ+0x3a4, OWNER)
    put(OBJ+0x1f8, INPUT)
    put(OBJ+0x1fc, OUTPUT)
    put(OBJ+0x318, PREVIEW)
    put(OBJ+0x330, ENCODED)
    for handle, pixels in ((INPUT, 0x60000000), (OUTPUT, 0x62000000)):
        put(handle+0x24, 2, 'B')
        uc.mem_write(handle+0x26, struct.pack('<3H', 9168, 6104, 4222))
        put(handle+0x34, pixels)
    put(ENCODED+0x50, 2, 'B')
    put(ENCODED+0x58, 0x64000000)
    put(ENCODED+0x5c, 0x123456)

report = dict(ok=False, scope=__doc__, firmware_sha256=SHA,
              probe_sha256=hashlib.sha256(source).hexdigest(), unicorn=un.__version__,
              cases=[], unmapped_payloads=['0x60000000','0x62000000','0x64000000','0x66000000'],
              limitations=['No complete RTOS boot, hardware execution or actual NEF file.',
                'Global RAM initially zero; config initialization flag seeded to 1.',
                'Numeric selectors are not assigned camera menu names.',
                'Driver tests deliberately use r2=0, omitting reset/start/completion.',
                'Driver packet is reduced to selected pointers; request metadata callbacks are absent.',
                'Metadata callback tests use an original tag descriptor in synthetic writable header RAM.',
                'A separately entered swap block is not a completed processing call.'])
try:
    for flag in (0, 1, 2):
        reset()
        put(CONFIG+0x3e1, flag, 'B')
        uc.mem_write(SOURCE+8, struct.pack('<2I', 1, 15))
        uc.mem_write(SELECTORS, bytes([0, 0, 2, 0, 0, 0]))
        calls = [execute(0x100760b6, [SOURCE, SELECTORS])]
        scalar = int(calls[-1]['r0'], 16)
        assert scalar == (0 if flag else 300)
        # Native static-object stores, entered at the post-query boundary.
        calls.append(execute(0x1013f938, until=0x1013f95c, regs={0:scalar, 4:OBJ}))
        assert [get(OWNER+o, 'H') for o in (0x198,0x19a,0x19c,0x19e)] == [scalar]*4
        calls.append(execute(0x100c278c, until=0x100c2798, regs={4:PROPERTIES, 5:OBJ}))
        put(CONTEXT, PROPERTIES)
        put(CONTEXT+0xd0, PARAM)
        put(CONTEXT+0x26, 512, 'H')
        uc.mem_write(CONTEXT+0x2e, struct.pack('<2H', 768, 1024))
        calls.append(execute(0x1019f3d0, [CONTEXT]))
        negatives = [get(PARAM+x, 'H') for x in (0x186,0x18c,0x192,0x198)]
        assert negatives == [(-scalar)&65535]*4
        report['cases'].append(dict(name=f'config-to-four-slots-{flag}', config=flag,
             scalar=scalar, negative_halfwords=negatives, calls=calls,
             owner=memory(OWNER+0x198,8), parameters=memory(PARAM+0x17e,0x20)))

    for flag, second_gate in ((0,0),(1,0),(2,0),(0,1)):
        reset()
        put(SOURCE+4, 1)
        put(SOURCE+8, 15)
        put(SOURCE+0x43, flag, 'B')
        calls = [execute(0x10179962, [SOURCE, PROPERTIES])]
        assert get(SOURCECTX+0x5b,'B') == flag
        put(SOURCECTX+0x38, second_gate)
        calls.append(execute(0x1011ebb8, [SOURCECTX]))
        ptr = get(SOURCEPACKET+0x40)
        record = list(struct.unpack('<4HI', uc.mem_read(ptr,12)))
        assert record == [101,202,303,0 if flag or second_gate else 300,405], record
        # Full native copy callback and dispatch run up to its following
        # update-control call. Only packet+40 is populated by this experiment.
        put(0xc180b76c+0xc,DRIVER)
        calls.append(execute(0x100bcd86,[SOURCEPACKET],until=0x100d7de2))
        source_regs=[get(0x20068804+i*4) for i in range(3)]
        assert source_regs==[(101<<16)|202,(303<<16)|record[3],405]
        report['cases'].append(dict(name=f'source-packet-{flag}-{second_gate}', config_input=flag,
             second_gate=second_gate, record=record, pointer=hex(ptr), calls=calls,
             packet=memory(ptr,12), context=memory(SOURCECTX,0xe0),
             source_registers=source_regs,register_area=memory(0x20068804,12)))

    for normalize in (0,1):
        reset()
        put(CONTEXT, PROPERTIES)
        put(CONTEXT+0xd0, PARAM)
        put(CONTEXT+0x26,512,'H')
        uc.mem_write(CONTEXT+0x2e,struct.pack('<2H',768,1024))
        put(PROPERTIES+0x86,300,'H')
        calls=[execute(0x1019f3d0,[CONTEXT])]
        put(OWNER+0x2815,normalize,'B')
        before=memory(PARAM+0x184,0x18)
        calls.append(execute(0x100ad858,[STAGE]))
        gains=[get(PARAM+x,'H') for x in (0x184,0x18a,0x190,0x196)]
        negatives=[get(PARAM+x,'H') for x in (0x186,0x18c,0x192,0x198)]
        assert gains == ([512]*4 if normalize else [768,512,512,1024])
        assert negatives == [0xfed4]*4
        report['cases'].append(dict(name=f'parameter-finalizer-{normalize}', selector=normalize,
            gains=gains, negatives=negatives, before=before, after=memory(PARAM+0x184,0x18), calls=calls))

    for bank in (0,1):
        for mode in (0,1):
            reset()
            for off, value in ((4,1),(8,INPUT),(0x1a8,OUTPUT),(0x35c,PARAM),
                               (0x360,TABLES),(0x364,FLAGS),(0x374,mode)):
                put(REQ+off,value)
            put(CONTEXT,PROPERTIES)
            put(CONTEXT+0xd0,PARAM)
            put(CONTEXT+0x26,512,'H')
            uc.mem_write(CONTEXT+0x2e,struct.pack('<2H',768,1024))
            put(PROPERTIES+0x86,300,'H')
            calls=[execute(0x1019f3d0,[CONTEXT]),execute(0x100b4b1c,[PACKET,STORAGE])]
            for fn in (0x100b3f94,0x100b37de,0x100b36f0,0x100b33bc):
                calls.append(execute(fn,[REQ,PACKET]))
            retained=(0,0xc,0x20,0x28,0x30,0x34,0x58,0xc8)
            for off in range(0,0xcc,4):
                if off not in retained:
                    put(PACKET+off,0)
            put(PACKET+0xcc,mode)
            put(DRIVER+4,bank,'B')
            mmio=MMIO+bank*0x40000
            for off in (0x310,0x3ec,0x710,0x714):
                put(mmio+off,0x5a5a5a5a)
            calls.append(execute(0x100d5c86,[DRIVER,PACKET,0,0]))
            skipped=bank==1 and mode==1
            observed={hex(off):get(mmio+off) for off in (0x310,0x3ec,0x710,0x714)}
            assert observed == ({hex(o):0x5a5a5a5a for o in (0x310,0x3ec,0x710,0x714)} if skipped else
                {'0x310':0x60000000,'0x3ec':0x62000000,'0x710':0x1ed41ed4,'0x714':0x1ed41ed4}), observed
            assert ('0x10107262' in calls[-1]['blocks']) == (not skipped)
            report['cases'].append(dict(name=f'offset-dispatch-{bank}-{mode}', bank=bank,mode=mode,
                skipped_normal_configuration=skipped, registers=observed, calls=calls,
                packet=memory(PACKET,0xd4), register_area=memory(mmio+0x700,0x24)))

    for global_flag in (0,1):
        for owner_mode, have_output in ((0,True),(0,False),(2,True)):
            reset()
            put(MODE,global_flag,'B')
            put(OWNER+0x190,owner_mode,'B')
            put(OBJ+0x1fc,OUTPUT if have_output else 0)
            put(INPUT+0x18,0x1234)
            put(INPUT+0x1c,0x5678)
            calls=[execute(0x100ae33e,[STAGE],until=0x100b4c78)]
            assert calls[-1]['r0']=='0x1' and int(calls[-1]['r1'],16)==REQ
            assert get(REQ+0x35c)==PARAM and get(REQ+8)==INPUT
            replace=owner_mode==0 and have_output
            assert get(REQ+0x1a8)==(OUTPUT if replace else 0)
            assert get(REQ+0x374)==(0 if global_flag else 1)
            request=memory(REQ,0x390)
            # Standalone post-call block: neither queue nor completion runs.
            calls.append(execute(0x100ae41e,until=0x100ae438,regs={4:OBJ,5:REQ}))
            expected=OUTPUT if replace else INPUT
            assert get(OBJ+0x1f8)==expected
            if replace:
                assert get(OUTPUT+0x18)==0x1234 and get(OUTPUT+0x1c)==0x5678
            if owner_mode==0:
                calls.append(execute(0x100af648,[STAGE],until=0x100a323e))
                assert int(calls[-1]['r0'],16)==expected+0x24
                assert int(calls[-1]['r1'],16)==ENCODED+0x50
            else:
                calls.append(execute(0x100af648,[STAGE]))
                assert '0x100a323e' not in calls[-1]['blocks']
            report['cases'].append(dict(name=f'raw-handoff-{global_flag}-{owner_mode}-{int(have_output)}',
                 global_flag=global_flag,owner_mode=owner_mode,output_present=have_output,
                 replacement=replace,encoder_reached=owner_mode==0,request=request,
                 final_input_handle=hex(expected),calls=calls))

    reset()
    put(HEADER_HANDLE+4,HEADER_ADDRESS_SLOT)
    put(HEADER_ADDRESS_SLOT,0x66000000)
    calls=[execute(0x100b1634,[1,OWNER,ENCODED,PREVIEW],stack_args=[HEADER_HANDLE,PACKAGE])]
    assert int(calls[-1]['r0'],16)==1
    assert get(PACKAGE+4)==ENCODED+0x50
    assert get(PACKAGE+0x38)==PACKAGE and get(PACKAGE+0x3c)==PACKAGE+0x68
    assert get(PACKAGE+0x68)==0x66000000
    # Native NEF branch's RAW length extraction, not the complete TIFF writer.
    put(PROPERTIES+8,PACKAGE)
    calls.append(execute(0x1026ddc4,until=0x1026ddce,regs={4:PROPERTIES,11:0}))
    assert get(PROPERTIES+0x2c)==0x123456
    report['cases'].append(dict(name='encoded-descriptor-to-container',calls=calls,
        raw_descriptor=memory(ENCODED+0x50,0x10),package=memory(PACKAGE,0x90),
        raw_payload_pointer=hex(get(ENCODED+0x58)),raw_payload_bytes=get(PROPERTIES+0x2c)))
    # Original NEF stream ordering and chunk selector consume the same RAW
    # descriptor. The payload remains unmapped; no filesystem write is run.
    order_calls=[execute(0x10271278,[1,i]) for i in range(6)]
    order=[int(c['r0'],16) for c in order_calls]
    assert order==[0,7,8,5,6,3]
    chunk_call=execute(0x10271226,[1,PROPERTIES,3,SOURCE])
    assert int(chunk_call['r0'],16)==0
    chunk=list(struct.unpack('<3I',uc.mem_read(SOURCE,12)))
    assert chunk==[0x64000000,0x123456,0]
    report['cases'].append(dict(name='nef-raw-stream-chunk',order=order,
        selected_chunk_id=3,chunk=chunk,calls=order_calls+[chunk_call],
        chunk_descriptor=memory(SOURCE,12)))

    reset()
    # Seed only the original RAM-backed metadata lookup tables needed here.
    # No full startup, metadata subsystem initialization or tag callbacks run.
    seeded=[]
    for address,size in ((0xc18d3650,16),(0xc18d36a0,64),(0xc18d38a0,4)):
        for off in range(0x14000,0x14120,16):
            src,dst,count,handler=struct.unpack_from('<4I',blob,off)
            if handler==0x1002006c and dst<=address and address+size<=dst+count:
                rom=src+address-dst
                uc.mem_write(address,blob[rom-BASE:rom-BASE+size])
                seeded.append(dict(address=hex(address),rom=hex(rom),size=size))
                break
        else:
            raise AssertionError(hex(address))
    calls=[execute(0x1028d6a0,[0,CONTEXT]),execute(0x1028d6ac,[5,CONTEXT])]
    assert get(CONTEXT+8)==0x1028d3c3
    assert get(CONTEXT+0xc)==0x11536dd8 and get(CONTEXT+0x10,'H')==91
    assert get(CONTEXT+0x14)==0x11537b52
    tags=list(struct.unpack('<'+str(get(CONTEXT+0x18,'H'))+'H',
                           uc.mem_read(get(CONTEXT+0x14),2*get(CONTEXT+0x18,'H'))))
    assert 0x3d in tags
    calls.append(execute(get(CONTEXT+8)&~1,[0x3d,PROPERTIES]))
    assert int(calls[-1]['r0'],16)==1
    report['cases'].append(dict(name='nef-makernote-selection',calls=calls,
        original_ram_tables_seeded=seeded,selection=memory(CONTEXT,0x1a),tags=tags))

    for flag in (0,1,2):
        reset()
        put(CONFIG+0x3e1,flag,'B')
        uc.mem_write(SOURCE+8,struct.pack('<2I',1,15))
        uc.mem_write(SELECTORS,bytes([0,0,2,0,0,0]))
        calls=[execute(0x100760b6,[SOURCE,SELECTORS])]
        scalar=int(calls[-1]['r0'],16)
        calls.append(execute(0x1013f938,until=0x1013f95c,regs={0:scalar,4:OBJ}))
        put(HEADER_HANDLE+4,HEADER_ADDRESS_SLOT)
        put(HEADER_ADDRESS_SLOT,0x66000000)
        calls.append(execute(0x100b1634,[1,OWNER,ENCODED,PREVIEW],stack_args=[HEADER_HANDLE,PACKAGE]))
        assert get(PACKAGE+0x34)==OWNER
        # Exact 12 bytes which native 101843fc..414 copies before callback.
        descriptor=blob[0x11537028-BASE:0x11537038-BASE]
        uc.mem_write(STORAGE,descriptor[:12])
        callback=struct.unpack_from('<I',descriptor,12)[0]
        put(CONTEXT+8,STORAGE)
        put(CONTEXT+0x10,STORAGE+0x100)
        calls.append(execute(callback&~1,[STORAGE,PACKAGE+0x30,CONTEXT]))
        values=list(struct.unpack('<4H',uc.mem_read(STORAGE+0x100,8)))
        assert values==[0 if flag else 300]*4
        assert get(STORAGE+8)==0x100 and get(CONTEXT+0x10)==STORAGE+0x108
        assert get(ENCODED+0x58)==0x64000000 and get(ENCODED+0x5c)==0x123456
        report['cases'].append(dict(name=f'config-to-nef-blacklevel-{flag}',config=flag,
            tag_id='0x003d',values=values,calls=calls,tag_entry=memory(STORAGE,12),
            tag_payload=memory(STORAGE+0x100,8),owner=memory(OWNER+0x198,8),
            package_request=memory(PACKAGE+0x30,0x10),
            raw_descriptor=memory(ENCODED+0x50,0x10)))
    report['ok']=True
except Exception:
    report['error']=traceback.format_exc()
    report['failure_pc']=hex(uc.reg_read(UC_ARM_REG_PC))
    report['failure_blocks']=list(trace)
    raise
finally:
    report['firmware_unchanged']=hashlib.sha256(firmware.read_bytes()).hexdigest()==SHA
    (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(dict(ok=report['ok'],cases=len(report['cases']),pc=hex(uc.reg_read(UC_ARM_REG_PC)))))
