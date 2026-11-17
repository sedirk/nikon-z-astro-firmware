"""Execute C3.80's original 257-entry curve generator and NEFInfo 0006 serializer.

Private RAM inputs are artificial. This tests parameter generation, the native
neutral branch and metadata serialization, not sensor/ISP pixels or a saved NEF.
No firmware instruction, peripheral algorithm or completion status is replaced.
"""
from pathlib import Path
import argparse, binascii, hashlib, json, struct, traceback
import unicorn as un
from unicorn.arm_const import *

ROOT = Path(__file__).resolve().parents[2]
BASE, RAM, STACK, STOP = 0x10020000, 0x50000000, 0x52000000, 0x53000000
PROPS, CACHE, CTX, ARG, OUT, HISTORY, CURVE, MIXED, CACHEOUT, DEBUG, OWNER, TAG, PAYLOAD, META, PACKAGE = [
    RAM + x for x in (0, 0x1000, 0x2000, 0x3000, 0x3100, 0x4000, 0x5000, 0x6000,
                     0x7000, 0x8000, 0x10000, 0x14000, 0x14400, 0x15000, 0x16000)]
SHA = '1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
REGS = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
        UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
        UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11, UC_ARM_REG_R12]
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--pack-curves', action='store_true', help='Also run the original table packer and configuration-only driver.')
p.add_argument('--mode-gates', action='store_true', help='Also test the independent properties+7d control using native export.')
a = p.parse_args()
assert not a.mode_gates or a.pack_curves
assert __debug__
a.output.mkdir(parents=True, exist_ok=False)
source = Path(__file__).read_bytes()
(a.output / 'probe-source.py').write_bytes(source)
fw = ROOT / 'firmware/decoded/eg1620_038000.bi'
blob = fw.read_bytes()
assert hashlib.sha256(blob).hexdigest() == SHA
uc = un.Uc(un.UC_ARCH_ARM, un.UC_MODE_THUMB)
romsize = (len(blob) + 4095) & ~4095
uc.mem_map(BASE, romsize)
uc.mem_write(BASE, blob)
uc.mem_protect(BASE, romsize, un.UC_PROT_READ | un.UC_PROT_EXEC)
regions = ((RAM, 0x40000), (STACK, 0x10000), (STOP, 0x1000), (0xc1800000, 0x2000000),
           (0x20380000, 0x10000), (0x54000000, 0x100000))
for address, size in regions:
    uc.mem_map(address, size)
blocks, reads, writes = [], [], []


def on_block(_uc, pc, size, _):
    blocks.append(hex(pc))
    if len(blocks) > 100000:
        raise RuntimeError('block cap')


def on_read(_uc, kind, address, size, value, _):
    if RAM <= address < RAM + 0x40000:
        reads.append(dict(pc=hex(uc.reg_read(UC_ARM_REG_PC)), address=hex(address),
                          size=size, bytes=bytes(uc.mem_read(address, size)).hex()))


uc.hook_add(un.UC_HOOK_BLOCK, on_block)
# Deliberately no RAM-write or code hooks: local Unicorn IT/memset issue.
uc.hook_add(un.UC_HOOK_MEM_READ, on_read)


def on_mmio_write(_uc, kind, address, size, value, _):
    writes.append(dict(pc=hex(uc.reg_read(UC_ARM_REG_PC)), address=hex(address), size=size, value=hex(value)))


uc.hook_add(un.UC_HOOK_MEM_WRITE, on_mmio_write, begin=0x20380000, end=0x2038ffff)


def put(address, value, fmt='I'):
    uc.mem_write(address, struct.pack('<' + fmt, value))


def get(address, fmt='I'):
    return struct.unpack('<' + fmt, uc.mem_read(address, struct.calcsize(fmt)))[0]


def memory(address, size):
    data = bytes(uc.mem_read(address, size))
    return dict(address=hex(address), size=size, bytes=data.hex(), sha256=hashlib.sha256(data).hexdigest())


report = dict(ok=False, scope=__doc__, firmware_sha256=SHA,
              probe_sha256=hashlib.sha256(source).hexdigest(), unicorn=un.__version__, cases=[],
              limitations=['Artificial properties, cached coefficients and RAM objects.',
                           'Complete generator and serializer, separately invoked.',
                           'Neutral curve means 257 parameter entries of 1024, not a proven ISP bypass.',
                           'Menu meanings and physical pipeline position require separate evidence.',
                           'No sensor samples, physical ISP arithmetic, encoder or saved NEF.'])


def execute(entry, args=(), until=STOP, regs=None):
    blocks.clear(); reads.clear(); writes.clear()
    for reg in REGS:
        uc.reg_write(reg, 0)
    for reg, value in zip(REGS, args):
        uc.reg_write(reg, value)
    for index, value in (regs or {}).items():
        uc.reg_write(REGS[index], value)
    uc.reg_write(UC_ARM_REG_SP, STACK + 0xf000)
    uc.reg_write(UC_ARM_REG_LR, STOP | 1)
    report['last_call'] = dict(entry=hex(entry), args=[hex(x) for x in args], until=hex(until),
                              initial_registers={str(k): hex(v) for k, v in (regs or {}).items()})
    uc.ctl_flush_tb()
    uc.emu_start(entry | 1, until, count=1500000)
    pc = uc.reg_read(UC_ARM_REG_PC)
    assert pc == until, hex(pc)
    return dict(**report['last_call'], stopped_at=hex(pc), blocks=list(blocks), reads=list(reads), writes=list(writes),
                registers={f'r{i}': hex(uc.reg_read(reg)) for i, reg in enumerate(REGS)})


def reset(cached, neutral, polynomial, strength):
    for address, size in regions:
        uc.mem_write(address, bytes(size))
    # Global RAM is an explicit zero fixture, matching probe_pixel_stage.py.
    # The packet constructor's calibration dependency is separately supplied
    # as zero-filled private memory, not as a replacement function return.
    for address in (CURVE, MIXED):
        uc.mem_write(address, b'\xa5' * (514 + 32))
    uc.mem_write(OWNER + 0xff8, b'\x5a' * 0x30)
    for off, val in ((0, PROPS), (4, CACHE), (8, CTX)):
        put(ARG + off, val)
    for off, val in ((0, CURVE), (4, MIXED), (8, CACHEOUT), (12, DEBUG), (16, OWNER + 0x1014)):
        put(OUT + off, val)
    put(PROPS + 0x62, cached, 'B')
    put(PROPS + 0x63, neutral, 'B')
    put(PROPS + 0x52, strength, 'B')
    # Keep the metadata owner setting consistent with the native builder's
    # owner+25e -> properties+52 identity mapping for numeric values 0..3.
    put(OWNER + 0x25e, strength, 'B')
    # A valid shape selector is supplied only in the cached path. The uncached
    # comparison intentionally starts from zero property bytes and ROM tables.
    put(CACHE, neutral, 'B'); put(CACHE + 1, polynomial, 'B')
    put(CACHE + 2, 16, 'B'); put(CACHE + 3, 160, 'B')
    put(CACHE + 4, 2048, 'H')
    for i, val in enumerate((4096, 2048, 1024, 512)):
        put(CACHE + 8 + 4*i, val, 'i')
    put(CACHE + 24, 256, 'i'); put(CACHE + 28, 4, 'i')


def serialize():
    call0 = execute(0x10305628)
    version = get(0xc27f1844)
    put(PACKAGE + 0x34, OWNER)
    descriptor = blob[0x11536d98-BASE:0x11536da8-BASE]
    assert struct.unpack_from('<H', descriptor)[0] == 6
    uc.mem_write(TAG, descriptor[:12])
    put(META + 12, TAG); put(META + 16, PAYLOAD)
    call1 = execute(0x10289942, [TAG, PACKAGE + 0x30, META])
    data = bytes(uc.mem_read(PAYLOAD, 116))
    assert get(TAG + 4) == 116 and get(TAG + 8) == PAYLOAD - TAG
    assert get(META + 16) == PAYLOAD + 116
    assert data[:4] == blob[version-BASE:version-BASE+4]
    assert struct.unpack_from('<H', data, 114)[0] == binascii.crc_hqx(data[:114], 0xffff)
    coefs = [get(OWNER + 0x1014 + 4*i, 'i') for i in range(4)]
    assert [struct.unpack_from('<i', data, x)[0] for x in (0x44, 0x34, 0x24, 0x14)] == coefs
    assert struct.unpack_from('<I', data, 0x60)[0] == get(OWNER + 0x1024, 'H')
    flag = 0 if get(OWNER + 0x22d6, 'B') & 8 else 1 if get(OWNER + 0x25e, 'B') else 2
    assert data[4] == flag
    return dict(calls=[call0, call1], version_pointer=hex(version), payload=memory(PAYLOAD, 116),
                coefficients=coefs, blend=get(OWNER + 0x1024, 'H'), status=flag)


def pack_curves(mode=None):
    """Fresh synthetic table context; full native calls, image payloads unmapped."""
    tctx, targ, oldprop, tables, oldcurves, history2, aux, debug2 = [
        RAM+x for x in (0x20000,0x25000,0x26000,0x27000,0x2c000,0x2d000,0x2e000,0x2f000)]
    req, packet, storage, driver, obj, inp, outp, flags = [
        RAM+x for x in (0x30000,0x31000,0x32000,0x33000,0x34000,0x35000,0x35100,0x36000)]
    calls = []
    if mode is not None:
        mainctx, mainprops, auxcal = RAM+0x37000, RAM+0x38000, RAM+0x39000
        for off,val in ((0,mainprops),(0x1c,auxcal),(0xcc,auxcal+0x40),
                        (0xd0,OWNER+0x394),(0xd4,oldprop)):
            put(mainctx+off,val)
        put(mainprops+0x68,6104,'H'); put(mainprops+0x6a,4222,'H')
        put(mainprops+0x7d,mode,'B')
        calls.append(execute(0x101a0828,[mainctx]))
        calls.append(execute(0x10171dfc,[mainctx]))
        assert get(oldprop+0x6c,'B')==int(mode in (2,3))
        assert get(OWNER+0x394+0x2b4)==int(mode not in (2,3))
    # Mirrors pointer relationships in 100ad7d8 -> 100c2842 -> 10171dbc.
    # For mode=None, oldprop/history2/oldcurves are explicit zero fixtures.
    for off,val in ((0,oldprop),(4,oldcurves),(8,0),(12,MIXED),(20,tctx)):
        put(targ+off,val)
    put(targ+16,1,'B'); put(targ+17,0,'B')
    put(aux,tables); put(aux+4,RAM+0x2e100); put(aux+8,debug2)
    packing_call=execute(0x10171dbc,[targ,history2,aux]); calls.append(packing_call)
    report['pending_packing'] = dict(calls=calls,table_memory=memory(tables,0x3a0c))
    mixed_reads = [r for r in packing_call['reads'] if MIXED <= int(r['address'],16) < MIXED+514]
    assert bool(mixed_reads)==(mode not in (2,3)), 'unexpected generated-curve read condition'
    put(0xc18812b4,1); put(0xc18fa954+0x14,0x54000000)
    put(obj+0x3a4,OWNER); put(obj+0x1f8,inp); put(obj+0x1fc,outp)
    for handle,pixels in ((inp,0x60000000),(outp,0x62000000)):
        put(handle+0x24,2,'B')
        uc.mem_write(handle+0x26,struct.pack('<3H',9168,6104,4222))
        put(handle+0x34,pixels)
    for off,val in ((4,1),(8,inp),(0x1a8,outp),(0x35c,OWNER+0x394),
                    (0x360,tables),(0x364,flags),(0x378,1),(0x380,obj)):
        put(req+off,val)
    calls.append(execute(0x100b5716,[req,packet,storage]))
    packet_before=memory(packet,0xd4)
    calls.append(execute(0x100d5c86,[driver,packet,0,0]))
    assert packet_before==memory(packet,0xd4)
    assert get(0x20380310)==0x60000000 and get(0x203803ec)==0x62000000
    if mode is not None:
        assert get(0x203809cc)>>24==int(mode not in (2,3))
        if mode in (2,3):
            assert bytes(uc.mem_read(0x20382890,516))==struct.pack('<257H',*([1024]*257))+b'\0\0'
    return dict(calls=calls,generated_curve_reads=mixed_reads,table_memory=memory(tables,0x3a0c),
                packet=packet_before,mmio=memory(0x20380000,0x10000),mode_numeric=mode,
                exported_main_parameters=memory(oldprop,0x74),
                fixture='Zero global RAM, calibration at 54000000, old parameters, history and 17-entry tables; config initialized c18812b4=1; forced table rebuild c=1; bank0; driver start=0; pixels unmapped.')


calls = []
try:
    configs = [(f'cached-quadratic-strength{s}', 1, 0, 0, s) for s in range(4)]
    configs += [('cached-neutral', 1, 1, 0, 2), ('cached-polynomial', 1, 0, 1, 2),
                ('uncached-neutral', 0, 1, 0, 2), ('uncached-rom-calculation', 0, 0, 0, 2)]
    configs = [(*c,None) for c in configs]
    if a.mode_gates:
        configs += [(f'independent-mode-{m}',1,0,0,2,m) for m in (0,2,3)]
    for name, cached, neutral, polynomial, strength, mode in configs:
        report['current_case'] = name
        reset(cached, neutral, polynomial, strength)
        before = dict(properties=memory(PROPS, 108), cache=memory(CACHE, 32),
                      output_vector=memory(OUT, 20), old_tag7=memory(OWNER + 0xff8, 28))
        calls = [execute(0x1017235a, [ARG, HISTORY, OUT])]
        curve = list(struct.unpack('<257H', uc.mem_read(CURVE, 514)))
        mixed = list(struct.unpack('<257H', uc.mem_read(MIXED, 514)))
        blend = get(CTX + 0x2c8, 'H')
        assert bytes(uc.mem_read(CURVE + 514, 32)) == b'\xa5' * 32
        assert bytes(uc.mem_read(MIXED + 514, 32)) == b'\xa5' * 32
        assert memory(OWNER + 0xff8, 28) == before['old_tag7']
        assert memory(PROPS, 108) == before['properties']
        assert memory(CACHE, 32) == before['cache']
        if neutral:
            assert curve == mixed == [1024] * 257
            assert bytes(uc.mem_read(OWNER + 0x1014, 18)) == bytes(18)
            assert '0x101a1240' in calls[0]['blocks']
        elif cached and not polynomial:
            expected = [max(1024, min(65535, ((4*min(i,160)+256)*min(i,160)+0x400000) >> 12)) for i in range(257)]
            assert curve == expected and len(set(curve)) > 1
        expected_mix = [max(0, min(65535, 1024 - blend + (x * blend)//1024)) for x in curve]
        assert mixed == expected_mix
        packing = pack_curves(mode) if a.pack_curves else None
        metadata = serialize()
        report['cases'].append(dict(name=name, cached=cached, neutral=neutral, polynomial=polynomial,
            strength_numeric=strength, before=before, calls=calls, curve=memory(CURVE, 514),
            mixed_curve=memory(MIXED, 514), curve_samples=[curve[i] for i in (0,64,128,160,256)],
            mixed_samples=[mixed[i] for i in (0,64,128,160,256)], blend=blend,
            cache_output=memory(CACHEOUT, 32), coefficient_output=memory(OWNER+0x1014,20), metadata=metadata, packing=packing))
    # Status-only changes are compared using identical generated parameters.
    reference = None
    curve_before, mixed_before = memory(CURVE,514), memory(MIXED,514)
    for name, bitfield, setting in [('flag-baseline',0,0), ('flag-setting1',0,1), ('flag-bit3-setting0',8,0), ('flag-bit3-setting1',8,1)]:
        report['current_case'] = name
        put(OWNER+0x22d6,bitfield,'B'); put(OWNER+0x25e,setting,'B')
        meta = serialize(); data = bytes.fromhex(meta['payload']['bytes'])
        if reference is None:
            reference = data
        changed = [i for i,(x,y) in enumerate(zip(reference,data)) if x != y]
        assert set(changed) <= {4,114,115}
        assert (4 in changed) == (name != 'flag-baseline')
        assert curve_before == memory(CURVE,514) and mixed_before == memory(MIXED,514)
        report['cases'].append(dict(name=name, status_inputs=[bitfield,setting], changed_offsets=changed, metadata=meta))
    report.pop('pending_packing',None)
    report['ok'] = True
except Exception:
    report['error'] = traceback.format_exc()
    report['failure_pc'] = hex(uc.reg_read(UC_ARM_REG_PC))
    report['failure_blocks'], report['failure_reads'] = list(blocks), list(reads)
    report['completed_calls'] = calls
    raise
finally:
    report['firmware_unchanged'] = hashlib.sha256(fw.read_bytes()).hexdigest() == SHA
    (a.output/'result.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(dict(ok=report['ok'], cases=len(report['cases']), pc=hex(uc.reg_read(UC_ARM_REG_PC)))))
