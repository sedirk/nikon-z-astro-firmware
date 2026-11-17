"""Build a same-size still-builder LAB: clear only the CAL33 +1a cached byte.

All native selector/upload calls remain. Only OR-with-zero after three proven
constant-zero selectors is omitted; final error ORs are equivalently shortened.
No resource mutation, ID35 change, shared selector patch, code cave or new literal.
This is an experimental control test, not a proven hardware bypass.
"""
from pathlib import Path
import argparse, binascii, json, struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from keystone import Ks, KS_ARCH_ARM, KS_MODE_THUMB
from probe_raw_candidates import ROOT, BASE, sha

START, END, LITERAL, TARGET = 0x1017d7b6, 0x1017d83e, 0x1017dbb8, 0xc29a3749
PARENT = 'outputs/Z6-C380-front-bit11-reviewed-2026-11-09/01_TEST_MODIFIED4/EG162080.BIN'
PARENT_SHA = 'bdf30026dc9d18b09a5ca9332369d126729d63a36013e94b8b20cf6638a4ef1b'
ZERO_OR = {0x1017d7ec: 0x1011e150, 0x1017d7f4: 0x1011e2ce, 0x1017d7fc: 0x1011e36a}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    b = (ROOT / PARENT).read_bytes()
    assert sha(b) == PARENT_SHA and binascii.crc_hqx(b, 0) == 0
    stock = (ROOT / 'firmware/decoded/eg1620_038000.bi').read_bytes()
    assert b[START - BASE:END - BASE] == stock[START - BASE:END - BASE]
    assert struct.unpack_from('<I', b, LITERAL - BASE)[0] == 0xc18fa844
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
    original = list(md.disasm(b[START - BASE:END - BASE], START))
    assert original[-1].address + original[-1].size == END
    code = bytearray()
    mapping = []
    def emit(assembly, source_pc, reason):
        pc = START + len(code)
        chunk = bytes(ks.asm(assembly, addr=pc)[0])
        code.extend(chunk)
        mapping.append(dict(pc=hex(pc), source_pc=hex(source_pc) if source_pc else None, assembly=assembly, bytes=chunk.hex(), reason=reason))
    for ins in original:
        if ins.address in ZERO_OR:
            assert ins.mnemonic == 'orrs' and ins.op_str == 'r4, r0'
            continue
        if ins.mnemonic == 'ldr' and ins.op_str.startswith('r0, [pc,'):
            pc = START + len(code)
            delta = LITERAL - ((pc + 4) & ~3)
            assembly = f'ldr r0, [pc, #{delta}]'
            reason = 'Keep the same existing context literal after relocation.'
        elif ins.address in (0x1017d826, 0x1017d830):
            assembly = 'orrs r4, r0'
            reason = 'Equivalent error accumulation; intermediate r5 is unnecessary.'
        else:
            assembly = ins.mnemonic + ' ' + ins.op_str
            reason = 'Original instruction semantics.'
        emit(assembly, ins.address, reason)
        if ins.address == 0x1017d7f0:
            emit('movw r1, #0x3749', None, 'Address of RAM cache for CAL33 header+1a.')
            emit('movt r1, #0xc29a', None, 'Address construction does not alter condition flags.')
            emit('strb r0, [r1]', None, 'Selector returns 0; clear one cached byte, retaining source calibration and table.')
    assert len(code) == END - START, (len(code), END - START)
    after = list(md.disasm(bytes(code), START))
    assert after[-1].address + after[-1].size == END
    original_calls = [i.op_str for i in original if i.mnemonic == 'bl']
    assert [i.op_str for i in after if i.mnemonic == 'bl'] == original_calls
    out = bytearray(b)
    out[START - BASE:END - BASE] = code
    out[-2:] = binascii.crc_hqx(out[:-2], 0).to_bytes(2, 'big')
    assert binascii.crc_hqx(out, 0) == 0 and len(out) == len(b)
    diff = [i for i, (x, y) in enumerate(zip(b, out)) if x != y]
    assert all(START - BASE <= i < END - BASE or i >= len(b) - 2 for i in diff)
    dest = a.output / 'modified4-static-cal33-control1a-zero-lab.bi'
    dest.write_bytes(out)
    manifest = dict(
        status='LAB_ONLY_NOT_RELEASED', scope=__doc__, parent=PARENT, parent_sha256=PARENT_SHA,
        module=dest.name, sha256=sha(out), bytes=len(out), crc16=out[-2:].hex(),
        function_start=hex(START), function_end=hex(END), before=b[START - BASE:END - BASE].hex(), after=bytes(code).hex(),
        target_cache_byte=hex(TARGET), target_register='0x20068704', calibration_resource_modified=False,
        existing_calls=original_calls, call_order_preserved=True, source_literal=hex(LITERAL),
        zero_return_contracts={hex(pc): hex(fn) for pc, fn in ZERO_OR.items()}, mapping=mapping,
        changed_code_bytes=sum(i < len(out) - 2 for i in diff), total_changed_bytes=len(diff),
        hardware_meaning='Unconfirmed; one control-input experiment. No pixel or shutter success claimed.',
        original_and_parent_preserved=sha((ROOT / PARENT).read_bytes()) == PARENT_SHA
    )
    (a.output / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf8')
    (a.output / 'instructions.txt').write_text('\n'.join(f'{i.address:08x} {i.mnemonic} {i.op_str}' for i in after) + '\n', encoding='utf8')
    (a.output / Path(__file__).name).write_bytes(Path(__file__).read_bytes())
    print(json.dumps({k: manifest[k] for k in ('status', 'sha256', 'bytes', 'changed_code_bytes', 'total_changed_bytes')}))

if __name__ == '__main__':
    main()
