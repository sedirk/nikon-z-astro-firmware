"""Independent exact-byte, native-call and protected-region audit of the CAL33 control1a LAB."""
from pathlib import Path
import argparse, binascii, json, struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC
from probe_raw_candidates import ROOT, BASE, sha
from verify_front_preflash_kit import EDITS as INHERITED

ROUND = ROOT / 'analysis/raw-spatial-controls-2026-11-12'
EXPECTED = '0b4ebdd106da2ebf0100063bf604898b15dacdb175ccb7ee7d759610a3e32945'
START, END = 0x1017d7b6, 0x1017d83e

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    stock = (ROOT / 'firmware/decoded/eg1620_038000.bi').read_bytes()
    parent = (ROOT / 'outputs/Z6-C380-front-bit11-reviewed-2026-11-09/01_TEST_MODIFIED4/EG162080.BIN').read_bytes()
    lab = (ROUND / 'static-cal33-lab/modified4-static-cal33-control1a-zero-lab.bi').read_bytes()
    assert sha(stock) == '1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
    assert sha(parent) == 'bdf30026dc9d18b09a5ca9332369d126729d63a36013e94b8b20cf6638a4ef1b'
    assert sha(lab) == EXPECTED
    assert len(stock) == len(parent) == len(lab) == 33502842 and all(binascii.crc_hqx(b, 0) == 0 for b in (stock, parent, lab))
    for addr, old, new in INHERITED:
        o = addr - BASE
        n = len(bytes.fromhex(new))
        assert stock[o:o + n].hex() == old and parent[o:o + n].hex() == lab[o:o + n].hex() == new
    diff = [i for i, (x, y) in enumerate(zip(parent, lab)) if x != y]
    assert len(diff) == 74 and sum(i < len(lab) - 2 for i in diff) == 72
    assert all(START - BASE <= i < END - BASE or i >= len(lab) - 2 for i in diff)
    reverted = bytearray(lab)
    reverted[START - BASE:END - BASE] = parent[START - BASE:END - BASE]
    reverted[-2:] = binascii.crc_hqx(reverted[:-2], 0).to_bytes(2, 'big')
    assert reverted == parent
    protected = []
    for name, lo, hi in [
        ('startup', BASE, BASE + 0x15000), ('updater', 0x101b4000, 0x101ba000),
        ('flash_veneers', 0x1014a674, 0x1014a6a4), ('resource_directory', 0x11f15000, 0x11f17000),
        ('id35_dispatch_and_selectors', 0x1011c2a0, 0x1011c820), ('id35_driver', 0x100cd64a, 0x100cda40),
        ('cal33_selector', 0x1011e23e, 0x1011e36a), ('frontend_upload', 0x1010b1c0, 0x1010b45e),
        ('static_start_wait_error', 0x10179d0c, 0x10179e00), ('irq_callback', 0x10178de8, 0x10178f38)
    ]:
        chunks = [b[lo - BASE:hi - BASE] for b in (stock, parent, lab)]
        assert len(set(chunks)) == 1, name
        protected.append(dict(name=name, start=hex(lo), end=hex(hi), sha256=sha(chunks[0])))
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True
    orig = list(md.disasm(parent[START - BASE:END - BASE], START))
    changed = list(md.disasm(lab[START - BASE:END - BASE], START))
    assert sum(i.size for i in orig) == sum(i.size for i in changed) == END - START
    assert [(i.mnemonic, i.op_str) for i in orig if i.mnemonic == 'bl'] == [(i.mnemonic, i.op_str) for i in changed if i.mnemonic == 'bl']
    assert orig[0].bytes == changed[0].bytes and orig[-1].bytes == changed[-1].bytes
    for i in changed:
        for op in i.operands:
            if op.type == ARM_OP_MEM and op.mem.base == ARM_REG_PC:
                addr = ((i.address + 4) & ~3) + op.mem.disp
                assert addr == 0x1017dbb8
                assert struct.unpack_from('<I', lab, addr - BASE)[0] == 0xc18fa844
    external = []
    for off in range(0, len(stock) - 4, 2):
        h1, h2 = struct.unpack_from('<HH', stock, off)
        if h1 & 0xf800 != 0xf000 or h2 & 0x9000 != 0x9000:
            continue
        s = (h1 >> 10) & 1
        j1 = (h2 >> 13) & 1
        j2 = (h2 >> 11) & 1
        delta = (s << 24) | ((1 ^ (j1 ^ s)) << 23) | ((1 ^ (j2 ^ s)) << 22) | ((h1 & 0x3ff) << 12) | ((h2 & 0x7ff) << 1)
        if s:
            delta -= 1 << 25
        pc = BASE + off
        target = pc + 4 + delta
        if START <= target < END and not START <= pc < END:
            ins = next(md.disasm(stock[off:off + 4], pc, count=1), None)
            if ins and ins.mnemonic in ('bl', 'b.w'):
                external.append(dict(pc=hex(pc), target=hex(target), kind=ins.mnemonic))
    code_refs = []
    asset_refs = []
    for hit in external:
        if hit == dict(pc='0x10179d7c', target=hex(START), kind='bl'):
            code_refs.append(hit)
            continue
        off = int(hit['pc'], 16) - BASE
        png = stock.rfind(b'\x89PNG\r\n\x1a\n', 0, off)
        assert png >= 0, hit
        cursor = png + 8
        chunks = []
        containing = None
        while cursor < len(stock):
            length = struct.unpack_from('>I', stock, cursor)[0]
            kind = stock[cursor + 4:cursor + 8]
            assert length < 0x1000000 and cursor + 12 + length <= len(stock), hit
            data = stock[cursor + 4:cursor + 8 + length]
            assert binascii.crc32(data) & 0xffffffff == struct.unpack_from('>I', stock, cursor + 8 + length)[0], hit
            if cursor + 8 <= off < cursor + 8 + length:
                containing = kind
            chunks.append(dict(kind=kind.decode('ascii'), bytes=length, crc32_valid=True))
            cursor += length + 12
            if kind == b'IEND':
                break
        assert containing == b'IDAT' and chunks[-1]['kind'] == 'IEND', hit
        asset = stock[png:cursor]
        name = f'branch-pattern-asset-{BASE + png:08x}.png'
        (a.output / name).write_bytes(asset)
        asset_refs.append(dict(**hit, classification='Compressed PNG IDAT data, not a recovered code reference',
            png_start=hex(BASE + png), png_end=hex(BASE + cursor), png_sha256=sha(asset), chunks=chunks, file=name))
    assert len(code_refs) == 1
    short = []
    for pc in range(START - 2052, END + 2052, 2):
        if START <= pc < END:
            continue
        i = next(md.disasm(stock[pc - BASE:pc - BASE + 2], pc, count=1), None)
        if i and i.size == 2 and i.mnemonic.startswith('b') and any(o.type == ARM_OP_IMM and START < o.imm < END for o in i.operands):
            short.append(dict(pc=hex(pc), mnemonic=i.mnemonic, operands=i.op_str))
    pointer_candidates = []
    for off in range(0, len(stock) - 4, 4):
        v = struct.unpack_from('<I', stock, off)[0]
        if START <= v & ~1 < END:
            pointer_candidates.append(dict(address=hex(BASE + off), value=hex(v)))
    result = dict(
        ok=True, scope=__doc__, sha256=EXPECTED, bytes=len(lab), changed_code_bytes=72, changed_crc_bytes=2,
        inherited_patch_count=len(INHERITED), exact_restore_to_modified4=True, protected=protected,
        native_call_count=len([i for i in changed if i.mnemonic == 'bl']), call_order_preserved=True,
        external_thumb2_candidates=external, external_thumb2_calls=code_refs, png_data_patterns=asset_refs,
        short_branch_candidates=short, aligned_pointer_candidates=pointer_candidates,
        branch_scan_limit='Thumb direct branches and aligned pointer constants only; not a complete indirect/ARM code-map proof.',
        hardware_operation_known=False, hardware_tested=False
    )
    (a.output / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf8')
    (a.output / Path(__file__).name).write_bytes(Path(__file__).read_bytes())
    print(json.dumps(dict(ok=True, changed_bytes=len(diff), short_candidates=short, pointer_candidates=pointer_candidates)))

if __name__ == '__main__':
    main()
