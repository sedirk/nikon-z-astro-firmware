"""Read-only final static audit of exact modified2 bytes, independent of recipe."""
from pathlib import Path
import argparse, binascii, datetime, json, struct
import capstone
from verify_vignette_preflash_kit import BASE, SIZE, DIGESTS, EDITS, need, sha, reconstruct

ROOT = Path(__file__).resolve().parents[2]
SOURCES = {
    'stock': ROOT/'firmware/decoded/eg1620_038000.bi',
    'modified1': ROOT/'outputs/Z6-C380-preflash-reviewed-2026-11-09/01_TEST/EG162080.BIN',
    'test': ROOT/'analysis/raw-ring-controls-2026-11-09/lab-modules/still-neighborhood-plus-vignette-neutral-lab.bi',
}


def read(path):
    return json.loads(path.read_text(encoding='utf8'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(); args.output.mkdir(parents=True, exist_ok=False)
    blobs = {key: path.read_bytes() for key, path in SOURCES.items()}
    for key, data in blobs.items():
        need(len(data) == SIZE and sha(data) == DIGESTS[key], 'Input changed: '+key)
        need(binascii.crc_hqx(data, 0) == 0, 'CRC mismatch: '+key)
    need(reconstruct(blobs['stock'], EDITS) == blobs['test'], 'Independent rebuild mismatch')
    need(reconstruct(blobs['stock'], EDITS[:3]) == blobs['modified1'], 'Modified1 mismatch')
    official = ROOT/'firmware/original/Z_6_0380.bin'
    official_sha = sha(official.read_bytes())
    need(official_sha == 'ff978ffdf77c58c0b861a06e16d432d5886969f3cdd05d62f6c8e82e8a4cea54', 'Official package changed')
    prior = ROOT/'analysis/raw-ring-controls-2026-11-09/evidence-index.json'
    for row in read(prior)['files']:
        need(sha((ROOT/row['path']).read_bytes()) == row['sha256'], 'Prior frozen file changed: '+row['path'])
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB); md.detail = True
    code = []; contexts = []
    for lo, hi in ((0x100c24f2, 0x100c2824), (0x100c289e, 0x100c29c6)):
        for variant, blob in blobs.items():
            ins = list(md.disasm(blob[lo-BASE:hi-BASE], lo))
            starts = {i.address for i in ins}
            for pc, _, _ in EDITS:
                if lo <= pc < hi:
                    need(pc in starts, 'Patch is not an instruction boundary')
            contexts.append(dict(variant=variant, start=hex(lo), end=hex(hi),
                instructions=[dict(pc=hex(i.address), bytes=i.bytes.hex(), text=i.mnemonic+' '+i.op_str) for i in ins]))
    for pc, old, new in EDITS:
        row = dict(pc=hex(pc), before=old, after=new)
        for label, data in (('old', bytes.fromhex(old)), ('new', bytes.fromhex(new))):
            decoded = list(md.disasm(data, pc)); need(len(decoded) == 1 and decoded[0].size == 4, 'Bad instruction')
            i = decoded[0]; need(not i.update_flags, 'Unexpected flag update')
            row[label+'_instruction'] = i.mnemonic+' '+i.op_str
        code.append(row)
    comparisons = []
    for key, edits, count in (('stock', EDITS, 18), ('modified1', EDITS[3:], 8)):
        other = blobs[key]; candidate = blobs['test']
        allowed = {j for pc, _, _ in edits for j in range(pc-BASE, pc-BASE+4)} | {SIZE-2, SIZE-1}
        delta = [i for i, (x, y) in enumerate(zip(other, candidate)) if x != y]
        need(set(delta) <= allowed and len(delta) == count, 'Unexpected differences: '+key)
        restored = bytearray(candidate)
        for i in allowed:
            restored[i] = other[i]
        need(bytes(restored) == other, 'Exact rollback mismatch: '+key)
        comparisons.append(dict(baseline=key, diff_bytes=len(delta), offsets=[hex(i) for i in delta],
                                all_bytes_outside_slots_and_crc_identical=True, exact_restore=True))
    # Unchanged ranges supplement the complete byte comparison above.
    ranges = []
    for label, lo, hi in (('startup_and_scatter', BASE, BASE+0x15000),
                         ('updater', 0x101b4000, 0x101ba000),
                         ('flash_veneers', 0x1014a674, 0x1014a6a4)):
        chunks = [b[lo-BASE:hi-BASE] for b in blobs.values()]
        need(len(set(chunks)) == 1, 'Protected range changed')
        ranges.append(dict(name=label, start=hex(lo), end=hex(hi), sha256=sha(chunks[0])))
    scatter = []
    for off in range(0x14000, 0x14120, 16):
        src, dst, length, handler = struct.unpack_from('<4I', blobs['stock'], off)
        if dst <= 0xc2a10c28 < dst+length:
            payloads = [b[src-BASE:src-BASE+length] for b in blobs.values()]
            need(len(set(payloads)) == 1, 'RAM scheduler source differs')
            scatter.append(dict(source=hex(src), destination=hex(dst), bytes=length,
                                handler=hex(handler), sha256=sha(payloads[0])))
    need(bool(scatter), 'No scheduler scatter mapping')
    # Previous successful chain checks are evidence dependencies, not new cases.
    dependencies = []
    for relative in ('analysis/raw-ring-controls-2026-11-09/lab-native-v2/result.json',
                     'analysis/raw-ring-controls-2026-11-09/candidate-review/result.json',
                     'analysis/modified1-nef-2026-11-09/verification.json'):
        path = ROOT/relative; need(read(path)['ok'], 'Prior result failed')
        dependencies.append(dict(path=relative, sha256=sha(path.read_bytes())))
    report = dict(ok=True, created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        inputs=[dict(mode=k, path=str(v.relative_to(ROOT)), sha256=DIGESTS[k], bytes=SIZE,
                     crc_trailer=blobs[k][-2:].hex()) for k, v in SOURCES.items()],
        original_container_sha256=official_sha, prior_frozen_files=len(read(prior)['files']),
        comparisons=comparisons, edits=code, unchanged_ranges=ranges, scheduler_scatter=scatter,
        prior_evidence=dependencies, version_bump=False, boot_or_updater_edits=False,
        physical_flash=False, physical_ring_removal=False)
    (args.output/'result.json').write_text(json.dumps(report, indent=2), encoding='utf8')
    (args.output/'contexts.json').write_text(json.dumps(contexts, indent=2), encoding='utf8')
    for name in (Path(__file__).name, 'verify_vignette_preflash_kit.py'):
        (args.output/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    print(json.dumps(dict(ok=True, candidate_sha256=DIGESTS['test'], comparisons=comparisons,
                          prior_frozen_files=report['prior_frozen_files'])))


if __name__ == '__main__':
    main()
