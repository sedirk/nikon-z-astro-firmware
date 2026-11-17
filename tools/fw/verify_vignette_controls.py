"""Verify Nov 8 curve/control evidence and preserved firmware; no pixel-effect claim."""
from pathlib import Path
from datetime import datetime, timezone
import ast, binascii, hashlib, json, re, struct
import capstone

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'analysis/raw-controls-2026-11-08'
BASE = 0x10020000


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def raw(row):
    return bytes.fromhex(row['bytes'])


def memory_check(obj):
    if isinstance(obj, dict):
        if {'bytes', 'size', 'sha256'} <= obj.keys():
            data = raw(obj)
            assert len(data) == obj['size'] and hashlib.sha256(data).hexdigest() == obj['sha256']
        for child in obj.values():
            memory_check(child)
    elif isinstance(obj, list):
        for child in obj:
            memory_check(child)


def main():
    assert __debug__
    prior = read(ROOT/'analysis/raw-writeback-2026-11-04/verification.json')
    firmware, models = prior['firmware_hashes_unchanged'], prior['model_sources_unchanged']
    assert len(firmware) == 5 and len(models) == 4
    for name, digest in {**firmware, **models}.items():
        assert sha(ROOT/name) == digest, name
    blob = (ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    folder = OUT/'validated-controls'
    result = read(folder/'result.json')
    assert result['ok'] and result['firmware_unchanged']
    assert result['firmware_sha256'] == firmware['firmware/decoded/eg1620_038000.bi']
    assert sha(folder/'probe-source.py') == sha(ROOT/'tools/fw/probe_vignette_controls.py') == result['probe_sha256']
    memory_check(result)
    cases = result['cases']
    assert len(cases) == 15
    count, writes, summary = 0, 0, []
    baseline = raw(cases[0]['packing']['mmio'])
    for index, case in enumerate(cases):
        calls = case.get('calls', []) + case.get('packing', {}).get('calls', []) + case['metadata']['calls']
        for call in calls:
            assert call['blocks'][0] == call['entry'] and call['stopped_at'] == call['until'] == '0x53000000'
            count += 1
        meta = case['metadata']; payload = raw(meta['payload'])
        assert len(payload) == 116
        assert struct.unpack_from('<H', payload, 114)[0] == binascii.crc_hqx(payload[:114], 0xffff)
        assert [struct.unpack_from('<i', payload, x)[0] for x in (0x44,0x34,0x24,0x14)] == meta['coefficients']
        assert struct.unpack_from('<I', payload, 0x60)[0] == meta['blend']
        assert payload[4] == meta['status']
        if index >= 11:
            assert set(case['changed_offsets']) <= {4,114,115}
            assert meta['coefficients'] == [10240,25600,0,0] and meta['blend'] == 136
            assert all(not call['writes'] for call in calls)
            continue
        packing = case['packing']; mode = packing['mode_numeric']
        curve, mixed = raw(case['curve']), raw(case['mixed_curve'])
        expected = struct.pack('<257H', *([1024]*257)) if mode in (2,3) else mixed
        mmio = raw(packing['mmio']); table = raw(packing['table_memory'])
        assert table[0x2a50:0x2c54] == expected+b'\0\0'
        assert mmio[0x2890:0x2a94] == expected+b'\0\0'
        read_addresses = {int(row['address'],16) for row in packing['generated_curve_reads']}
        assert read_addresses == (set() if mode in (2,3) else set(range(0x50006000,0x50006202,2)))
        for lo, hi in ((0x700,0x73c),(0x1200,0x1248)):
            assert mmio[lo:hi] == baseline[lo:hi], (case['name'],hex(lo))
        driver = packing['calls'][-1]
        assert driver['entry'] == '0x100d5c86' and driver['args'][2:] == ['0x0','0x0']
        assert len(driver['writes']) == 3951
        writes += len(driver['writes'])
        selected = [row for row in driver['writes'] if 0x20382890 <= int(row['address'],16) < 0x20382a94]
        assert len(selected) == 129
        for i,row in enumerate(selected):
            assert row['pc'] == '0x10108992' and row['size'] == 4
            assert int(row['address'],16) == 0x20382890+4*i
            assert int(row['value'],16) == struct.unpack_from('<I',expected+b'\0\0',4*i)[0]
        if case['neutral']:
            assert curve == mixed == struct.pack('<257H',*([1024]*257))
            assert meta['coefficients'] == [0]*4 and meta['blend'] == 0
        changed = [i for i in range(0,len(mmio),4) if mmio[i:i+4] != baseline[i:i+4]]
        if index < 8:
            assert all(0x2890 <= i < 0x2a94 for i in changed)
        summary.append(dict(name=case['name'],blend=case['blend'],curve_samples=case['curve_samples'],
                            mixed_samples=case['mixed_samples'],coefficients=meta['coefficients'],
                            metadata_status=meta['status'],mode_numeric=mode,
                            curve_reads=len(packing['generated_curve_reads']),
                            control_9cc=hex(struct.unpack_from('<I',mmio,0x9cc)[0]),
                            changed_words_vs_strength0=[hex(x) for x in changed]))
    assert count == 80 and writes == 43461
    assert [c['blend'] for c in cases[:4]] == [0,68,136,204]
    assert [len(x['changed_words_vs_strength0']) for x in summary[:4]] == [0,79,97,103]
    normal = raw(cases[8]['packing']['mmio'])
    mode_comparisons = []
    for case in cases[9:11]:
        mmio = raw(case['packing']['mmio'])
        changes = [i for i in range(0,len(mmio),4) if mmio[i:i+4] != normal[i:i+4]]
        assert len(changes) == 98 and 0x9cc in changes
        assert all(i == 0x9cc or 0x2890 <= i < 0x2a94 for i in changes)
        assert raw(case['metadata']['payload']) == raw(cases[8]['metadata']['payload'])
        assert struct.unpack_from('<I',normal,0x9cc)[0] >> 24 == 1
        assert struct.unpack_from('<I',mmio,0x9cc)[0] >> 24 == 0
        mode_comparisons.append(dict(name=case['name'],changed_words=98,metadata_identical=True))
    # Earlier successful runs are historical iterations, not extra independent cases.
    history = []
    for name, expected_ok in (('generator-probe',True), ('curve-packing-probe',False),
                             ('isolated-curve-packing',False), ('curve-packing-calibration',True),
                             ('mode-gate-probe',True)):
        old = read(OUT/name/'result.json')
        assert old['ok'] == expected_ok and old['firmware_unchanged']
        assert sha(OUT/name/'probe-source.py') == old['probe_sha256']
        if not expected_ok:
            assert old['failure_pc'] == '0x1011f10e' and old['last_call']['entry'] == '0x100b5716'
        if name == 'generator-probe':
            for oldcase,newcase in zip(old['cases'][:8],cases[:8]):
                assert raw(oldcase['curve']) == raw(newcase['curve'])
                assert raw(oldcase['mixed_curve']) == raw(newcase['mixed_curve'])
                assert oldcase['metadata']['coefficients'] == newcase['metadata']['coefficients']
        history.append(dict(directory=name,ok=expected_ok,cases=len(old['cases'])))
        del old
    curated = read(OUT/'curated-evidence.json')
    assert len(curated['ranges']) == 26
    md = capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_THUMB)
    instruction_count = 0
    for span in curated['ranges']:
        assert span['decoded_to_end']
        lo,hi = int(span['start'],16),int(span['end'],16)
        instructions = list(md.disasm(blob[lo-BASE:hi-BASE],lo))
        assert len(instructions) == len(span['instructions'])
        for ins,row in zip(instructions,span['instructions']):
            assert (hex(ins.address),ins.bytes.hex(),ins.mnemonic,ins.op_str) == (row['pc'],row['bytes'],row['mnemonic'],row['operands'])
            if 'literal_address' in row:
                assert struct.unpack_from('<I',blob,int(row['literal_address'],16)-BASE)[0] == int(row['literal_value'],16)
            instruction_count += 1
    exif = ROOT/'analysis/raw-pixel-stage-2026-11-03/exiftool-nikon.pm'
    assert sha(exif) == '8cb754e109e41a7d108359b841db9128f6076760b3e4e10299bf8414067b1edd'
    commands = {}
    for path in sorted((OUT/'commands').glob('*/command.json')):
        cmd = read(path)
        if 'exit_code' not in cmd:
            assert 'verify_vignette_controls.py' in ' '.join(cmd['argv'])
            continue
        expected = 1 if path.parent.name in ('21-curve-packing-probe','22-isolated-curve-packing') else 0
        assert cmd['exit_code'] == expected, str(path)
        commands[path.parent.name] = cmd['exit_code']
    documents = ['README.md','docs/NEXT_STEPS.md','docs/PROJECT_GOALS.md',
                 'docs/RAW_TARGET_MAP_2026-11-03.md','docs/RAW_CONTROLS_2026-11-08.md']
    links = 0
    for name in documents:
        path = ROOT/name
        for target in re.findall(r'\]\(([^)]+)\)',path.read_text(encoding='utf-8')):
            if '://' in target or target.startswith('#'): continue
            local = (path.parent/target.split('#')[0]).resolve()
            if local not in (OUT/'verification.json',OUT/'evidence-summary.json'):
                assert local.exists(), (name,target)
            links += 1
    scripts = ['tools/fw/probe_vignette_controls.py','tools/fw/verify_vignette_controls.py']
    for name in scripts:
        ast.parse((ROOT/name).read_text(encoding='utf-8'))
    (OUT/'evidence-summary.json').write_text(json.dumps(dict(cases=summary,mode_comparisons=mode_comparisons,
        validated_cases=15,segments=80,mmio_writes=writes,curated_ranges=26,history=history,
        boundary='Original parameter/control software only; no sensor samples, physical ISP arithmetic or final NEF pixels.'),indent=2),encoding='utf-8')
    (OUT/'verification-source.py').write_bytes(Path(__file__).read_bytes())
    artifacts = {str(path.relative_to(ROOT)):sha(path) for path in OUT.rglob('*')
                 if path.is_file() and path.name!='verification.json' and 'commands' not in path.parts}
    artifacts.update({name:sha(ROOT/name) for name in scripts+documents})
    verification = dict(ok=True,checked_utc=datetime.now(timezone.utc).isoformat(),
        firmware_hashes_unchanged=firmware,model_sources_unchanged=models,qemu_runs=0,
        validated_cases=15,isolated_segments=count,mmio_writes=writes,curated_ranges=26,
        disassembled_instructions_checked=instruction_count,local_links_checked=links,
        command_exit_codes=commands,artifacts=artifacts)
    (OUT/'verification.json').write_text(json.dumps(verification,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in verification.items() if k not in
        ('firmware_hashes_unchanged','model_sources_unchanged','command_exit_codes','artifacts')}))


if __name__ == '__main__':
    main()
