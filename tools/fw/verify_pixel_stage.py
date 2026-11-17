"""Audit saved original-code evidence, not camera or NEF pixel behavior."""
from pathlib import Path
from datetime import datetime, timezone
import ast
import binascii
import hashlib
import json
import re
import struct
import capstone

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT/'analysis/raw-pixel-stage-2026-11-03'
BASE = 0x10020000

def read(path):
    return json.loads(path.read_text(encoding='utf-8'))

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def check_memory(value):
    if isinstance(value, dict):
        if {'bytes', 'size', 'sha256'} <= value.keys():
            data = bytes.fromhex(value['bytes'])
            assert len(data) == value['size']
            assert hashlib.sha256(data).hexdigest() == value['sha256']
        for child in value.values():
            check_memory(child)
    elif isinstance(value, list):
        for child in value:
            check_memory(child)

def main():
    assert __debug__, 'Run without -O.'
    previous = read(ROOT/'analysis/raw-output-routing-2026-11-03/verification.json')
    hashes = previous['firmware_hashes_unchanged']
    assert len(hashes) == 5
    for name, digest in hashes.items():
        assert sha(ROOT/name) == digest, name
    blob = (ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    versions = {}
    for name, count, ok in (('isolated-stages', 1, False), ('isolated-stages-v2', 17, True)):
        result = read(OUT/name/'result.json')
        assert len(result['cases']) == count and result['ok'] == ok
        assert result['firmware_unchanged']
        assert result['firmware_sha256'] == hashes['firmware/decoded/eg1620_038000.bi']
        assert sha(OUT/name/'probe-source.py') == result['probe_sha256']
        check_memory(result)
        versions[name] = dict(ok=ok, completed_cases=count)
    failed = read(OUT/'isolated-stages/result.json')
    assert failed['failure_pc'] == '0x100b1732'
    assert failed['last_call']['args'][3] == '0x0'
    final = read(OUT/'isolated-stages-v2/result.json')
    assert sha(ROOT/'tools/fw/probe_pixel_stage.py') == final['probe_sha256']
    cases = {c['name']: c for c in final['cases']}
    assert len(cases) == 17
    selection = cases['nefinfo-profile-zero-group15']
    assert selection['tags'] == [5, 6, 7, 8, 9]
    assert selection['calls'][-1]['r0'] == '0x1'
    segments = writes = 0
    for c in cases.values():
        for call in c['calls']:
            assert call['until'] == call['stopped_at']
            assert call['blocks'][0] == call['entry']
            segments += 1
            for w in call['writes']:
                addr = int(w['address'], 16)
                assert 0x20380000 <= addr < 0x20390000 or 0x203c0000 <= addr < 0x203d0000
                writes += 1
    assert (segments, writes) == (259, 7040)
    expected_entries = ['0x1019e8b2', '0x1019f3d0', '0x10196060', '0x10196fe4',
                        '0x10197500', '0x101975be', '0x10197678', '0x10198640',
                        '0x100b5716', '0x100d5c86', '0x10305628', '0x102899a0',
                        '0x100ae41e', '0x100af648', '0x100b1634', '0x10271226']
    for bank in (0, 1):
        baseline = cases[f'baseline-bank{bank}']
        for variation in ('baseline', 'negative-0', 'negative-1', 'negative-2', 'negative-3',
                          'limit', 'curve-0', 'curve-1'):
            c = cases[f'{variation}-bank{bank}']
            assert not c['hardware_pixels_observed'] and not c['nef_created']
            assert [call['entry'] for call in c['calls']] == expected_entries
            driver = c['calls'][9]
            assert driver['args'][2:] == ['0x0', '0x0']
            assert len(driver['writes']) == 440 and len(driver['candidate_reads']) == 35
            registers = {hex(int(w['address'], 16)-0x20380000-bank*0x40000): w['value']
                         for w in driver['writes']}
            assert registers == c['registers']
            assert '0x8' not in registers
            assert registers['0x310'] == '0x60000000'
            assert registers['0x3ec'] == '0x62000000'
            assert registers['0x580'] == '0x1' and registers['0x67c'] == '0x300'
            actual_changes = {k for k in set(registers) | set(baseline['registers'])
                              if registers.get(k) != baseline['registers'].get(k)}
            if variation == 'baseline':
                expected_changes = set()
            elif variation.startswith('negative-'):
                channel = int(variation[-1])
                offset = hex(0x710 + 4*(channel//2))
                expected_changes = {offset}
                assert registers[offset] == ('0x1ed4' if channel % 2 == 0 else '0x1ed40000')
                assert c['intervention']['new'] == 0 and c['intervention']['old'] == 0xfed4
            elif variation == 'limit':
                expected_changes = {'0x720'}
                assert registers['0x720'] == '0x3039'
                assert c['intervention']['old'] == 32466 and c['intervention']['new'] == 12345
            else:
                start = 0x1200 if variation == 'curve-0' else 0x1224
                expected_changes = {hex(x) for x in range(start, start+36, 4)}
            assert actual_changes == set(c['changed_registers']) == expected_changes
            payload = bytes.fromhex(c['metadata_payload']['bytes'])
            old_payload = bytes.fromhex(baseline['metadata_payload']['bytes'])
            assert len(payload) == 104
            assert payload[:4] == blob[0x11536080-BASE:0x11536084-BASE]
            assert struct.unpack_from('<H', payload, 102)[0] == binascii.crc_hqx(payload[:102], 0xffff)
            coefficients = [0]*6
            if variation == 'curve-0': coefficients[0] = 16
            if variation == 'curve-1': coefficients[3] = 32
            assert c['coefficients'] == coefficients
            assert [struct.unpack_from('<i', payload, off)[0]
                    for off in (0x2c, 0x1c, 0x14, 0x50, 0x40, 0x38)] == coefficients
            changed_bytes = [i for i, (x, y) in enumerate(zip(payload, old_payload)) if x != y]
            expected_bytes = [44, 102, 103] if variation == 'curve-0' else (
                             [80, 102, 103] if variation == 'curve-1' else [])
            assert changed_bytes == c['metadata_changed_offsets'] == expected_bytes
            table = list(struct.unpack('<34h', bytes.fromhex(c['table']['bytes'])))
            assert table == ([1]*17 if variation == 'curve-0' else [0]*17) + (
                             [2]*17 if variation == 'curve-1' else [0]*17)
            assert struct.unpack('<3I', bytes.fromhex(c['raw_chunk_descriptor']['bytes'])) == (
                   0x64000000, 0x123456, 0)
            assert c['calls'][14]['args'][3] == '0x50028580'

    inventory = read(OUT/'table-inventory-v2.json')
    assert [d['tag'] for d in inventory['descriptors']] == ['0x5', '0x6', '0x7']
    assert inventory['nefinfo_tags'] == [5, 6, 7, 8, 9]
    for row in inventory['descriptors'] + [inventory['coefficient_metadata_template'],
               inventory['spatial_sample_positions'], inventory['nefinfo_vtable'],
               inventory['nef_profile'], inventory['nefinfo_tag_list']]:
        off = int(row['address'], 16)-BASE
        assert blob[off:off+row['size']] == bytes.fromhex(row['bytes'])
    parent = read(OUT/'parent-descriptor.json')
    assert len(parent) == 1 and parent[0]['address'] == '0x11537538'
    assert parent[0]['fields'] == [0xc7d5, 7, 0, 0, 0x102889d5]
    assert blob[0x11537538-BASE:0x11537548-BASE] == bytes.fromhex(parent[0]['bytes'])

    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    instructions = 0
    for path in OUT.glob('*.json'):
        report = read(path)
        check_memory(report)
        if not isinstance(report, dict): continue
        for span in report.get('ranges', []):
            if path.name == 'curated-evidence.json': assert span['decoded_to_end']
            for ins in span['instructions']:
                pc = int(ins['pc'], 16)
                data = bytes.fromhex(ins['bytes'])
                assert blob[pc-BASE:pc-BASE+len(data)] == data
                decoded = list(md.disasm(data, pc))
                assert len(decoded) == 1
                assert (decoded[0].mnemonic, decoded[0].op_str) == (ins['mnemonic'], ins['operands'])
                if 'literal_address' in ins:
                    off = int(ins['literal_address'], 16)-BASE
                    assert struct.unpack_from('<I', blob, off)[0] == int(ins['literal_value'], 16)
                instructions += 1
    assert len(read(OUT/'curated-evidence.json')['ranges']) == 14
    source = read(OUT/'exiftool-nikon.source.json')
    assert sha(OUT/'exiftool-nikon.pm') == source['sha256']
    assert (OUT/'exiftool-nikon.pm').stat().st_size == source['bytes']
    audit = read(OUT/'model-dependencies.json')
    for name, digest in audit['source_hashes'].items():
        assert sha(ROOT/name) == digest, name
    for item in audit['excerpts']:
        path = ROOT/next(name for name in audit['source_hashes'] if Path(name).name == item['file'])
        assert path.read_text(encoding='utf-8').splitlines()[item['first_line']-1:item['last_line']] == item['lines']

    commands = {}
    for path in sorted((OUT/'commands').glob('*/command.json')):
        command = read(path)
        if 'exit_code' not in command:
            assert any('verify_pixel_stage.py' in arg for arg in command['argv'])
            continue  # Current recorder updates this after verification returns.
        commands[path.parent.name] = command['exit_code']
    failures = {k: v for k, v in commands.items() if v}
    assert failures == {'14-isolated-stages': 1}, failures
    documents = ['README.md', 'docs/NEXT_STEPS.md', 'docs/PROJECT_GOALS.md',
                 'docs/RAW_TARGET_MAP_2026-11-03.md', 'docs/RAW_OUTPUT_ROUTING_2026-11-03.md',
                 'docs/RAW_PIXEL_STAGE_2026-11-03.md']
    links = 0
    for name in documents:
        path = ROOT/name
        for link in re.findall(r'\]\(([^)]+)\)', path.read_text(encoding='utf-8')):
            if '://' in link or link.startswith('#'): continue
            target = (path.parent/link.split('#')[0]).resolve()
            if target == OUT/'verification.json': continue
            assert target.exists(), (name, link)
            links += 1
    scripts = ['tools/fw/probe_pixel_stage.py', 'tools/fw/inspect_pixel_stage.py',
               'tools/fw/audit_pixel_model.py', 'tools/fw/verify_pixel_stage.py']
    for name in scripts: ast.parse((ROOT/name).read_text(encoding='utf-8'))
    (OUT/'verification-source.py').write_bytes(Path(__file__).read_bytes())
    artifacts = {str(path.relative_to(ROOT)): sha(path) for path in OUT.rglob('*')
                 if path.is_file() and path.name != 'verification.json' and 'commands' not in path.parts}
    artifacts.update({name: sha(ROOT/name) for name in documents+scripts})
    result = dict(ok=True, checked_utc=datetime.now(timezone.utc).isoformat(),
                  firmware_hashes_unchanged=hashes, model_sources_unchanged=audit['source_hashes'],
                  qemu_rerun_this_round=False, latest_cases=17, segments=segments,
                  recorded_mmio_writes=writes, curated_ranges=14,
                  disassembled_instructions_checked=instructions, local_links_checked=links,
                  versions=versions, command_exit_codes=commands, expected_failed_commands=failures,
                  artifacts=artifacts,
                  limitation='Verifies original-code evidence and metadata, not hardware pixel influence or a saved NEF.')
    (OUT/'verification.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps({k: result[k] for k in ('ok', 'latest_cases', 'segments', 'recorded_mmio_writes',
                                          'curated_ranges', 'disassembled_instructions_checked', 'local_links_checked')}))

if __name__ == '__main__':
    main()
