"""Recheck saved RAW configuration evidence, not physical camera pixel behavior."""
from pathlib import Path
from datetime import datetime, timezone
import ast
import hashlib
import json
import re
import struct
import capstone

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT/'analysis/raw-preprocess-2026-11-03'
BASE = 0x10020000
COMMIT = '419a1f2a91a1f2d3a0209027c29606475f7fe26f'


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def u32(data, offset=0):
    return struct.unpack_from('<I', data, offset)[0]


def u16(data, offset=0):
    return struct.unpack_from('<H', data, offset)[0]


def memory(area):
    data = bytes.fromhex(area['bytes'])
    assert len(data) == area['size']
    assert hashlib.sha256(data).hexdigest() == area['sha256']
    return data


def main():
    assert __debug__, 'Run without -O.'
    (OUT/'verification-source.py').write_bytes(Path(__file__).read_bytes())
    previous = read(ROOT/'analysis/raw-buffers-2026-11-03/verification.json')
    hashes = previous['firmware_hashes_unchanged']
    assert len(hashes) == 5
    for name, digest in hashes.items():
        assert sha(ROOT/name) == digest, name
    eg_sha = hashes['firmware/decoded/eg1620_038000.bi']
    blob = (ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    metrics = {}
    for name, count in (('native-preprocess', 19), ('native-offset', 51)):
        path = OUT/name
        run, rows = read(path/'result.json'), read(path/'events.json')
        assert run['ok'] and run['firmware_unchanged']
        assert run['firmware_sha256'] == eg_sha and run['upstream_commit'] == COMMIT
        assert run['event_count'] == len(rows) == count
        assert sha(path/'probe-source.py') == run['probe_sha256']
        calls = [c['result'] for c in run['calls']]
        assert [c['function'] for c in calls] == ['0x101efaa8', '0x101eedb4', '0x10170cca', '0x10170cca']
        assert calls[1]['payload'] == '0000010000000000000000000000000001000000000000000000000000000000'
        assert int(calls[1]['return_r0'], 16) == 0
        assert calls[2]['arguments'] == ['0x64'] and calls[3]['arguments'] == ['0x1388']
        actions = [json.loads(s) for s in (path/'session/actions.jsonl').read_text(encoding='utf-8').splitlines()]
        boot, = [a for a in actions if a['kind'] == 'boot']
        assert not boot['firmware_modified'] and not boot['camera_access'] and boot['guest_state_modified']
        assert boot['build']['binary_sha256'] == previous['recorded_qemu_binary_sha256']
        assert boot['build']['sources']['qemu/nikon-z6.c'] == previous['qemu_source_sha256']
        capped = [a['result']['function'] for a in actions if a['kind'] == 'original_firmware_call'
                  and len(a['result']['trace']) >= 256]
        assert not capped
        for stage in ('baseline', 'final'):
            for area in run[stage].values():
                if 'bytes' in area:
                    memory(area)
        banks, table_count, stored = [], 0, []
        for row in rows:
            assert run['points'][row['registers']['r15']] == row['event']
            areas = row['memory']
            for area in areas.values():
                if 'bytes' in area:
                    memory(area)
            if row['event'] == 'processing_driver':
                banks.append(memory(areas['driver'])[4])
            if row['event'] == 'offset_calibration_lookup':
                ctx = memory(areas['calibration_context'])
                table = areas['offset_calibration_table']
                assert u32(ctx, 0x14) == 0xc9700000
                assert int(table['address'], 16) == u32(ctx, 0x14)+0xbc7f6
                assert memory(table) == bytes(7*33*12)
                assert memory(areas['offset_lookup_input'])[0x10] == 0
                table_count += 1
            if row['event'] == 'offset_calibration_return':
                assert row['return_value'] == int(row['registers']['r1'], 16) == 0
            if row['event'] == 'four_slot_parameter_generator':
                assert u16(memory(areas['generator_input']), 0x86) == 0
            if row['event'] == 'four_slot_register_packer':
                data = memory(areas['four_slot_input'])
                assert [u16(data, off) for off in (2, 8, 14, 20)] == [0]*4
            if row['event'] == 'still_offset_stored':
                owner = areas['still_parameter_owner']
                assert u16(memory(owner), 0x19c) == row['stored_value'] == 0
                assert owner['address'] == run['final']['still_parameter_owner']['address']
                stored.append(row['stored_value'])
        assert banks and set(banks) == {0}
        absent = ['still_raw_processing_entry', 'processing_submit_wrapper', 'processing_packet_builder',
                  'instance_1_queue_submit', 'raw_output_address_packer', 'still_raw_encoding_entry']
        assert not set(absent) & {r['event'] for r in rows}
        if name == 'native-offset':
            assert len(stored) == 1 and table_count > 0
        metrics[name] = dict(event_count=count, driver_banks=banks, capped_calls=capped,
            zero_calibration_table_snapshots=table_count, still_offset_values=stored,
            later_still_points_not_hit=absent)

    # Preserve failed probes as failures; intermediate successes are superseded,
    # not added to the final count.
    versions = [('isolated-preprocess', False, 5), ('isolated-preprocess-v2', False, 5),
                ('isolated-preprocess-v3', True, 8), ('isolated-preprocess-v4', True, 14),
                ('isolated-preprocess-v5', True, 20)]
    for name, ok, count in versions:
        result = read(OUT/name/'result.json')
        assert result['ok'] is ok and len(result['cases']) == count
        assert result['firmware_unchanged'] and result['firmware_sha256'] == eg_sha
        assert sha(OUT/name/'probe-source.py') == result['probe_sha256']
    result = read(OUT/'isolated-preprocess-v5/result.json')
    for case in result['cases']:
        for call in case['calls']:
            assert call['stopped_at'] == '0x53000000'
        if 'register_file' in case:
            registers = (OUT/'isolated-preprocess-v5'/case['register_file']).read_bytes()
            assert len(registers) == 0x10000
            assert hashlib.sha256(registers).hexdigest() == case['register_sha256']
            out = case['output_present']
            assert u32(registers, 0x310+case['input_group']*0x10) == 0x60000000
            assert u32(registers, 0x3ec) == (0x62000000 if out else 0)
            assert u32(registers, 0x580) == int(out)
            assert u32(registers, 0x67c) == (3 if out else 1)<<8
        if case['name'].startswith('four-slot-offset'):
            value, bank = case['source_offset'], case['bank']
            assert case['gains'] == [768, 512, 512, 1024]
            assert case['negative_halfwords'] == [(-value)&0xffff]*4
            encoded = (-value)&0x1fff
            assert case['encoded_13bit'] == encoded
            for off in (0x710, 0x714):
                assert int(case['registers'][hex(0x20380000+bank*0x40000+off)], 16) == (encoded<<16)|encoded
        if case['name'].startswith('calibration-flag'):
            assert case['returned_value'] == (0 if case['calibration_byte10'] else case['table_value'])
    special = next(c for c in result['cases'] if c['name'] == 'bank-1-mode-1-config-only')
    assert special['retained_raw_input'] == '0x60000000' and special['retained_raw_output'] == '0x62000000'
    table = next(c for c in result['cases'] if c['name'] == 'table-flag-skips-upload-config-only')
    assert table['table_byte_count'] == 64 and table['retained_words'] == [0x11220000+i for i in range(16)]

    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    curated = read(OUT/'curated-evidence.json')
    assert len(curated['ranges']) == 36 and curated['firmware_sha256'] == eg_sha
    for span in curated['ranges']:
        lo, hi = int(span['start'], 16), int(span['end'], 16)
        decoded = list(md.disasm(blob[lo-BASE:hi-BASE], lo))
        assert span['decoded_to_end'] and decoded[-1].address+decoded[-1].size == hi
        assert len(decoded) == len(span['instructions'])
        for ins, row in zip(decoded, span['instructions']):
            assert (hex(ins.address), ins.bytes.hex(), ins.mnemonic, ins.op_str) == (
                row['pc'], row['bytes'], row['mnemonic'], row['operands'])
            if 'literal_address' in row:
                assert u32(blob, int(row['literal_address'], 16)-BASE) == int(row['literal_value'], 16)

    scripts = [ROOT/'tools/fw'/name for name in ('qemu_raw_preprocess_probe.py', 'probe_raw_preprocess.py',
        'inspect_parameter_offsets.py', 'inspect_native.py', 'record_research_command.py', 'verify_raw_preprocess.py')]
    for path in scripts+list(OUT.rglob('probe-source.py')):
        ast.parse(path.read_text(encoding='utf-8'))
    docs = [ROOT/name for name in ('README.md', 'docs/NEXT_STEPS.md', 'docs/PROJECT_GOALS.md',
        'docs/RAW_TARGET_MAP_2026-11-03.md', 'docs/RAW_PREPROCESS_2026-11-03.md')]
    for path in docs:
        for link in re.findall(r'\]\(([^)]+)\)', path.read_text(encoding='utf-8')):
            if '://' not in link and not link.startswith('#'):
                target = (path.parent/link.split('#')[0]).resolve()
                assert target.exists() or target == OUT/'verification.json', (path, link)
    failures, pending = [], []
    for path in sorted((OUT/'commands').glob('*/command.json')):
        command = read(path)
        if 'exit_code' not in command:
            # This verification's recorder cannot have its exit code yet.
            assert any('verify_raw_preprocess.py' in x for x in command['argv'])
            pending.append(path.parent.name)
        elif command['exit_code'] != 0:
            failures.append(path.parent.name)
    assert failures == ['13-isolated-preprocess', '14-isolated-preprocess-v2'], failures
    source = ROOT/f'work/src/z6-qemu-{COMMIT}/qemu/nikon-z6.c'
    assert sha(source) == previous['qemu_source_sha256']
    # Snapshot integrity covers all raw evidence; the manifest and current
    # recorder are excluded to avoid self-referential hashes.
    evidence = [p for p in OUT.rglob('*') if p.is_file() and p.name != 'verification.json'
                and not any(q in p.parts for q in pending)]
    report = dict(ok=True, generated_at_utc=datetime.now(timezone.utc).isoformat(),
        firmware_hashes_unchanged=hashes, native_runs=metrics, isolated_case_count=20,
        curated_range_count=36, failed_probe_commands_preserved=failures,
        current_verification_record_pending=pending,
        recorded_qemu_binary_sha256=previous['recorded_qemu_binary_sha256'],
        qemu_source_sha256=previous['qemu_source_sha256'],
        scripts={p.relative_to(ROOT).as_posix(): sha(p) for p in scripts},
        docs={p.relative_to(ROOT).as_posix(): sha(p) for p in docs},
        evidence_sha256={p.relative_to(OUT).as_posix(): sha(p) for p in sorted(evidence)},
        scope='Original bytes, saved trace integrity, scalar arithmetic and register dataflow only. '
              'No verified dark-current preservation, RAW correction disable, NEF or ring removal.')
    (OUT/'verification.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps({k: report[k] for k in ('ok', 'isolated_case_count', 'curated_range_count',
                     'failed_probe_commands_preserved')}, indent=2))


if __name__ == '__main__':
    main()
