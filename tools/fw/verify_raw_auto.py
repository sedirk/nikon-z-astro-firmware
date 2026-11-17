"""Verify recorded automatic-parameter, cache and alternate-builder evidence."""
from pathlib import Path
from datetime import datetime, timezone
import ast
import json
import re
import struct
import capstone
from verify_raw_targets import read, sha, memory, reg

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'analysis/raw-auto-2026-11-03'
BASE = 0x10020000


def main():
    assert __debug__, 'Run without -O.'
    previous = read(ROOT / 'analysis/raw-targets-2026-11-03/verification.json')
    firmware = previous['firmware_hashes_unchanged']
    assert len(firmware) == 5
    for path, expected in firmware.items():
        assert sha(ROOT / path) == expected, path
    eg_sha = firmware['firmware/decoded/eg1620_038000.bi']
    blob = (ROOT / 'firmware/decoded/eg1620_038000.bi').read_bytes()
    isolated = read(OUT / 'isolated-auto/result.json')
    extended = read(OUT / 'isolated-with-alternate/result.json')
    assert isolated['polynomial_cases'] == extended['polynomial_cases']
    assert isolated['automatic_cases'] == extended['automatic_cases']
    for name, run in (('isolated-auto', isolated), ('isolated-with-alternate', extended)):
        assert run['ok'] and run['firmware_unchanged'] and run['firmware_sha256'] == eg_sha
        assert sha(OUT / name / 'probe-source.py') == run['probe_sha256']
        assert len(run['polynomial_cases']) == 16 and len(run['automatic_cases']) == 27
        for case in run['polynomial_cases']:
            assert case['output'] == case['expected'] and case['guard_unchanged']
        for case in run['automatic_cases']:
            assert len(case['parameter_calls']) == 2
            for call in case['parameter_calls']:
                assert call['cached'] == call['expected_cached'] and call['guard_unchanged']
                assert list(struct.unpack_from('<4H', bytes.fromhex(call['output']), 0x62)) == call['slots']
                assert ('0x1011308c' in call['blocks']) == (call['config_29c'] == 0)
    assert len(extended['alternate_cases']) == 12
    for case in extended['alternate_cases']:
        params = bytes.fromhex(case['parameters'])
        assert list(struct.unpack_from('<4H', params, 0x62)) == case['slots'] == [0x21, 0x12, 0x33, 0x44]
        assert case['cached_after'] == '0x13572468' and case['guard_unchanged']
        assert '0x101cb734' not in case['call']['blocks']
    runs, counts, maxima = {}, {}, {}
    for name, count, calls_count in (('native-auto', 60, 4), ('cache-reuse', 99, 18), ('auto-crosscheck', 98, 14)):
        run = runs[name] = read(OUT / name / 'result.json')
        events = read(OUT / name / 'events.json')
        assert run['ok'] and run['firmware_unchanged'] and run['firmware_sha256'] == eg_sha
        assert run['upstream_commit'] == '419a1f2a91a1f2d3a0209027c29606475f7fe26f'
        assert sha(OUT / name / 'probe-source.py') == run['probe_sha256']
        assert run['event_count'] == len(events) == count
        counts[name] = count
        calls = [c['result'] for c in run['calls']]
        assert len(calls) == calls_count
        assert [c['function'] for c in calls[:4]] == ['0x101efaa8', '0x101eedb4', '0x10170cca', '0x10170cca']
        assert calls[1]['payload'] == '0000010000000000000000000000000001000000000000000000000000000000'
        assert int(calls[1]['return_r0'], 16) == 0 and calls[3]['arguments'] == ['0x1388']
        maxima[name] = max(len(c['trace']) for c in calls)
        assert maxima[name] == 11
        for snapshot in ('baseline', 'final'):
            for area in run[snapshot].values():
                if 'bytes' in area:
                    memory(area)
            assert memory(run[snapshot]['mode_scale_bytes']) == bytes([1, 1, 1, 1, 1, 3, 1, 1, 1])
        for event in events:
            assert run['points'][hex(reg(event, 15))] == event['event']
            for area in event['memory'].values():
                if 'bytes' in area:
                    memory(area)
        native = [e for e in events if e['phase'] in ('synthetic-boot', 'native-without-card', 'native-settle')]
        assert all(int(e['automatic_result_before_mov'], 16) == 0 for e in native
                   if e['event'] == 'automatic_parameter_return')
        assert any(e['event'] == 'reused_parameters_entry' and e['phase'] == 'native-settle' for e in native)
        actions = [json.loads(s) for s in (OUT / name / 'session/actions.jsonl').read_text(encoding='utf-8').splitlines()]
        boots = [a for a in actions if a['kind'] == 'boot']
        assert len(boots) == 1
        boot = boots[0]
        assert not boot['camera_access'] and not boot['firmware_modified'] and boot['guest_state_modified']
        assert boot['build']['binary_sha256'] == previous['recorded_qemu_binary_sha256']
        assert boot['build']['sources']['qemu/nikon-z6.c'] == previous['qemu_source_sha256']
    cache = runs['cache-reuse']['cache_experiment']
    assert cache['explicit_restoration'] and len(cache['cases']) == 12
    keys = set()
    for case in cache['cases']:
        keys.add((case['config_29c'], case['cached_input'], case['selector']))
        expected = [0] * 4
        expected[case['selector']] = case['cached_input']
        params = bytes.fromhex(case['parameters'])
        assert list(struct.unpack_from('<4H', params, 0x62)) == expected == case['slots']
        assert params == bytes.fromhex(case['call']['output'])[0x40:0xec]
        assert case['cache_after'] == struct.pack('<I', case['cached_input']).hex()
        assert case['config_after'] == bytes([case['config_29c']]).hex() and case['guards_unchanged']
    assert len(keys) == 12
    assert cache['cache_after_refresh'] == '00000000'
    assert cache['refresh_call']['function'] == '0x10114136'
    assert cache['refresh_call']['arguments'][:3] == ['0x0', '0x0', '0x0']
    assert bytes.fromhex(cache['reuse_after_refresh']['output'])[0xa2:0xaa] == bytes(8)
    cross = runs['auto-crosscheck']['auto_crosscheck']
    assert cross['explicit_restoration'] and cross['expected_report_sha256'] == sha(OUT / 'isolated-auto/result.json')
    assert len(cross['polynomial_cases']) == 4 and len(cross['automatic_cases']) == 6
    for case in cross['polynomial_cases']:
        assert case['expected'] in isolated['polynomial_cases']
        assert case['actual'] == case['expected']['output']
        assert struct.unpack_from('<i', bytes.fromhex(case['call']['output']), 0x20)[0] == case['actual']
    for case in cross['automatic_cases']:
        assert case['expected'] in isolated['automatic_cases']
        assert case['actual'] == case['expected']['automatic_call']['returned_signed']
        assert struct.unpack('<i', struct.pack('<I', int(case['call']['return_r0'], 16)))[0] == case['actual']

    metadata = read(OUT / 'static-property-map.json')
    for row in metadata['startup_values'].values():
        raw = bytes.fromhex(row['bytes'])
        address = int(row['rom'], 16)
        assert blob[address - BASE:address - BASE + len(raw)] == raw
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    md.detail = True
    for row in metadata['property_getters']:
        offset = struct.unpack_from('<I', blob, int(row['table_entry'], 16) - BASE)[0]
        assert hex(offset) == row['relative_offset'] and hex(0x1015c388 + offset) == row['case_target']
        address = int(row['case_target'], 16)
        assert blob[address - BASE:address - BASE + 8].hex() == row['case_bytes']
        calls = [i for i in md.disasm(bytes.fromhex(row['case_bytes']), address) if i.mnemonic == 'bl']
        assert len(calls) == 1 and hex(calls[0].operands[0].imm) == row['getter']
    ins = next(md.disasm(blob[0x100a0ea0 - BASE:0x100a0ea2 - BASE], 0x100a0ea0))
    assert ins.mnemonic == 'adr' and ((ins.address + 4) & ~3) + ins.operands[1].imm == 0x100a0fbc
    assert blob[0x100a0fbc - BASE:0x100a0fbc - BASE + 16] == b'A:\\PdAf%03d.bin\x00'
    curated = read(OUT / 'curated-evidence.json')
    assert len(curated['ranges']) == 32
    for span in curated['ranges']:
        lo, hi = int(span['start'], 16), int(span['end'], 16)
        decoded = list(md.disasm(blob[lo - BASE:hi - BASE], lo))
        assert span['decoded_to_end'] and decoded[-1].address + decoded[-1].size == hi
        assert len(decoded) == len(span['instructions'])
        for ins, row in zip(decoded, span['instructions']):
            assert (hex(ins.address), ins.bytes.hex(), ins.mnemonic, ins.op_str) == (row['pc'], row['bytes'], row['mnemonic'], row['operands'])
    scripts = [ROOT / 'tools/fw' / n for n in ('qemu_raw_auto_probe.py', 'probe_raw_auto.py',
               'inspect_raw_auto_metadata.py', 'verify_raw_auto.py', 'record_research_command.py',
               'inspect_native.py', 'verify_raw_targets.py')]
    for script in scripts + list(OUT.rglob('probe-source.py')):
        ast.parse(script.read_text(encoding='utf-8'))
    docs = [ROOT / n for n in ('README.md', 'docs/PROJECT_GOALS.md', 'docs/NEXT_STEPS.md',
            'docs/RAW_TARGET_MAP_2026-11-03.md', 'docs/RAW_AUTO_PARAMETERS_2026-11-03.md')]
    for doc in docs:
        for link in re.findall(r'\]\(([^)]+)\)', doc.read_text(encoding='utf-8')):
            if '://' not in link and not link.startswith('#'):
                target = (doc.parent / link.split('#')[0]).resolve()
                assert target.exists() or target == OUT / 'verification.json', (doc, link)
    pending = []
    for path in (OUT / 'commands').glob('*/command.json'):
        record = read(path)
        if 'exit_code' not in record:
            pending.append(path.parent)
        else:
            assert record['exit_code'] == 0, path
            assert record['recorder_sha256'] == sha(ROOT / 'tools/fw/record_research_command.py')
    files = sorted(p for p in OUT.rglob('*') if p.is_file() and p != OUT / 'verification.json'
                   and not any(d in p.parents for d in pending)) + scripts + docs
    result = dict(ok=True, generated_at_utc=datetime.now(timezone.utc).isoformat(),
        firmware_hashes_unchanged=firmware, event_counts=counts, max_postboot_trace_per_call=maxima,
        polynomial_cases=16, automatic_input_combinations=27, automatic_gate_calls=54,
        alternate_builder_cases=12, qemu_cache_cases=12, qemu_arithmetic_crosschecks=10,
        cache_refresh_reuse_checked=True, curated_ranges=32, property_routes=5,
        nef_generated=None, physical_pixel_effect_verified=False, dark_current_preserved=False,
        all_raw_corrections_disabled=False, rings_removed=False,
        scope='Native arithmetic, property sources and parameter dependencies in synthetic RAM; no physical pixel validation.',
        qemu_source_sha256=previous['qemu_source_sha256'],
        recorded_qemu_binary_sha256=previous['recorded_qemu_binary_sha256'],
        unfinished_command_records_excluded=[p.relative_to(ROOT).as_posix() for p in pending],
        evidence=[dict(file=p.relative_to(ROOT).as_posix(), bytes=p.stat().st_size, sha256=sha(p)) for p in files])
    (OUT / 'verification.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps({k: result[k] for k in ('ok', 'event_counts', 'polynomial_cases', 'automatic_input_combinations',
         'alternate_builder_cases', 'qemu_cache_cases', 'qemu_arithmetic_crosschecks', 'physical_pixel_effect_verified')}, indent=2))
    print(f'Hashed {len(files)} files. All five original firmware hashes unchanged.')


if __name__ == '__main__':
    main()
