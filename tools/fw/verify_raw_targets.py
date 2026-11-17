"""Recheck saved RAW-parameter evidence, without claiming physical pixel effects."""
from pathlib import Path
from datetime import datetime, timezone
import ast
import hashlib
import json
import re
import struct
import capstone

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'analysis/raw-targets-2026-11-03'
BASE = 0x10020000
COMMIT = '419a1f2a91a1f2d3a0209027c29606475f7fe26f'


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def memory(row):
    data = bytes.fromhex(row['bytes'])
    assert len(data) == row['size']
    assert hashlib.sha256(data).hexdigest() == row['sha256']
    return data


def reg(row, n):
    return int(row['registers'][f'r{n}'], 16)


def only(rows, name):
    found = [r for r in rows if r['event'] == name]
    assert len(found) == 1, (name, len(found))
    return found[0]


def main():
    assert __debug__, 'Run without -O.'
    previous = read(ROOT / 'analysis/source-trigger-2026-11-03/verification.json')
    firmware = previous['firmware_hashes_unchanged']
    assert len(firmware) == 5
    for path, expected in firmware.items():
        assert sha(ROOT / path) == expected, path
    blob = (ROOT / 'firmware/decoded/eg1620_038000.bi').read_bytes()
    eg_sha = firmware['firmware/decoded/eg1620_038000.bi']
    assert eg_sha == '1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
    runs, events, caps, maxima = {}, {}, {}, {}
    for name, expected_count in (('native-trace', 58), ('register-trace', 429)):
        run = runs[name] = read(OUT / name / 'result.json')
        rows = events[name] = read(OUT / name / 'events.json')
        assert run['ok'] and run['firmware_unchanged']
        assert run['firmware_sha256'] == eg_sha and run['upstream_commit'] == COMMIT
        assert run['event_count'] == len(rows) == expected_count
        assert sha(OUT / name / 'probe-source.py') == run['probe_sha256']
        calls = [c['result'] for c in run['calls']]
        assert [c['function'] for c in calls] == ['0x101efaa8', '0x101eedb4', '0x10170cca', '0x10170cca']
        assert calls[0]['arguments'] == ['0x1']
        assert calls[1]['payload'] == '0000010000000000000000000000000001000000000000000000000000000000'
        assert int(calls[1]['return_r0'], 16) == 0
        assert calls[2]['arguments'] == ['0x64'] and calls[3]['arguments'] == ['0x1388']
        assert all(c['kind'] == 'synthetic diagnostic input; not a controller protocol model' for c in calls)
        maxima[name] = max(len(c['trace']) for c in calls)
        assert maxima[name] < 256
        actions = [json.loads(s) for s in (OUT / name / 'session/actions.jsonl').read_text(encoding='utf-8').splitlines()]
        boots = [a for a in actions if a['kind'] == 'boot']
        assert len(boots) == 1
        boot = boots[0]
        assert not boot['firmware_modified'] and not boot['camera_access'] and boot['guest_state_modified']
        assert boot['firmware_sha256'] == eg_sha
        assert boot['build']['binary_sha256'] == previous['recorded_qemu_binary_sha256']
        assert boot['build']['sources']['qemu/nikon-z6.c'] == previous['qemu_source_sha256']
        caps[name] = [a['result']['function'] for a in actions
                      if a['kind'] == 'original_firmware_call' and len(a['result']['trace']) >= 256]
        for snap in ('baseline', 'final'):
            state = run[snap]
            for row in state.values():
                if 'bytes' in row:
                    memory(row)
            context, directory = memory(state['parameter_context']), memory(state['data_directory'])
            # Only established IDs are read; the captured directory tail is not interpreted.
            for off, index, delta in ((0x30, 0x25, 0), (0x34, 0x25, 0x400),
                                      (0x38, 0x25, 0x800), (0x3c, 0xc, 0), (0x40, 0x31, 0)):
                entry = struct.unpack_from('<7I', directory, index * 28)
                pointer = struct.unpack_from('<I', context, off)[0]
                assert entry[0] == index and pointer == entry[2] + delta
                sample = state[f'parameter_pointer_{off:x}']
                assert int(sample['address'], 16) == pointer
                assert memory(sample) == bytes(0x300)  # A prefix, NOT the complete resource.
            assert memory(state['config_290_29f'])[0xe] == 1  # retained upstream 0x29e fixture
        for row in rows:
            assert hex(reg(row, 15)) in run['points']
            assert run['points'][hex(reg(row, 15))] == row['event']
            for area in row['memory'].values():
                if 'bytes' in area:
                    memory(area)
    assert caps == {'native-trace': [], 'register-trace': ['0x10170cca']}
    assert maxima == {'native-trace': 10, 'register-trace': 19}

    still = [e for e in events['register-trace'] if e['phase'] == 'native-settle']
    chain = [only(still, n) for n in ('still_lower_submit', 'reused_parameters_wrapper',
             'reused_parameters_entry', 'reused_parameters_return', 'parameter_field_mapper',
             'parameter_field_mapper_return')]
    assert [still.index(e) for e in chain] == sorted(still.index(e) for e in chain)
    wrapper, entry, returned, mapper, mapped = chain[1:]
    assert reg(wrapper, 14) == 0x10076bcb and reg(entry, 14) == 0x100a20a1
    assert reg(mapper, 14) == 0x10076b15 and reg(mapper, 0) == 0
    assert reg(wrapper, 0) == reg(entry, 0) == 0xc252bf4c
    assert memory(wrapper['memory']['reuse_input']) == memory(entry['memory']['reuse_input'])
    assert reg(wrapper, 1) == reg(entry, 1) == reg(returned, 4) == reg(mapper, 1) == 0xc2528b04
    params = memory(returned['memory']['parameters'])
    assert params == memory(mapper['memory']['mapper_input'])
    assert struct.unpack_from('<3I', params, 0x20) == (0x80660000, 0x80669720, 0x80672e40)
    packed = memory(mapped['memory']['mapped_parameters'])
    for src, dst in ((0x60, 0x88), (0x62, 0x8a), (0x64, 0x8c), (0x66, 0x8e), (0x68, 0x94)):
        assert params[src:src + 2] == packed[dst:dst + 2]
    assert not any(e['event'] == 'signed_pair_register_write' for e in still)
    writes = [e['mmio_write'] for e in events['register-trace'] if e['event'] == 'signed_pair_register_write']
    assert {int(w['address'], 16) for w in writes} == {0x2006b388, 0x2006b38c, 0x2006b390}
    assert all(int(w['value'], 16) == 0 for w in writes)

    isolated = {}
    for name, ok, counts in (('isolated-parameters', False, (9, 0, 0)),
                            ('isolated-parameters-v2', True, (144, 30, 0)),
                            ('isolated-register-chain', True, (144, 30, 32))):
        run = isolated[name] = read(OUT / name / 'result.json')
        assert run['ok'] == ok and run['firmware_unchanged'] and run['firmware_sha256'] == eg_sha
        assert sha(OUT / name / 'probe-source.py') == run['probe_sha256']
        assert tuple(len(run.get(k, [])) for k in ('signed_cases', 'table_cases', 'register_cases')) == counts
        for case in run['signed_cases']:
            output = bytes.fromhex(case['output'])
            assert len(output) == 0xac and hashlib.sha256(output).hexdigest() == case['output_sha256']
            assert case['unchanged_elsewhere_and_guards']
            slots = list(struct.unpack_from('<4H', output, 0x62))
            expected = [0] * 4
            if case['output_slot'] is not None:
                expected[case['output_slot']] = case['encoded_value']
            assert slots == expected
        # Derive table strides independently from the original descriptor bytes.
        for case in run['table_cases']:
            group = {0: 0, 1: 6, 2: 6, 3: 6, 4: 2, 5: 4, 6: 1, 7: 3, 8: 3, 9: 6}[case['mode']]
            _, blocks, _, _, stride, offset = struct.unpack_from('<4B2I', blob, 0x11f66eb0 - BASE + 12 * group)
            offsets = [4 * (offset + stride * i) for i in range(3)]
            assert case['selected_offsets'] == list(map(hex, offsets))
            output = bytes.fromhex(case['output'])
            assert struct.unpack_from('<3I', output, 0x20) == tuple(int(case['table_base'], 16) + n for n in offsets)
            assert output[0x2c:0x2e] == bytes([blocks, case['selector']])
        for case in run.get('register_cases', []):
            assert [c['entry'] for c in case['calls']] == ['0x10114136', '0x100bed06', '0x100d8582']
            assert case['output_guard_unchanged']
            p, m = bytes.fromhex(case['parameters']), bytes.fromhex(case['mapped_parameters'])
            for src, dst in ((0x60, 0x88), (0x62, 0x8a), (0x64, 0x8c), (0x66, 0x8e), (0x68, 0x94)):
                assert p[src:src + 2] == m[dst:dst + 2]
            assert m[0x90:0x94] == bytes(4)
            v, a, b, c, d = struct.unpack_from('<5H', p, 0x60)
            expected = dict(zip(('0x2006b384', '0x2006b388', '0x2006b38c', '0x2006b390'), (v, a | (b << 16), c, d << 16)))
            assert {k: int(v, 16) for k, v in case['registers'].items()} == expected
    assert isolated['isolated-parameters-v2']['signed_cases'] == isolated['isolated-register-chain']['signed_cases']
    assert 'AssertionError' in (OUT / 'commands/10-isolated-parameters/stderr.txt').read_text(encoding='utf-8')
    assert all(c['encoded_value'] == 1023 for c in isolated['isolated-register-chain']['signed_cases']
               if c['input_114'] == 64 and c['config_29c'] == 0)

    curated = read(OUT / 'curated-evidence.json')
    assert curated['firmware_sha256'] == eg_sha and len(curated['ranges']) == 22
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    for span in curated['ranges']:
        lo, hi = int(span['start'], 16), int(span['end'], 16)
        decoded = list(md.disasm(blob[lo - BASE:hi - BASE], lo))
        assert span['decoded_to_end'] and decoded[-1].address + decoded[-1].size == hi
        assert len(decoded) == len(span['instructions'])
        for ins, row in zip(decoded, span['instructions']):
            assert (hex(ins.address), ins.bytes.hex(), ins.mnemonic, ins.op_str) == (row['pc'], row['bytes'], row['mnemonic'], row['operands'])
            if 'literal_address' in row:
                assert struct.unpack_from('<I', blob, int(row['literal_address'], 16) - BASE)[0] == int(row['literal_value'], 16)

    scripts = [ROOT / 'tools/fw' / n for n in ('probe_raw_parameters.py', 'qemu_raw_target_probe.py',
               'record_research_command.py', 'inspect_native.py', 'verify_raw_targets.py')]
    for script in scripts + list(OUT.rglob('probe-source.py')):
        ast.parse(script.read_text(encoding='utf-8'))
    docs = [ROOT / n for n in ('README.md', 'docs/PROJECT_GOALS.md', 'docs/NEXT_STEPS.md', 'docs/RAW_TARGET_MAP_2026-11-03.md')]
    for doc in docs:
        for link in re.findall(r'\]\(([^)]+)\)', doc.read_text(encoding='utf-8')):
            if '://' not in link and not link.startswith('#'):
                target = (doc.parent / link.split('#')[0]).resolve()
                assert target.exists() or target == OUT / 'verification.json', (doc, link)
    source = ROOT / f'work/src/z6-qemu-{COMMIT}/qemu/nikon-z6.c'
    assert sha(source) == previous['qemu_source_sha256']
    pending = []
    for record in sorted((OUT / 'commands').glob('*/command.json')):
        cmd = read(record)
        if 'exit_code' not in cmd:
            pending.append(record.parent)
            continue
        assert cmd['exit_code'] == (1 if record.parent.name == '10-isolated-parameters' else 0), record
        assert cmd['recorder_sha256'] == sha(ROOT / 'tools/fw/record_research_command.py')
    files = sorted(p for p in OUT.rglob('*') if p.is_file() and p != OUT / 'verification.json'
                   and not any(parent in p.parents for parent in pending)) + scripts + docs
    report = dict(ok=True, generated_at_utc=datetime.now(timezone.utc).isoformat(),
        firmware_hashes_unchanged=firmware, saved_native_runs=2,
        event_counts={k: len(v) for k, v in events.items()}, max_postboot_trace_per_call=maxima,
        capped_boot_calls=caps, distinct_passing_isolated_cases=206, preserved_failed_cases=9,
        curated_instruction_ranges=22, still_parameter_reuse_observed=True,
        still_final_register_submission_observed=False, physical_parameter_meaning_verified=False,
        dark_current_preservation_verified=False, raw_corrections_disabled_verified=False,
        rings_removed_verified=False, nef_generated=None,
        qemu_source_sha256=sha(source), recorded_qemu_binary_sha256=previous['recorded_qemu_binary_sha256'],
        scope='Saved native code, synthetic memory, and parameter/register packing evidence only; no physical pixel validation.',
        metadata_errata=['register-trace scope omitted the repeated 1010b958 breakpoint; boot reached 256-entry cap.',
                         'isolated-register-chain scope says no MMIO; its assumptions and source declare inert MMIO RAM.'],
        unfinished_command_records_excluded=[p.relative_to(ROOT).as_posix() for p in pending],
        evidence=[dict(file=p.relative_to(ROOT).as_posix(), bytes=p.stat().st_size, sha256=sha(p)) for p in files])
    (OUT / 'verification.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps({k: report[k] for k in ('ok', 'event_counts', 'distinct_passing_isolated_cases',
                      'curated_instruction_ranges', 'capped_boot_calls', 'physical_parameter_meaning_verified')}, indent=2))
    print(f'Hashed {len(files)} evidence files; all five original firmware hashes unchanged.')


if __name__ == '__main__':
    main()
