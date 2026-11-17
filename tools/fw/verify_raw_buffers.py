"""Recheck saved native buffer routes; does not validate physical RAW effects."""
from pathlib import Path
from datetime import datetime, timezone
import ast
import hashlib
import json
import re
import struct
import capstone

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'analysis/raw-buffers-2026-11-03'
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


def u32(data, off=0):
    return struct.unpack_from('<I', data, off)[0]


def u16(data, off=0):
    return struct.unpack_from('<H', data, off)[0]


def reg(row, n):
    return int(row['registers'][f'r{n}'], 16)


def main():
    assert __debug__, 'Run without -O.'
    (OUT / 'verification-source.py').write_bytes(Path(__file__).read_bytes())
    previous = read(ROOT / 'analysis/raw-auto-2026-11-03/verification.json')
    hashes = previous['firmware_hashes_unchanged']
    assert len(hashes) == 5
    for name, digest in hashes.items():
        assert sha(ROOT / name) == digest, name
    blob = (ROOT / 'firmware/decoded/eg1620_038000.bi').read_bytes()
    eg_sha = hashes['firmware/decoded/eg1620_038000.bi']
    runs, events, caps, maxima, af_counts, af_routes = {}, {}, {}, {}, {}, {}
    for name, count in (('native-buffers', 40), ('native-pdaf', 53), ('native-main-raw', 60)):
        run = runs[name] = read(OUT / name / 'result.json')
        rows = events[name] = read(OUT / name / 'events.json')
        assert run['ok'] and run['firmware_unchanged']
        assert run['firmware_sha256'] == eg_sha and run['upstream_commit'] == COMMIT
        assert run['event_count'] == len(rows) == count
        assert sha(OUT / name / 'probe-source.py') == run['probe_sha256']
        calls = [c['result'] for c in run['calls']]
        assert [c['function'] for c in calls] == ['0x101efaa8', '0x101eedb4', '0x10170cca', '0x10170cca']
        assert calls[0]['arguments'] == ['0x1']
        assert calls[1]['payload'] == '0000010000000000000000000000000001000000000000000000000000000000'
        assert int(calls[1]['return_r0'], 16) == 0
        assert calls[2]['arguments'] == ['0x64'] and calls[3]['arguments'] == ['0x1388']
        maxima[name] = max(len(c['trace']) for c in calls)
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
        assert not caps[name]
        for stage in ('baseline', 'final'):
            for area in run[stage].values():
                if 'bytes' in area:
                    memory(area)
            if name != 'native-buffers':
                assert struct.unpack('<2I', memory(run[stage]['task_metadata_bases'])) == (0xc18fd93c, 0xc18fe870)
        publications = []
        routes = set()
        for row in rows:
            assert run['points'][hex(reg(row, 15))] == row['event']
            areas = row['memory']
            for area in areas.values():
                if 'bytes' in area:
                    memory(area)
            if row['event'] == 'buffer_builder_ready':
                params = memory(areas['buffer_parameters'])
                for offset, field in ((0xc8, 0x20), (0xcc, 0x2c)):
                    handle, vector = areas[f'handle_{offset:x}'], areas[f'vector_{offset:x}']
                    assert u32(params, offset) == int(handle['address'], 16)
                    assert u32(memory(handle), 4) == int(vector['address'], 16)
                    assert u32(memory(vector)) == u32(params, field)
            if row['event'] == 'af_record_payload_copied':
                frame = memory(areas['frame'])
                record = memory(areas['published_af_record'])
                handle = areas['frame_payload_7c']
                assert int(handle['address'], 16) == u32(frame, 0x7c)
                assert record[0xc0:0x130] == memory(handle)
                pointer = u32(record, 0x12c)
                assert pointer == u32(memory(handle), 0x6c)
                idx, remainder = divmod(int(areas['published_af_record']['address'], 16) - 0xc2152370, 0xc30)
                assert remainder == 0 and 0 <= idx < 8
                publications.append(pointer)
                routes.add((handle['address'], hex(pointer)))
            if 'mmio_write' in row:
                mmio = row['mmio_write']
                assert int(mmio['value'], 16) == reg(row, 2)
                offset = {0x1010ba0a: 0x3e8, 0x1010ba1c: 0x3f4,
                          0x1010b9ca: 0x3c8, 0x1010b9d0: 0x3c4}[reg(row, 15)]
                assert int(mmio['address'], 16) == reg(row, 0) + offset
        af_counts[name] = len(publications)
        af_routes[name] = sorted(routes)
        if name != 'native-buffers':
            bank_rows = [r for r in rows if r['event'] in ('pdaf_bank_0_address_write', 'pdaf_bank_1_address_write')]
            assert bank_rows
            assert {reg(r, 2) for r in bank_rows} <= set(publications)

    # Only the third run follows the still object's distinct layout and adds
    # breakpoints at later processing/encoding stages. No absence claim for V1/2.
    run = runs['native-main-raw']
    still = [r for r in events['native-main-raw'] if r['event'] == 'still_lower_submit']
    assert len(still) == 1
    areas = still[0]['memory']
    obj = memory(areas['still_capture_object'])
    handle = areas['still_handle_1f8']
    assert u32(obj, 0x1f8) == int(handle['address'], 16)
    assert all(u32(obj, off) == 0 for off in (0x1fc, 0x318, 0x330))
    assert memory(handle) == memory(run['final']['still_handle_1f8'])
    desc = memory(handle)[0x24:0x44]
    observed_descriptor = dict(format_id=desc[0], byte_stride=u16(desc, 2), width=u16(desc, 8),
                               height=u16(desc, 10), crop_x=u16(desc, 12), crop_y=u16(desc, 14),
                               pixel_address=hex(u32(desc, 16)))
    assert observed_descriptor == dict(format_id=2, byte_stride=9168, width=6104, height=4222,
                                       crop_x=0, crop_y=0, pixel_address='0xa448e000')
    stage_names = ('main_raw_processing_entry', 'main_raw_output_stage', 'raw_io_descriptor_builder',
                   'raw_io_queue_submit', 'raw_io_field_mapper', 'raw_io_register_packer')
    assert set(stage_names) <= set(run['points'].values())
    assert not set(stage_names) & {r['event'] for r in events['native-main-raw']}

    anchors = read(OUT / 'task-anchors.json')['task_anchors']
    for name, row in anchors.items():
        rom, ram = int(row['rom'], 16), int(row['ram'], 16)
        src, dst, size, handler = struct.unpack_from('<4I', blob, int(row['scatter_record'], 16))
        assert handler == 0x1002006c and src <= rom < src + size and ram == dst + rom - src
        data = bytes.fromhex(row['descriptor_bytes'])
        assert data == blob[rom-BASE-0x10:rom-BASE+0xc]
        assert data[0x10:].split(b'\0')[0].decode('ascii') == name
        table = int(row['table_base'], 16)
        ident = int(row['metadata_id'], 16) - (0x10000 if table == 0xc18fe870 else 0)
        assert table + 0x1c * ident == ram - 0x10 == int(row['descriptor_address'], 16)

    iso = read(OUT / 'isolated-raw-io/result.json')
    assert iso['ok'] and iso['firmware_unchanged'] and iso['firmware_sha256'] == eg_sha
    assert sha(OUT / 'isolated-raw-io/probe-source.py') == iso['probe_sha256']
    assert len(iso['cases']) == 6
    for case in iso['cases']:
        fmt, mode = case['format_id'], case['output_mode_id']
        inp, out = bytes.fromhex(case['input_descriptor']), bytes.fromhex(case['output_descriptor'])
        packet, mapped = bytes.fromhex(case['prepared_packet']), bytes.fromhex(case['mapped_packet'])
        registers = bytes.fromhex(case['register_image'])
        assert hashlib.sha256(registers).hexdigest() == case['register_sha256']
        n, d = {2: (3, 2), 3: (2, 1), 4: (7, 4)}[fmt]
        source = u32(inp, 0x10) + u16(inp, 0xe) * u16(inp, 2) + u16(inp, 0xc) * n // d
        stride = (u16(out, 2) * n // d + 15) & 0xfff0
        assert source == u32(packet, 0x40) == u32(mapped, 0x38) == u32(registers, 0x400)
        assert u32(out, 8) == u32(packet, 0x48) == u32(mapped, 0x40) == u32(registers, 0x420)
        assert u16(inp, 2) == u16(packet, 0x44) == u16(mapped, 0x3c) == u32(registers, 0x404)
        assert stride == u16(packet, 0x4c) == u16(mapped, 0x44) == u32(registers, 0x424)
        assert u16(out, 2) == u32(packet, 4) == u16(mapped, 6) == u32(registers, 0x4c)
        assert u16(out, 4) == u32(packet, 8) == u16(mapped, 8) == u32(registers, 0x50)
        assert [c['entry'] for c in case['calls']] == ['0x100a323e', '0x101ca6c6', '0x10108f8a']
        assert case['calls'][0]['stopped_at'] == '0x101caad8'
        assert case['calls'][0]['r0'] == '0xc23234c8'
        assert all(c['stopped_at'] == '0x53000000' for c in case['calls'][1:])
        table = u32(mapped, 0xc)
        assert table == (0 if mode == 1 else 0x1152ad70 if fmt == 2 else 0x1152af70)
        if table:
            values = struct.unpack_from('<256H', blob, table-BASE)
            expected = [(values[i] & 0x3fff) | ((values[i+1] & 0x3fff) << 16) for i in range(0, 256, 2)]
            assert list(struct.unpack_from('<128I', registers, 0x200)) == expected
            assert case['table_word_count'] == 128
        else:
            assert registers[0x200:0x400] == bytes(0x200) and case['table_word_count'] == 0

    curated = read(OUT / 'curated-evidence-v2.json')
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    assert len(curated['ranges']) == 26 and curated['firmware_sha256'] == eg_sha
    for span in curated['ranges']:
        lo, hi = int(span['start'], 16), int(span['end'], 16)
        decoded = list(md.disasm(blob[lo-BASE:hi-BASE], lo))
        assert span['decoded_to_end'] and decoded[-1].address + decoded[-1].size == hi
        assert len(decoded) == len(span['instructions'])
        for ins, row in zip(decoded, span['instructions']):
            assert (hex(ins.address), ins.bytes.hex(), ins.mnemonic, ins.op_str) == (row['pc'], row['bytes'], row['mnemonic'], row['operands'])
            if 'literal_address' in row:
                assert u32(blob, int(row['literal_address'], 16)-BASE) == int(row['literal_value'], 16)
    assert blob[0x100a0fbc-BASE:0x100a0fbc-BASE+16] == b'A:\\PdAf%03d.bin\0'
    assert u32(blob, 0x100a0fb8-BASE) == 0x22cc00
    source = ROOT / f'work/src/z6-qemu-{COMMIT}/qemu/nikon-z6.c'
    assert sha(source) == previous['qemu_source_sha256']
    scripts = [ROOT / 'tools/fw' / n for n in ('qemu_raw_buffer_probe.py', 'probe_raw_io.py',
                'inspect_raw_buffer_clues.py', 'inspect_raw_buffer_stores.py', 'verify_raw_buffers.py',
                'inspect_native.py', 'record_research_command.py')]
    for script in scripts + list(OUT.rglob('probe-source.py')):
        ast.parse(script.read_text(encoding='utf-8'))
    docs = [ROOT / n for n in ('README.md', 'docs/NEXT_STEPS.md', 'docs/PROJECT_GOALS.md',
                               'docs/RAW_TARGET_MAP_2026-11-03.md', 'docs/RAW_BUFFER_ROUTES_2026-11-03.md')]
    for doc in docs:
        for link in re.findall(r'\]\(([^)]+)\)', doc.read_text(encoding='utf-8')):
            if '://' not in link and not link.startswith('#'):
                target = (doc.parent / link.split('#')[0]).resolve()
                assert target.exists() or target == OUT / 'verification.json', (doc, link)
    pending = []
    failures = {'01-buffer-entry': 2, '15-task-anchors': 1, '35-verify': 1}
    for record in sorted((OUT / 'commands').glob('*/command.json')):
        cmd = read(record)
        if 'exit_code' not in cmd:
            pending.append(record.parent)
            continue
        assert cmd['exit_code'] == failures.get(record.parent.name, 0), record
        assert cmd['recorder_sha256'] == sha(ROOT / 'tools/fw/record_research_command.py')
    files = sorted(p for p in OUT.rglob('*') if p.is_file() and p != OUT / 'verification.json'
                   and not any(parent in p.parents for parent in pending)) + scripts + docs
    report = dict(ok=True, generated_at_utc=datetime.now(timezone.utc).isoformat(),
        firmware_hashes_unchanged=hashes, event_counts={n: len(e) for n, e in events.items()},
        max_postboot_trace_per_call=maxima, capped_boot_calls=caps, af_payload_copy_counts=af_counts,
        af_handle_to_buffer=af_routes, main_raw_descriptor_observed=observed_descriptor,
        raw_stage_breakpoints_not_hit_in_third_window=list(stage_names),
        isolated_descriptor_register_cases=6, curated_ranges=26, task_anchors=anchors,
        nef_generated=None, physical_pixel_effect_verified=False, dark_current_preserved=False,
        all_raw_corrections_disabled=False, rings_removed=False,
        qemu_source_sha256=sha(source), recorded_qemu_binary_sha256=previous['recorded_qemu_binary_sha256'],
        scope=__doc__, metadata_errata=[
            'native-buffers called a still capture object frame and read +78/+7c using a different layout; those readings are excluded from still buffer conclusions.',
            'curated-evidence-v2 trims one literal-pool halfword and extends the start-register range; v1 is retained.'],
        unfinished_command_records_excluded=[p.relative_to(ROOT).as_posix() for p in pending],
        evidence=[dict(file=p.relative_to(ROOT).as_posix(), bytes=p.stat().st_size, sha256=sha(p)) for p in files])
    (OUT / 'verification.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps({k: report[k] for k in ('ok', 'event_counts', 'af_payload_copy_counts',
                     'main_raw_descriptor_observed', 'isolated_descriptor_register_cases', 'curated_ranges')}, indent=2))
    print(f'Hashed {len(files)} evidence files; all five original firmware hashes unchanged.')


if __name__ == '__main__':
    main()
