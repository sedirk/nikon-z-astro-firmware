"""Native exact-candidate update/rollback checks using RAM-only flash adapters."""
from pathlib import Path
import argparse, gc, json, traceback
import probe_eg_update_route as eg
from probe_preflash_review import AuditRig, schedule
from probe_raw_candidates import ROOT, sha

ROUND = ROOT / 'analysis/raw-spatial-controls-2026-11-12'
FILES = {
    'stock': ('firmware/decoded/eg1620_038000.bi', '1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'),
    'modified1': ('outputs/Z6-C380-preflash-reviewed-2026-11-09/01_TEST/EG162080.BIN', 'eeded80d4009204ba9760b6e20436aea3f6a37ce4ed6331ca662b839164a8875'),
    'modified4': ('outputs/Z6-C380-front-bit11-reviewed-2026-11-09/01_TEST_MODIFIED4/EG162080.BIN', 'bdf30026dc9d18b09a5ca9332369d126729d63a36013e94b8b20cf6638a4ef1b'),
    'test': ('analysis/raw-spatial-controls-2026-11-12/static-cal33-lab/modified4-static-cal33-control1a-zero-lab.bi', '0b4ebdd106da2ebf0100063bf604898b15dacdb175ccb7ee7d759610a3e32945')
}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', required=True, type=Path)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    blobs = {n: (ROOT / f).read_bytes() for n, (f, h) in FILES.items()}
    for n, (_, h) in FILES.items():
        assert sha(blobs[n]) == h
    for n in (Path(__file__).name, 'probe_eg_update_route.py', 'probe_preflash_review.py'):
        (a.output / n).write_bytes((ROOT / 'tools/fw' / n).read_bytes())
    report = dict(ok=False, scope=__doc__, file_checks=[], scheduler=[], physical_flash=False,
        model='OS/file and low-level flash adapters; native validation and scheduler code.')
    try:
        for rom, target in (
            ('modified4', 'test'), ('stock', 'test'), ('test', 'modified4'), ('test', 'modified1'), ('test', 'stock')
        ):
            label = rom + '_to_' + target
            rig = AuditRig(blobs[rom])
            row = eg.run(rig, label, blobs[target], 'EG162080.BIN')
            assert row['discovery_return'] == row['integrity_return'] == row['component_precheck_return'] == 0
            assert row['loaded_buffer_sha256'] == FILES[target][1]
            report['file_checks'].append(dict(running_rom=rom, target=target, **row))
            print(label, flush=True)
            del rig
            gc.collect()
        bad = bytearray(blobs['test'])
        bad[0x15d7fa] ^= 1
        for label, data, name, size in (
            ('bad_crc', bytes(bad), 'EG162080.BIN', None),
            ('wrong_model', blobs['test'], 'EG172080.BIN', None),
            ('oversize', blobs['test'], 'EG162080.BIN', 0x2940001)
        ):
            rig = AuditRig(blobs['modified4'])
            row = eg.run(rig, label, data, name, reported_size=size)
            if label == 'bad_crc':
                assert row['discovery_return'] == 0 and row['integrity_return'] == 3
            else:
                assert row['discovery_return'] != 0
            report['file_checks'].append(dict(expected_rejection=True, **row))
            del rig
            gc.collect()
        for rom, target, failure in (
            ('modified4', 'test', None), ('test', 'modified4', None), ('test', 'stock', None),
            ('modified4', 'test', 'erase'), ('test', 'modified4', 'readback')
        ):
            rig = AuditRig(blobs[rom])
            row = schedule(rig, rom + '_to_' + target, blobs[target], failure)
            report['scheduler'].append(row)
            print(json.dumps(dict(stage='scheduler', label=row['label'], failure=failure, completion=row['completion'])), flush=True)
            del rig
            gc.collect()
        report['ok'] = True
    except Exception:
        report['error'] = traceback.format_exc()
        raise
    finally:
        (a.output / 'result.json').write_text(json.dumps(report, indent=2), encoding='utf8')
        print(json.dumps(dict(ok=report['ok'], file_checks=len(report['file_checks']), scheduler=len(report['scheduler']))))

if __name__ == '__main__':
    main()
