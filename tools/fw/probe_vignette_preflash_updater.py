"""Native modified2 install/rollback audit; flash services operate private RAM only."""
from pathlib import Path
import argparse, gc, json, traceback
import probe_eg_update_route as eg
from probe_preflash_review import AuditRig, schedule
from review_vignette_preflash import SOURCES
from verify_vignette_preflash_kit import DIGESTS, need, sha

ROOT = eg.ROOT


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(); args.output.mkdir(parents=True, exist_ok=False)
    blobs = {k: v.read_bytes() for k, v in SOURCES.items()}
    for k, v in blobs.items():
        need(sha(v) == DIGESTS[k], 'Input mismatch '+k)
    report = dict(ok=False, scope=__doc__, file_checks=[], scheduler=[], physical_flash=False,
        adapters='Original file/CRC/descriptor and RAM scheduler instructions; host filesystem/OS services and private-memory erase/program adapters.',
        limits='No physical flash timing, power interruption, electrical recovery or camera boot test.')
    try:
        # Exact bytes, both previous running ROMs, and both recovery choices.
        for rom, target in (('modified1','test'), ('stock','test'), ('test','modified1'), ('test','stock')):
            rig = AuditRig(blobs[rom]); label = rom+'_accepts_'+target
            row = eg.run(rig, label, blobs[target])
            need(row['discovery_return'] == 0 and row['integrity_return'] == 0 and row['component_precheck_return'] == 0, label)
            need(row['file_kind'] == 2 and row['component'] == 3 and row['component_count'] == 1, 'Wrong component')
            need(row['displayed_version'] == '03.80', 'Unexpected version')
            need(row['loaded_buffer_sha256'] == DIGESTS[target], 'Native load mismatch')
            need(row['update_length'] == len(blobs[target])-2, 'Bad length')
            report['file_checks'].append(dict(running_rom=rom, target=target, **row))
            print(json.dumps(dict(stage='file', label=label, ok=True)), flush=True)
            del rig; gc.collect()
        damaged = bytearray(blobs['test']); damaged[0xa28b5] ^= 1
        for label, data, name, size in (
            ('damaged_crc',bytes(damaged),'EG162080.BIN',None),
            ('wrong_model_filename',blobs['test'],'EG172080.BIN',None),
            ('oversize_directory_entry',blobs['test'],'EG162080.BIN',0x2940001)):
            rig = AuditRig(blobs['modified1'])
            row = eg.run(rig,label,data,name,reported_size=size)
            if label == 'damaged_crc':
                need(row['discovery_return'] == 0 and row['integrity_return'] == 3, 'Damaged file accepted')
            else:
                need(row['discovery_return'] != 0, 'Wrong file accepted')
            report['file_checks'].append(dict(running_rom='modified1', expected_rejection=True, **row))
            print(json.dumps(dict(stage='file-negative', label=label, rejected=True)), flush=True)
            del rig; gc.collect()
        for rom, target, failure in (
            ('modified1','test',None), ('test','modified1',None), ('test','stock',None),
            ('modified1','test','erase'), ('test','stock','readback')):
            rig = AuditRig(blobs[rom]); label = rom+'_to_'+target+('_'+failure if failure else '')
            row = schedule(rig,label,blobs[target],failure)
            report['scheduler'].append(row)
            print(json.dumps({k:v for k,v in row.items() if k not in ('events','calls')}),flush=True)
            del rig; gc.collect()
        report['ok'] = True
    except Exception:
        report['error'] = traceback.format_exc()
        if 'rig' in locals():
            report['failed_calls'] = rig.calls
            report['failed_events'] = rig.flash_events
        raise
    finally:
        (args.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
        for name in (Path(__file__).name,'probe_eg_update_route.py','probe_preflash_review.py',
                     'review_vignette_preflash.py','verify_vignette_preflash_kit.py'):
            (args.output/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
        print(json.dumps(dict(ok=report['ok'],file_checks=len(report['file_checks']),scheduler=len(report['scheduler']))))


if __name__ == '__main__':
    main()
