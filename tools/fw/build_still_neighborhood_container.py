"""Package the pinned static neighborhood control candidate, offline only.

Reuses the previously audited Nikon XOR tables/container format. This script
does not flash, change the firmware version, alter the upgrade checks, or add
an image-processing model. Camera installation/recovery and pixel behavior are
distinct from checksums and exact byte reversal.

2026-11-09: this builder preserves the outer SHA-1 digest and is therefore a
CRC-only diagnostic, excluded from installation candidates. The tested raw-EG
module route is packaged by package_still_neighborhood.py instead.
"""
from pathlib import Path
import argparse, binascii, json
from build_raw_candidates import apply_candidate
from build_raw_container import (ROOT, SOURCE_SHA, EG_SHA, SIZE, MODULES,
    sha, require, tables_from, transform, inspect_body)

ID='still-neighborhood-gates-off'
MODULE_SHA='eeded80d4009204ba9760b6e20436aea3f6a37ce4ed6331ca662b839164a8875'


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--module',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--crc-only-diagnostic',action='store_true')
    args=p.parse_args()
    if not args.crc_only_diagnostic:p.error('Outer SHA-1 is not repaired; use package_still_neighborhood.py, or --crc-only-diagnostic for format research.')
    paths={'original':ROOT/'firmware/original/Z_6_0380.bin', 'module':args.module,
           'catalog':ROOT/'patches/z6-c380-still-neighborhood-off.json'}
    inputs={k:path.read_bytes() for k,path in paths.items()}
    original=inputs['original'];module=inputs['module'];catalog=json.loads(inputs['catalog'])
    require(len(original)==SIZE and sha(original)==SOURCE_SHA,'Original container mismatch')
    require(sha(module)==MODULE_SHA,'Pinned candidate mismatch')
    tables=tables_from(original);body=transform(original[32:],tables)
    original_modules=inspect_body(body);start,n=MODULES[2][1:]
    original_eg=bytes(body[start:start+n]);require(sha(original_eg)==EG_SHA,'Embedded module mismatch')
    expected,recipe=apply_candidate(original_eg,catalog,catalog['candidates'][0])
    require(module==expected and recipe['id']==ID,'Recipe mismatch')
    require(original[:32]+transform(body,tables)==original,'Original round trip mismatch')
    patched=bytearray(body);patched[start:start+n]=module
    patched[-16:-14]=binascii.crc_hqx(patched[:-16],0).to_bytes(2,'big')
    output=original[:32]+transform(patched,tables);decoded=transform(output[32:],tables)
    require(decoded==patched,'Candidate round trip mismatch');modules=inspect_body(decoded)
    require(decoded[:176]==body[:176],'Container header changed')
    for i in (0,1,3):
        _,pos,length=MODULES[i]
        require(decoded[pos:pos+length]==body[pos:pos+length],'Unrelated module changed')
    changes=[i for i,(x,y) in enumerate(zip(original,output)) if x!=y]
    allowed={32+start+int(off,16) for off in recipe['changed_byte_offsets']}
    allowed.update(i for i in range(SIZE-16,SIZE-14) if original[i]!=output[i])
    require(set(changes)==allowed,'Unexpected changed container bytes')
    restored=bytearray(decoded)
    for edit in recipe['edits']:
        pos=start+int(edit['file_offset'],16);old=bytes.fromhex(edit['before'])
        restored[pos:pos+len(old)]=old
    restored[start+n-2:start+n]=original_eg[-2:]
    restored[-16:-14]=binascii.crc_hqx(restored[:-16],0).to_bytes(2,'big')
    require(restored==body and original[:32]+transform(restored,tables)==original,'Byte reversal mismatch')
    args.output.mkdir(parents=True,exist_ok=False)
    filename='Z6-C380-'+ID+'-EXPERIMENTAL.bin.lab'
    (args.output/filename).write_bytes(output)
    require((args.output/filename).read_bytes()==output,'Output readback mismatch')
    for k,path in paths.items():require(path.read_bytes()==inputs[k],'Input changed: '+k)
    for name in ('build_still_neighborhood_container.py','build_raw_container.py','build_raw_candidates.py'):
        (args.output/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    (args.output/'catalog.json').write_bytes(inputs['catalog'])
    manifest=dict(ok=True,id=ID,file=filename,model='Nikon Z6 first generation',version='C3.80',
        scope=__doc__,source_sha256=sha(original),module_sha256=sha(module),output_sha256=sha(output),size=len(output),
        input_hashes={k:sha(v) for k,v in inputs.items()},recipe=recipe,
        original_modules=original_modules,output_modules=modules,
        header_and_version_preserved=True,other_modules_preserved=True,
        body_crc_before=body[-16:-14].hex(),body_crc_after=patched[-16:-14].hex(),
        changed_bytes=[dict(offset=hex(i),before=f'{original[i]:02x}',after=f'{output[i]:02x}') for i in changes],
        exact_encoded_reversal=True,inputs_preserved=True,
        combined_with_fullsize_or_class_candidate=False,
        camera_installation_verified=False,camera_recovery_verified=False,camera_nef_effect_verified=False,
        whole_container_header_digest_updated=False,distribution_eligible=False,
        status='CRC-only diagnostic container; outer SHA-1 not repaired; excluded from installation candidates',
        effect_scope='Static property controls +4c=0,+4e=2,+4f=2; no claim of all RAW corrections disabled.')
    (args.output/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf8')
    print(json.dumps(dict(ok=True,file=str(args.output/filename),sha256=sha(output),changed_bytes=len(changes),exact_reversal=True)))


if __name__=='__main__':main()
