"""Rebuild an offline experimental Z6 C3.80 container from a pinned module.

Verifies headers, all module CRCs, the body CRC, exact changed byte locations,
and byte-for-byte reversal to the original. This is a file-format build, not a
camera acceptance, installation, recovery, or RAW-pixel validation.

2026-11-09: the whole-file route additionally verifies SHA-1(body || suffix8).
This legacy builder does NOT update that digest; it is retained for CRC-only
format diagnostics. Use the separately tested raw EG module route for the
current experiment. Earlier output/snapshots remain historical evidence.
"""
from pathlib import Path
import argparse, binascii, hashlib, json, struct
from build_raw_candidates import apply_candidate
from z6_c380_container import recover_c380_mask, apply_mask

ROOT=Path(__file__).resolve().parents[2]
SOURCE_SHA='ff978ffdf77c58c0b861a06e16d432d5886969f3cdd05d62f6c8e82e8a4cea54'
EG_SHA='1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
VARIANTS={
 'still-preserve-front-raw':dict(sha256='c77b4a700d87b0cd1ced828591891ac676a1f7f300ec48d132c80b9dd57a8f53',
    module='analysis/raw-patch-candidates-2026-11-08/modules/still-preserve-front-raw.bi',
    catalog='patches/z6-c380-raw-candidates.json'),
 'still-preserve-fullsize-raw':dict(sha256='7ff43669a82d9def1407056d889db041338dbe12a0bb2867eccfc98527f0875c',
    module='analysis/raw-release-contract-2026-11-08/fullsize-module/still-preserve-fullsize-raw.bi',
    catalog='patches/z6-c380-fullsize-raw-candidate.json')}
SIZE=34923366
MODULES=(('ex1620_037000.bi',176,524290),('_tpj01_v140.bin',524466,57346),
         ('eg1620_038000.bi',581812,33502842),('vr1620_010200.bi',34084654,838664))


def sha(b): return hashlib.sha256(b).hexdigest()
def require(value,message):
    if not value: raise ValueError(message)


def tables_from(original_container):
    require(len(original_container)==SIZE and sha(original_container)==SOURCE_SHA,'Original container hash/size mismatch')
    return recover_c380_mask(original_container[32:])


def transform(data,tables):
    return bytearray(apply_mask(bytes(data),tables))

def inspect_body(body):
    require(len(body)==SIZE-32,'Decoded body size mismatch')
    require(struct.unpack_from('>4I',body,32)==(4,176,0,0),'Unexpected module header')
    require(body[-14:]==bytes(14),'Unexpected trailing bytes')
    require(binascii.crc_hqx(body[:-16],0)==int.from_bytes(body[-16:-14],'big'),'Body CRC mismatch')
    rows=[]
    for i,(expected_name,expected_start,expected_size) in enumerate(MODULES):
        name,start,size,r0,r1=struct.unpack_from('>16s4I',body,48+i*32)
        require((name.rstrip(b'\0').decode('ascii'),start,size,r0,r1)==
                (expected_name,expected_start,expected_size,0,0),'Unexpected module entry')
        content=bytes(body[start:start+size])
        require(binascii.crc_hqx(content,0)==0,'Module CRC mismatch: '+expected_name)
        rows.append(dict(name=expected_name,body_offset=start,size=size,sha256=sha(content),crc_remainder=0))
    return rows


def build(original,module,catalog,candidate_id='still-preserve-fullsize-raw'):
    require(candidate_id in VARIANTS,'Unknown candidate')
    require(len(original)==SIZE and sha(original)==SOURCE_SHA,'Original container hash/size mismatch')
    require(sha(module)==VARIANTS[candidate_id]['sha256'],'Candidate module hash mismatch')
    tables=tables_from(original)
    body=transform(original[32:],tables)
    original_modules=inspect_body(body)
    start,size=MODULES[2][1:]
    original_eg=bytes(body[start:start+size])
    require(sha(original_eg)==EG_SHA,'Original embedded EG hash mismatch')
    recipe=next(c for c in catalog['candidates'] if c['id']==candidate_id)
    expected,patch_manifest=apply_candidate(original_eg,catalog,recipe)
    require(module==expected,'Candidate does not match the pinned patch recipe')
    require(original[:32]+transform(body,tables)==original,'Original round trip mismatch')
    patched=bytearray(body)
    patched[start:start+size]=module
    patched[-16:-14]=binascii.crc_hqx(patched[:-16],0).to_bytes(2,'big')
    built=original[:32]+transform(patched,tables)
    reread=transform(built[32:],tables)
    require(reread==patched,'New container round trip mismatch')
    new_modules=inspect_body(reread)
    require(reread[:176]==body[:176],'Header changed')
    for i in (0,1,3):
        _,pos,n=MODULES[i]
        require(reread[pos:pos+n]==body[pos:pos+n],'Unrelated module changed')
    changes=[i for i,(a,b) in enumerate(zip(original,built)) if a!=b]
    expected_changes={32+start+int(i,16) for i in patch_manifest['changed_byte_offsets']}
    expected_changes.update(i for i in range(SIZE-16,SIZE-14) if original[i]!=built[i])
    require(set(changes)==expected_changes,'Unexpected container byte changes')
    # Reversal is a byte-level proof. It says nothing about camera recovery.
    reverse=bytearray(reread)
    for edit in patch_manifest['edits']:
        pos=start+int(edit['file_offset'],16); before=bytes.fromhex(edit['before'])
        reverse[pos:pos+len(before)]=before
    reverse[start+size-2:start+size]=original_eg[-2:]
    reverse[-16:-14]=binascii.crc_hqx(reverse[:-16],0).to_bytes(2,'big')
    require(reverse==body,'Reversed decoded body mismatch')
    restored=original[:32]+transform(reverse,tables)
    require(restored==original,'Reversed encoded container mismatch')
    manifest=dict(schema=1,id=candidate_id,model='Nikon Z6 first generation',version='C3.80',
        status='CRC-only diagnostic container; outer SHA-1 digest not updated; excluded from installation candidates',
        source_sha256=SOURCE_SHA,candidate_sha256=sha(module),output_sha256=sha(built),size=len(built),
        mask_recovery='z6_c380_zero_samples_spanning_tree',outer_prefix_preserved=True,header_preserved=True,
        original_modules=original_modules,output_modules=new_modules,
        body_crc_before=body[-16:-14].hex(),body_crc_after=patched[-16:-14].hex(),
        byte_changes=[dict(offset=hex(i),before=f'{original[i]:02x}',after=f'{built[i]:02x}') for i in changes],
        byte_exact_reversal_to_original=True,restored_sha256=sha(restored),
        camera_acceptance_verified=False,camera_recovery_verified=False,hardware_pixels_verified=False,
        whole_container_header_digest_updated=False,distribution_eligible=False,
        native_fullsize_guard=candidate_id=='still-preserve-fullsize-raw',
        candidate_constraints=['Geometry must match the current input and backend RAW descriptors.',
          ('The native size predicate retains input RAW only when owner+0x192=0; other sizes follow the original replacement path.'
           if candidate_id=='still-preserve-fullsize-raw' else
           'Small/medium RAW geometry differs for the tested owner+2811=0 paths; no runtime guard exists yet.'),
          'Format 3 with output mode 0 can exceed the native RAW allocation in synthetic flag combinations.',
          'Front-end correction and earlier RAW producers remain; preserving this input is not an untouched sensor tap.',
          'Queue completion, cache coherency and continuous-shooting resource lifetime need hardware evidence.'])
    return bytes(built),manifest


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--candidate',choices=VARIANTS,default='still-preserve-fullsize-raw')
    p.add_argument('--crc-only-diagnostic',action='store_true',help='Acknowledge this builds a format diagnostic with an unrepaired outer SHA-1 digest.')
    args=p.parse_args()
    if not args.crc_only_diagnostic:p.error('Outer SHA-1 is not repaired. Use the raw EG candidate package, or explicitly select --crc-only-diagnostic for format research.')
    inputs=dict(original=ROOT/'firmware/original/Z_6_0380.bin',
        candidate=ROOT/VARIANTS[args.candidate]['module'],
        catalog=ROOT/VARIANTS[args.candidate]['catalog'])
    contents={k:path.read_bytes() for k,path in inputs.items()}
    built,manifest=build(contents['original'],contents['candidate'],json.loads(contents['catalog']),args.candidate)
    args.output.mkdir(parents=True,exist_ok=False)
    filename='Z6-C380-'+args.candidate+'-EXPERIMENTAL.bin.lab'
    with (args.output/filename).open('xb') as f: f.write(built)
    require(sha((args.output/filename).read_bytes())==manifest['output_sha256'],'Output readback mismatch')
    for k,path in inputs.items(): require(path.read_bytes()==contents[k],'Input changed: '+k)
    for filename_source,path in (('builder-source.py',Path(__file__)),
                                 ('module-builder-source.py',ROOT/'tools/fw/build_raw_candidates.py')):
        (args.output/filename_source).write_bytes(path.read_bytes())
    manifest.update(file=filename,builder_sha256=sha(Path(__file__).read_bytes()),
        module_builder_sha256=sha((ROOT/'tools/fw/build_raw_candidates.py').read_bytes()),
        catalog_sha256=sha(contents['catalog']),inputs_preserved=True)
    (args.output/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print(json.dumps(dict(ok=True,file=str(args.output/filename),sha256=sha(built),
                         changed_bytes=len(manifest['byte_changes']),exact_reversal=True),indent=2))


if __name__=='__main__': main()
