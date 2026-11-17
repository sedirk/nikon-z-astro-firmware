"""Verify a local experimental module; optionally reconstruct the original EG.

No flash, card access, downloads or in-place writes. A restore output must be a
new file. Byte reconstruction does not validate recovery of a physical camera.
"""
from pathlib import Path
import argparse,binascii,hashlib,json

def sha(data):return hashlib.sha256(data).hexdigest()

def reconstruct(data,recipe):
    assert sha(data)==recipe['output_sha256'] and len(data)==recipe['module_size']
    assert binascii.crc_hqx(data,0)==0
    restored=bytearray(data)
    for edit in recipe['edits']:
        off=int(edit['file_offset'],16);new=bytes.fromhex(edit['after']);old=bytes.fromhex(edit['before'])
        assert restored[off:off+len(new)]==new
        restored[off:off+len(old)]=old
    restored[-2:]=binascii.crc_hqx(restored[:-2],0).to_bytes(2,'big')
    assert sha(restored)==recipe['source_sha256'] and binascii.crc_hqx(restored,0)==0
    return bytes(restored)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--package',type=Path,default=Path(__file__).resolve().parent)
    p.add_argument('--restore-to',type=Path)
    a=p.parse_args();m=json.loads((a.package/'manifest.json').read_text(encoding='utf8'))
    for item in m['files']:
        data=(a.package/item['path']).read_bytes()
        assert len(data)==item['bytes'] and sha(data)==item['sha256'],item['path']
    data=(a.package/'candidate/EG162080.BIN').read_bytes()
    restored=reconstruct(data,m['recipe'])
    if a.restore_to:
        with a.restore_to.open('xb') as f:f.write(restored)
        assert a.restore_to.read_bytes()==restored
    print(json.dumps(dict(ok=True,verified_files=len(m['files']),module_sha256=sha(data),
        exact_original_module_sha256=sha(restored),restore_output=str(a.restore_to) if a.restore_to else None,
        physical_installation_verified=False,physical_recovery_verified=False,raw_pixel_effect_verified=False),indent=2))

if __name__=='__main__':main()
