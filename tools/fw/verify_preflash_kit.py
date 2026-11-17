"""Read-only Z6 preflash kit/card check. Never copies, deletes or flashes files.

Passing this check validates bytes and card file selection only. It is not a
camera compatibility, boot, electrical, power-loss or recovery guarantee.
"""
from pathlib import Path
import argparse,binascii,hashlib,json,sys

SIZE=33502842
DIGESTS={'test':'eeded80d4009204ba9760b6e20436aea3f6a37ce4ed6331ca662b839164a8875',
         'rollback':'1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'}
PATHS={'test':'01_TEST/EG162080.BIN','rollback':'02_ROLLBACK/EG162080.BIN'}

def need(value,message):
    if not value:raise ValueError(message)

def sha(data):return hashlib.sha256(data).hexdigest()

def read_module(path,mode):
    need(path.is_file(),f'Missing file: {path}')
    need(path.stat().st_size==SIZE,f'Wrong file size: {path}')
    data=path.read_bytes()
    need(sha(data)==DIGESTS[mode],f'Wrong SHA-256 for {mode}: {path}')
    need(binascii.crc_hqx(data,0)==0,f'Wrong CRC: {path}')
    return data

def check_kit(root):
    m=json.loads((root/'manifest.json').read_text(encoding='utf8'))
    expected={*PATHS.values(),'START_HERE.txt','REVIEW.md','verify.py','baseline112.json'}
    listed=[r['path'] for r in m['files']]
    need(len(listed)==len(expected) and set(listed)==expected,'Unexpected manifest paths')
    for row in m['files']:
        file=root/row['path'];need(file.is_file(),f'Missing kit file: {file}')
        need(file.stat().st_size==row['bytes'] and sha(file.read_bytes())==row['sha256'],f'Kit file changed: {file}')
    original=read_module(root/PATHS['rollback'],'rollback')
    candidate=read_module(root/PATHS['test'],'test')
    # Independent edit locations, not supplied by a mutable manifest.
    expected=bytearray(original)
    for off,old,new in ((0xa2654,'00f065fa','4ff00000'),(0xa267c,'00f045fa','4ff00200'),(0xa2690,'90f81a18','4ff00201')):
        need(expected[off:off+4]==bytes.fromhex(old),'Original instruction mismatch')
        expected[off:off+4]=bytes.fromhex(new)
    expected[-2:]=binascii.crc_hqx(expected[:-2],0).to_bytes(2,'big')
    need(bytes(expected)==candidate,'Candidate is not the reviewed three-instruction edit')
    return dict(kit_files_checked=len(listed),candidate_sha256=DIGESTS['test'],rollback_sha256=DIGESTS['rollback'])

def check_card_contents(root,mode):
    # Kept separately callable for fixtures; the CLI also requires a drive root.
    need(root.is_dir(),'Card root is not a directory')
    names=[p.name for p in root.iterdir() if p.is_file() and
           (p.suffix.lower() in ('.bin','.bi','.lab') or '.bin.' in p.name.lower())]
    need(len(names)==1 and names[0].upper()=='EG162080.BIN',
         'Keep exactly one firmware file at card root, named EG162080.BIN; found '+repr(names))
    data=read_module(root/names[0],mode)
    return dict(card_root=str(root),mode=mode,firmware_file=names[0],bytes=len(data),sha256=sha(data))

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--kit',type=Path,default=Path(__file__).resolve().parent)
    p.add_argument('--card-root',type=Path)
    p.add_argument('--mode',choices=tuple(PATHS))
    a=p.parse_args()
    try:
        result=check_kit(a.kit)
        if a.card_root:
            need(a.mode is not None,'--mode test or --mode rollback is required for card checking')
            root=a.card_root.resolve(strict=True)
            need(root==Path(root.anchor) and len(root.drive)==2 and root.drive[1]==':',
                 '--card-root must be an actual Windows drive root, for example E:\\')
            result['card']=check_card_contents(root,a.mode)
        else:need(a.mode is None,'--mode needs --card-root')
        result.update(ok=True,read_only=True,physical_installation_verified=False,physical_recovery_verified=False)
        print(json.dumps(result,indent=2))
    except (OSError,ValueError,KeyError,TypeError) as exc:
        print(json.dumps(dict(ok=False,error=str(exc),read_only=True)),file=sys.stderr);return 1
    return 0

if __name__=='__main__':raise SystemExit(main())
