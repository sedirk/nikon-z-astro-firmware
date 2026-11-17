"""Read-only Z6 recovery verifier. Rejects the recalled modified5 hash."""
from pathlib import Path
import argparse,binascii,hashlib,json,sys

SIZE=33502842
REVOKED='76474a8977a3bf4b456fe68f9594110714a04c09b4ec575f019ba27fadd0d2d7'
DIGESTS={'modified4':'bdf30026dc9d18b09a5ca9332369d126729d63a36013e94b8b20cf6638a4ef1b',
 'modified1':'eeded80d4009204ba9760b6e20436aea3f6a37ce4ed6331ca662b839164a8875',
 'stock':'1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'}
PATHS={'modified4':'01_RECOVER_MODIFIED4/EG162080.BIN','modified1':'02_DARK_ONLY_MODIFIED1/EG162080.BIN','stock':'03_STOCK_C380/EG162080.BIN'}
def need(x,msg):
    if not x:raise ValueError(msg)
def sha(b):return hashlib.sha256(b).hexdigest()
def check_file(path,mode):
    need(path.is_file(),'Missing firmware: '+str(path));need(path.stat().st_size==SIZE,'Wrong file size')
    b=path.read_bytes();h=sha(b)
    need(h!=REVOKED,'RECALLED modified5: physical shutter Err/restart reported; do not install')
    need(h==DIGESTS[mode],'Wrong firmware hash for '+mode)
    need(binascii.crc_hqx(b,0)==0,'CRC mismatch')
    return dict(path=str(path),mode=mode,sha256=h,bytes=len(b))
def check_kit(root):
    result=[check_file(root/PATHS[n],n) for n in PATHS]
    actual={p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file() and p.suffix.lower() in ('.bin','.bi','.lab')}
    need(actual==set(PATHS.values()),'Unexpected firmware in recovery kit')
    return result
def check_card(root,mode):
    need(root.is_dir(),'Card root is not a directory')
    files=[p for p in root.iterdir() if p.is_file() and (p.suffix.lower() in ('.bin','.bi','.lab') or '.bin.' in p.name.lower())]
    need(len(files)==1 and files[0].name.upper()=='EG162080.BIN','Keep exactly one EG162080.BIN and no other firmware/backup at card root')
    return check_file(files[0],mode)
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--kit',type=Path,default=Path(__file__).resolve().parent)
    ap.add_argument('--card-root',type=Path);ap.add_argument('--mode',choices=tuple(PATHS));a=ap.parse_args()
    try:
        r=dict(kit=check_kit(a.kit))
        if a.card_root:
            need(a.mode is not None,'--mode is required');p=a.card_root.resolve(strict=True)
            need(p==Path(p.anchor) and len(p.drive)==2 and p.drive[1]==':','Use the actual Windows drive root')
            r['card']=check_card(p,a.mode)
        else:need(a.mode is None,'--mode requires --card-root')
        r.update(ok=True,read_only=True,physical_recovery_confirmed=False,revoked_sha256=REVOKED)
        print(json.dumps(r,indent=2));return 0
    except (OSError,ValueError,KeyError,TypeError) as e:
        print(json.dumps(dict(ok=False,error=str(e),read_only=True)),file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
