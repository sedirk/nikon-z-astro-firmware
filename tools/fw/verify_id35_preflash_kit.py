"""Read-only, fixed-hash Z6 C3.80 modified5 kit/card verifier. Never flashes."""
from pathlib import Path
import argparse, binascii, hashlib, json, sys

SIZE, BASE = 33502842, 0x10020000
DIGESTS = {
 'test':'76474a8977a3bf4b456fe68f9594110714a04c09b4ec575f019ba27fadd0d2d7',
 'modified4':'bdf30026dc9d18b09a5ca9332369d126729d63a36013e94b8b20cf6638a4ef1b',
 'modified1':'eeded80d4009204ba9760b6e20436aea3f6a37ce4ed6331ca662b839164a8875',
 'stock':'1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c',
}
PATHS = {'test':'01_TEST_MODIFIED5/EG162080.BIN',
 'modified4':'02_BACK_TO_MODIFIED4/EG162080.BIN',
 'modified1':'03_BACK_TO_MODIFIED1/EG162080.BIN',
 'stock':'04_STOCK_C380/EG162080.BIN'}
# Fixed independently of the delivered recipe/manifest; exact in-place blocks.
EDITS = ((0x100c2654,'00f065fa','4ff00000'),(0x100c267c,'00f045fa','4ff00200'),
 (0x100c2690,'90f81a18','4ff00201'),(0x100c28b2,'84f86200','84f86290'),
 (0x100c28c8,'84f86390','84f86300'),(0x100c2964,'90f85f02','4ff00100'),
 (0x1019741a,'59b1','0ee0'),(0x10197868,'4e77','4a77'),(0x10197876,'4078','0020'),(0x100f64b4,'90f85902','4ff00200'))
EDITS = EDITS + ((269983060, '0020', '0420'), (269600598, '05460e464ff6ff77', '074620f004050e46'), (269600612, 'b8420ed0', '1c280ed2'), (269600650, '526900eb8000484902eb0010843990f84025ca6190f8412581f8202090f8422581f8262090f84305c8670846f4f727fa2fe0', '526950235843121802f5a86247488438137807b1234600bf00bfc361537880f82030937880f82630d378c367f4f727fa2fe0'))
SUPPORT={'START_HERE.txt','FLAT_COMPARE.txt','REVIEW.md','verify.py','baseline112.json',
         'patch-recipe.json','SHOT_LOG_TEMPLATE.txt'}

def need(value,message):
    if not value:raise ValueError(message)
def sha(data):return hashlib.sha256(data).hexdigest()
def read_module(path,mode):
    need(path.is_file(),f'Missing module: {path}')
    need(path.stat().st_size==SIZE,f'Wrong size: {path}')
    data=path.read_bytes();need(sha(data)==DIGESTS[mode],f'Wrong SHA-256 for {mode}: {path}')
    need(binascii.crc_hqx(data,0)==0,f'CRC mismatch: {path}')
    return data
def reconstruct(stock,edits):
    need(len(stock)==SIZE and sha(stock)==DIGESTS['stock'],'Wrong original module')
    data=bytearray(stock)
    for address,before,after in edits:
        old,new=bytes.fromhex(before),bytes.fromhex(after);off=address-BASE
        need(len(old)==len(new) and len(old) in (2,4,8,50) and 0<=off<=SIZE-2-len(old),'Instruction extent')
        need(data[off:off+len(old)]==old,'Original instruction mismatch')
        data[off:off+len(new)]=new
    data[-2:]=binascii.crc_hqx(data[:-2],0).to_bytes(2,'big')
    return bytes(data)
def check_kit(root):
    manifest=json.loads((root/'manifest.json').read_text(encoding='utf8'))
    need(manifest['schema']==5 and manifest['candidate']=='modified5','Wrong kit kind')
    expected=set(PATHS.values())|SUPPORT;listed=[r['path'] for r in manifest['files']]
    need(len(listed)==len(expected) and set(listed)==expected,'Unexpected manifest paths')
    for row in manifest['files']:
        path=root/row['path'];need(path.is_file(),f'Missing kit file: {path}')
        need(path.stat().st_size==row['bytes'] and sha(path.read_bytes())==row['sha256'],f'Kit file changed: {path}')
    actual={p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file() and p.suffix.lower() in ('.bin','.bi','.lab')}
    need(actual==set(PATHS.values()),'Unexpected firmware file inside kit')
    modules={mode:read_module(root/name,mode) for mode,name in PATHS.items()}
    for mode,count in (('modified1',3),('modified4',10),('test',14)):
        need(reconstruct(modules['stock'],EDITS[:count])==modules[mode],f'Exact reconstruction failed: {mode}')
    return dict(kit_files_checked=len(listed),module_sha256=DIGESTS,exact_patch_reconstruction=True)
def check_card_contents(root,mode):
    need(mode in PATHS,'Select test, modified4, modified1 or stock')
    need(root.is_dir(),'Card root is not a directory')
    names=[p.name for p in root.iterdir() if p.is_file() and (p.suffix.lower() in ('.bin','.bi','.lab') or '.bin.' in p.name.lower())]
    need(len(names)==1 and names[0].upper()=='EG162080.BIN','Keep exactly one firmware file named EG162080.BIN at card root; found '+repr(names))
    data=read_module(root/names[0],mode)
    return dict(card_root=str(root),mode=mode,firmware_file=names[0],bytes=len(data),sha256=sha(data))
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--kit',type=Path,default=Path(__file__).resolve().parent)
    ap.add_argument('--card-root',type=Path);ap.add_argument('--mode',choices=tuple(PATHS));a=ap.parse_args()
    try:
        result=check_kit(a.kit)
        if a.card_root:
            need(a.mode is not None,'--mode is required with --card-root')
            root=a.card_root.resolve(strict=True)
            need(root==Path(root.anchor) and len(root.drive)==2 and root.drive[1]==':','Use an actual Windows drive root, for example E:\\')
            result['card']=check_card_contents(root,a.mode)
        else:need(a.mode is None,'--mode requires --card-root')
        result.update(ok=True,read_only=True,physical_installation_verified=False,physical_recovery_verified=False,ring_removal_verified=False)
        print(json.dumps(result,indent=2));return 0
    except (OSError,ValueError,KeyError,TypeError) as exc:
        print(json.dumps(dict(ok=False,error=str(exc),read_only=True)),file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
