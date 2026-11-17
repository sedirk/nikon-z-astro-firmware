"""Map the observed read-only Z6 inventory to pinned primary libgphoto2 sources.

Downloads source text only; never executes a camera opcode. Also saves the exact
working QEMU source used to audit the frontend completion-model boundary.
"""
from pathlib import Path
import datetime, hashlib, json, re, subprocess, urllib.request

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT/'analysis/raw-front-completion-2026-11-10'

def sha(b): return hashlib.sha256(b).hexdigest()
def write(p, obj): p.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding='utf8')
def fetch(url):
    req = urllib.request.Request(url, headers={'User-Agent':'Z6-local-research/1.0'})
    with urllib.request.urlopen(req, timeout=45) as r: return r.read()

def main():
    dst=OUT/'primary-sources';dst.mkdir(exist_ok=False)
    api='https://api.github.com/repos/gphoto/libgphoto2/commits/master'
    data=fetch(api);(dst/'libgphoto2-commit.json').write_bytes(data)
    commit=json.loads(data)['sha']; assert re.fullmatch(r'[0-9a-f]{40}',commit)
    sources=[]
    for name in ('ptp.h','ptp.c','config.c'):
        url=f'https://raw.githubusercontent.com/gphoto/libgphoto2/{commit}/camlibs/ptp2/{name}'
        b=fetch(url);(dst/name).write_bytes(b)
        sources.append(dict(url=url,bytes=len(b),sha256=sha(b),file=name))
    definitions={}
    for line_no,line in enumerate((dst/'ptp.h').read_text(encoding='utf8').splitlines(),1):
        m=re.match(r'\s*#define\s+(PTP_OC_NIKON_\w+)\s+(0x[0-9a-fA-F]+)\b',line)
        if m:definitions.setdefault(int(m[2],16),[]).append(dict(name=m[1],line=line_no))
    inv=json.loads((OUT/'camera-readonly-inventory-v2.json').read_text(encoding='utf8'))
    ops=[int(x,16) for x in inv['vendor_opcodes']]; assert inv['ok'] and len(ops)==len(set(ops))
    rows=[dict(opcode=f'0x{x:04x}',definitions=definitions.get(x,[])) for x in ops]
    write(OUT/'usb-opcode-map.json',dict(ok=True,observed_count=len(rows),commit=commit,
        pinned_sources=sources,mapped_count=sum(bool(x['definitions']) for x in rows),opcodes=rows,
        legacy_service_commands={f'0x{x:04x}':x in ops for x in (0xfc01,0xfc02,0xfe01,0xfe02,0xfe31,0xfe34,0xfe63,0xfeb1)},
        vendor_opcodes_executed=[],scope='Symbol mapping is source evidence, not a Z6 handler audit or an authorization to execute commands. Unadvertised does not mean unsupported.'))
    expected={
        'nikon-z6.c':'9a92f19510f6730312158079cea39717826648da0d245d766ed39ce412e9091c',
        'nikon-z6-profile.h':'301091acd26b268fd315741a17eed8e8940aa004a9d72ab61eb08b74a06a324a',
        'nikon-functional-isp.h':'d53ebf656d1bb5bf7fba70c749b7caa9f5cca0746344df89dbd46405076181c6',
        'nikon-isp-pixels.h':'327d4535af98bd2aeecbfa2d97a2ac5cd85a9ba56af8338f7ee6400228a6dbaa'}
    model=[]
    for name,h in expected.items():
        argv=['wsl','-d','Ubuntu-24.04','--','cat','/home/z6lab/z6lab/z6-qemu/qemu/'+name]
        r=subprocess.run(argv,capture_output=True,timeout=30,check=True)
        (dst/name).write_bytes(r.stdout);(dst/(name+'.stderr')).write_bytes(r.stderr)
        assert sha(r.stdout)==h, name
        model.append(dict(file=name,sha256=h,argv=argv))
    write(OUT/'source-provenance.json',dict(retrieved_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        github_commit_api=api,libgphoto2=sources,working_qemu=model,
        microsoft_documentation=[
          'https://learn.microsoft.com/en-us/windows/win32/wpd_sdk/wpd-command-mtp-ext-get-supported-vendor-opcodes',
          'https://learn.microsoft.com/en-us/windows/win32/api/portabledeviceapi/nf-portabledeviceapi-iportabledevice-sendcommand',
          'https://learn.microsoft.com/en-us/windows/win32/wpd_sdk/supporting-mtp-extensions']))
    print(json.dumps(dict(ok=True,advertised_count=len(rows),mapped_count=sum(bool(x['definitions']) for x in rows),
        unknown=[x['opcode'] for x in rows if not x['definitions']],pinned_commit=commit,model_files=len(model))))

if __name__=='__main__':main()
