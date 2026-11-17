"""Stream independent C++ lossless decoding and compare every pixel with LibRaw."""
from pathlib import Path
import argparse,hashlib,json,struct,subprocess,urllib.request,datetime
import numpy as np
import rawpy
from audit_nef import file_sha

ROOT=Path(__file__).resolve().parents[2];WSL=r'C:\Program Files\WSL\wsl.exe'
def linux(path):
    p=str(Path(path).resolve());assert p[1:3]==':\\';return '/mnt/'+p[0].lower()+'/'+p[3:].replace('\\','/')

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    source=ROOT/'tools/fw/nikon_lossless14_check.cpp';exe=a.output/'nikon-lossless14-check'
    build=[WSL,'-d','Ubuntu-24.04','--','g++','-std=c++17','-O2','-Wall','-Wextra',linux(source),'-o',linux(exe)]
    built=subprocess.run(build,capture_output=True);(a.output/'build.stderr.txt').write_bytes(built.stderr)
    (a.output/'build.stdout.txt').write_bytes(built.stdout);assert built.returncode==0
    report=dict(scope=__doc__,script_sha256=file_sha(__file__),cpp_sha256=file_sha(source),executable_sha256=file_sha(exe),
        build_argv=build,files=[],ok=False)
    url='https://raw.githubusercontent.com/LibRaw/LibRaw/0.22.2/src/decoders/decoders_dcraw.cpp'
    body=urllib.request.urlopen(url,timeout=30).read()
    (a.output/'libraw-0.22.2-decoders_dcraw.cpp').write_bytes(body)
    report['format_reference']=dict(url=url,sha256=hashlib.sha256(body).hexdigest(),retrieved_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
    cases=[]
    for name in ['new-bias-audit.json','new-dark-audit.json']:
        cases+=json.loads((ROOT/'analysis/real-nef-2026-11-09'/name).read_text(encoding='utf8'))['files']
    for case in cases:
        path=Path(case['path']);assert file_sha(path)==case['sha256']
        raw=max(case['tiff']['raw_strips'],key=lambda v:v['width'][0]*v['height'][0])
        maker=[x for x in case['tiff']['ifds'] if x['label'].endswith('/Nikon')][0]
        assert maker['byte_order']=='<'
        tag=maker['tags']['0x0096']
        with path.open('rb') as f:f.seek(tag['offset']);data=f.read(tag['bytes'])
        assert data[:2]==b'F0' and raw['bits']==[14]
        preds=struct.unpack_from('<4H',data,2)
        cmd=[WSL,'-d','Ubuntu-24.04','--',linux(exe),linux(path),str(raw['offset']),str(raw['size']),
             str(raw['width'][0]),str(raw['height'][0]),*map(str,preds)]
        with rawpy.imread(str(path)) as r:
            wanted=r.raw_image.astype('<u2',copy=False).tobytes()
            proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            pos=0;diff=0;digest=hashlib.sha256()
            while True:
                chunk=proc.stdout.read(1024*1024)
                if not chunk:break
                digest.update(chunk)
                expected=wanted[pos:pos+len(chunk)];assert len(expected)==len(chunk)
                assert len(chunk)%2==0
                diff+=int(np.count_nonzero(np.frombuffer(chunk,dtype='<u2')!=np.frombuffer(expected,dtype='<u2')))
                pos+=len(chunk)
            stderr=proc.stderr.read();rc=proc.wait()
            (a.output/(path.stem+'.stderr.txt')).write_bytes(stderr)
            assert rc==0 and pos==len(wanted) and diff==0,(path.name,rc,pos,diff)
            assert digest.hexdigest()==case['stored_pixels_sha256']
        report['files'].append(dict(name=path.name,source_sha256=case['sha256'],argv=cmd,predictors=preds,
            raw_shape=case['raw_shape'],pixels=pos//2,mismatches=diff,pixels_sha256=digest.hexdigest()))
        print(path.name,pos//2,'pixels',diff,'mismatches',flush=True)
    report['ok']=True
    (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    (a.output/'probe-source.py').write_bytes(Path(__file__).read_bytes());(a.output/source.name).write_bytes(source.read_bytes())

if __name__=='__main__':main()
