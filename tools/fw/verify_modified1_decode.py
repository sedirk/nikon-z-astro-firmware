"""Compare every new NEF code with a separate narrow lossless decoder.

Reuses the previously built, hash-pinned C++ decoder. The format is derived
from the published Nikon lossless scheme; neither implementation applies a
demosaic, display stretch or bad-pixel filter here.
"""
from pathlib import Path
import argparse,hashlib,json,struct,subprocess,traceback
import numpy as np
import rawpy
from audit_nef import file_sha
ROOT=Path(__file__).resolve().parents[2];WSL=r'C:\Program Files\WSL\wsl.exe'
def need(test,msg):
    if not test:raise ValueError(msg)
def linux(p):
    p=str(Path(p).resolve());need(p[1:3]==':\\','Expected local drive');return '/mnt/'+p[0].lower()+'/'+p[3:].replace('\\','/')
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--audit',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    old=ROOT/'analysis/real-nef-2026-11-09/independent-lossless';pin=json.loads((old/'result.json').read_text())
    exe=old/'nikon-lossless14-check';source=old/'nikon_lossless14_check.cpp'
    need(file_sha(exe)==pin['executable_sha256'] and file_sha(source)==pin['cpp_sha256'],'Decoder changed')
    cases=[x for x in json.loads(a.audit.read_text(encoding='utf8'))['files'] if x['id']>=4856]
    report=dict(ok=False,scope=__doc__,audit_sha256=file_sha(a.audit),executable_sha256=file_sha(exe),cpp_sha256=file_sha(source),files=[])
    try:
        for case in cases:
            path=Path(case['path']);need(file_sha(path)==case['sha256'],'Input changed')
            strip=max(case['tiff']['raw_strips'],key=lambda v:v['width'][0]*v['height'][0])
            maker=[x for x in case['tiff']['ifds'] if x['label'].endswith('/Nikon')][0]
            need(maker['byte_order']=='<' and strip['bits']==[14],'Unsupported format')
            tag=maker['tags']['0x0096']
            with path.open('rb') as f:f.seek(tag['offset']);data=f.read(tag['bytes'])
            need(data[:2]==b'F0','Unsupported compression prefix');preds=struct.unpack_from('<4H',data,2)
            cmd=[WSL,'-d','Ubuntu-24.04','--',linux(exe),linux(path),str(strip['offset']),str(strip['size']),str(strip['width'][0]),str(strip['height'][0]),*map(str,preds)]
            with rawpy.imread(str(path)) as raw:wanted=raw.raw_image.astype('<u2',copy=False).tobytes()
            with (a.output/(path.stem+'.stderr.txt')).open('wb') as stderr:
                proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=stderr)
                position=0;mismatches=0;digest=hashlib.sha256()
                while True:
                    chunk=proc.stdout.read(1024*1024)
                    if not chunk:break
                    need(len(chunk)%2==0 and position+len(chunk)<=len(wanted),'Decoder size mismatch')
                    digest.update(chunk);mismatches+=int(np.count_nonzero(np.frombuffer(chunk,dtype='<u2')!=np.frombuffer(wanted[position:position+len(chunk)],dtype='<u2')))
                    position+=len(chunk)
                rc=proc.wait()
            need(rc==0 and position==len(wanted) and mismatches==0,'Independent decoding mismatch')
            need(digest.hexdigest()==case['stored_pixels_sha256'],'Pixel hash mismatch')
            need(file_sha(path)==case['sha256'],'Input changed during read')
            row=dict(name=path.name,source_sha256=case['sha256'],pixels=position//2,mismatches=mismatches,
                     pixels_sha256=digest.hexdigest(),argv=cmd,predictors=preds,returncode=rc)
            report['files'].append(row);print(json.dumps({k:v for k,v in row.items() if k!='argv'}),flush=True)
        report.update(ok=True,total_pixels=sum(x['pixels'] for x in report['files']))
    except Exception:report['error']=traceback.format_exc();raise
    finally:
        (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
        (a.output/Path(__file__).name).write_bytes(Path(__file__).read_bytes())
        (a.output/source.name).write_bytes(source.read_bytes())
    print(json.dumps(dict(ok=report['ok'],files=len(report['files']),total_pixels=report['total_pixels'])))
if __name__=='__main__':main()
