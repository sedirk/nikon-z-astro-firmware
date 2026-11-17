"""Read real NEFs without postprocess; preserve CFA statistics, bins and hashes.

Groups are specific to the explicitly supplied 2026-10-06/07 sample set. The
second body's capped dark is separate, never subtracted from the 85mm samples.
No alignment, demosaic, white balance, lens correction or black clamp is used.
"""
from pathlib import Path
import argparse, datetime, hashlib, io, json, platform, time
import numpy as np
import rawpy
from audit_nef import stats

def sha(b): return hashlib.sha256(b).hexdigest()

def packed_check(blob, meta, pixels):
    """Independent padded-row LSB 14-bit unpack; compare every stored pixel."""
    h,w=pixels.shape
    start=int(meta['SubIFD1:StripOffsets']); size=int(meta['SubIFD1:StripByteCounts'])
    stride=size//h
    assert size==stride*h and stride==((w*14+7)//8+15)//16*16
    packed=np.frombuffer(blob,dtype=np.uint8,count=size,offset=start).reshape(h,stride)
    mismatches=0; first=[]
    weights=(1 << np.arange(14,dtype=np.uint16))
    for y in range(0,h,64):
        n=min(64,h-y)
        bits=np.unpackbits(packed[y:y+n],axis=1,bitorder='little')[:,:w*14]
        decoded=(bits.reshape(n,w,14)*weights).sum(axis=2,dtype=np.uint16)
        bad=decoded!=pixels[y:y+n]
        mismatches+=int(bad.sum())
        if bad.any() and not first:
            first=[dict(y=int(iy+y),x=int(ix),independent=int(decoded[iy,ix]),libraw=int(pixels[y+iy,ix]))
                   for iy,ix in np.argwhere(bad)[:8]]
    return dict(raw_offset=start,raw_bytes=size,row_stride=stride,raw_sha256=sha(memoryview(blob)[start:start+size]),
        pixels=int(pixels.size),mismatches=mismatches,first_mismatches=first,packing='14-bit LSB, row padded to 16 bytes')

def kind(meta):
    n=meta['System:FileName']
    if n=='Z61_4850.NEF': return 'dark_other_body'
    if int(n[4:8])>=3086:return 'flat'
    return 'light30' if float(meta['ExifIFD:ExposureTime'])==30 else 'light10'

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--metadata',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args(); a.output.mkdir(parents=True,exist_ok=False)
    root=Path(__file__).resolve().parents[2]
    rows=json.loads(a.metadata.read_text(encoding='utf8'))
    # Flats first so downstream diagnostics can start while stars are decoded.
    rows.sort(key=lambda m: (dict(flat=0,dark_other_body=1,light10=2,light30=3)[kind(m)],m['System:FileName']))
    chosen={'DSC_2958.NEF','DSC_3022.NEF','DSC_3085.NEF','DSC_3086.NEF','DSC_3122.NEF','Z61_4850.NEF'}
    independent=chosen-{'Z61_4850.NEF'}
    sample_root=root/'samples/nas-2026-11-09'; sample_root.mkdir(parents=True,exist_ok=False)
    report=dict(scope=__doc__,source_metadata_sha256=sha(a.metadata.read_bytes()),
        script_sha256=sha(Path(__file__).read_bytes()),
        rawpy=rawpy.__version__,libraw=rawpy.libraw_version,numpy=np.__version__,python=platform.python_version(),
        started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),frames=[])
    for i,m in enumerate(rows):
        started=time.monotonic(); path=Path(m['SourceFile']); name=m['System:FileName']; group=kind(m)
        st=path.stat(); blob=path.read_bytes(); digest=sha(blob)
        assert len(blob)==st.st_size
        out=a.output/name[:-4]; out.mkdir(exist_ok=False)
        frame=dict(name=name,source=str(path),kind=group,sha256=digest,bytes=len(blob),source_mtime_ns=st.st_mtime_ns,
            metadata=m,script_sha256=report['script_sha256'])
        with rawpy.imread(io.BytesIO(blob)) as r:
            pixels=r.raw_image; s=r.sizes._asdict(); black=np.asarray(r.black_level_per_channel)
            assert pixels.shape==(4040,6064) and pixels.dtype==np.uint16
            assert r.raw_pattern.tolist()==[[0,1],[3,2]]
            x,y,w,h=[s[k] for k in ['crop_left_margin','crop_top_margin','crop_width','crop_height']]
            assert (x,y,w,h)==(8,8,6048,4024)
            crop=pixels[y:y+h,x:x+w]
            # Symmetric 12-row trim at top/bottom, gives exact 32x32 bins.
            by=y+12; bh=h-24; bw=w; tile=pixels[by:by+bh,x:x+bw]
            assert bh%32==bw%32==0
            frame.update(raw_shape=list(pixels.shape),crop=dict(x=x,y=y,width=w,height=h),
                bin_roi=dict(x=x,y=by,width=bw,height=bh,sensor_bin=32,cfa_samples_per_bin=256),
                raw_pixels_sha256=sha(pixels.astype('<u2',copy=False).tobytes()),
                black_level=black.tolist(),white_level=r.white_level,cfa_pattern=r.raw_pattern.tolist(),phases=[])
            hist=[]; means=[]; medians=[]; rowmeans=[]; colmeans=[]
            for dy,dx,ch in [(0,0,0),(0,1,1),(1,0,3),(1,1,2)]:
                q=crop[dy::2,dx::2]
                c=np.bincount(q.ravel(),minlength=65536).astype(np.uint32); hist.append(c)
                frame['phases'].append(dict(phase=[dy,dx],channel_index=ch,**stats(q,int(black[ch]))))
                z=tile[dy::2,dx::2].reshape(bh//32,16,bw//32,16)
                means.append(z.mean(axis=(1,3),dtype=np.float64))
                medians.append(np.median(z.transpose(0,2,1,3).reshape(bh//32,bw//32,256),axis=2))
                rowmeans.append(q.mean(axis=1,dtype=np.float64)); colmeans.append(q.mean(axis=0,dtype=np.float64))
            np.savez_compressed(out/'cfa.npz',histograms=np.stack(hist),mean=np.stack(means),median=np.stack(medians),
                row_mean=np.stack(rowmeans),column_mean=np.stack(colmeans))
            if name in independent:frame['independent_unpack']=packed_check(blob,m,pixels)
            if group=='dark_other_body':
                frame['confirmed_capped_by_user']=True
                frame['below_black_total']=sum(v['below_metadata_black'] for v in frame['phases'])
                frame['pixels_total']=int(crop.size)
                frame['below_black_fraction']=frame['below_black_total']/frame['pixels_total']
        after=path.stat()
        assert (after.st_size,after.st_mtime_ns)==(st.st_size,st.st_mtime_ns)
        frame['source_stat_unchanged']=True
        if name in chosen:
            target=sample_root/name
            with target.open('xb') as f: assert f.write(blob)==len(blob)
            assert sha(target.read_bytes())==digest
            frame['local_copy']=str(target)
        frame['elapsed_seconds']=round(time.monotonic()-started,3)
        (out/'result.json').write_text(json.dumps(frame,indent=2,ensure_ascii=False),encoding='utf8')
        report['frames'].append({k:frame[k] for k in ['name','kind','source','sha256','bytes','source_mtime_ns','source_stat_unchanged']})
        report['frames'][-1]['result']=str(out/'result.json')
        report['frames'][-1]['bin_sha256']=sha((out/'cfa.npz').read_bytes())
        report['frames'][-1]['elapsed_seconds']=frame['elapsed_seconds']
        (a.output/'progress.json').write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf8')
        print(f'{i+1}/{len(rows)} {name} {group} {frame["elapsed_seconds"]}s independent={frame.get("independent_unpack",{}).get("mismatches")}',flush=True)
    report.update(completed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),ok=True,
        local_copies=sorted(chosen),total_source_bytes=sum(f['bytes'] for f in report['frames']))
    (a.output/'result.json').write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf8')
    (sample_root/'manifest.json').write_text(json.dumps(dict(scope='Verified byte-identical copies; NAS originals left in place',
        source_report=str(a.output/'result.json'),files=[f for f in report['frames'] if f['name'] in chosen]),
        indent=2,ensure_ascii=False),encoding='utf8')
    assert all(json.loads((a.output/n[:-4]/'result.json').read_text(encoding='utf8'))['independent_unpack']['mismatches']==0 for n in independent)

if __name__=='__main__':main()
