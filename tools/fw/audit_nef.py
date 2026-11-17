"""Read-only NEF inventory and stored RAW-code comparison (no postprocess).

Statistics describe file samples, not untouched sensor charge. A flat radial
profile includes lighting/optics; it is not an automatic ring-correction verdict.
"""
from pathlib import Path
import argparse, hashlib, json, struct
import numpy as np
import rawpy

def sha(data): return hashlib.sha256(data).hexdigest()

def file_sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
    return h.hexdigest()


def tiff_inventory(path):
    """Bounded classic-TIFF/NEF reader; never follows arbitrary embedded code."""
    path=Path(path); size=path.stat().st_size
    result=dict(file_bytes=size,ifds=[],raw_strips=[])
    seen=set()
    with path.open('rb') as f:
        def read(pos,n):
            if not (0<=pos<=size and 0<=n<=size-pos):raise ValueError(('out-of-file',pos,n,size))
            f.seek(pos);data=f.read(n)
            if len(data)!=n:raise ValueError('short file')
            return data
        def endian_at(base):
            b=read(base,8)
            order={b'II':'<',b'MM':'>'}.get(b[:2])
            if order is None or struct.unpack_from(order+'H',b,2)[0]!=42:raise ValueError('classic TIFF required')
            return order,struct.unpack_from(order+'I',b,4)[0]
        def walk(pos,base,order,label,depth=0):
            if pos==base or (pos,base) in seen:return
            if depth>12 or len(seen)>128:raise ValueError('IFD traversal bound')
            seen.add((pos,base));n=struct.unpack(order+'H',read(pos,2))[0]
            if n>4096:raise ValueError('IFD entry bound')
            table=read(pos+2,n*12+4);tags={};values={};links=[]
            for i in range(n):
                entry=table[i*12:i*12+12];tag,kind,count,ptr=struct.unpack(order+'HHII',entry)
                widths={1:1,2:1,3:2,4:4,5:8,6:1,7:1,8:2,9:4,10:8,11:4,12:8,13:4}
                item=dict(type=kind,count=count)
                tags[f'0x{tag:04x}']=item
                if kind not in widths:continue
                length=count*widths[kind]
                if length>16*1024*1024:raise ValueError('metadata length bound')
                offset=pos+2+i*12+8 if length<=4 else base+ptr
                payload=read(offset,length)
                item.update(offset=offset,bytes=length,sha256=sha(payload))
                if count<=128:
                    fmt={1:'B',3:'H',4:'I',6:'b',8:'h',9:'i',13:'I'}.get(kind)
                    if fmt:values[tag]=list(struct.unpack(order+str(count)+fmt,payload));item['value']=values[tag]
                    elif kind==2:item['text']=payload.rstrip(b'\0').decode('utf-8','replace')
                    elif length<=64:item['hex']=payload.hex()
                if tag in (0x014a,0x8769,0x8825,0xa005):
                    for j,target in enumerate(values.get(tag,[])):
                        if target:links.append((base+target,base,order,f'{label}/{tag:04x}[{j}]'))
                if tag==0x927c and payload.startswith(b'Nikon\0\x02') and length>=18:
                    makerbase=offset+10;mo,mf=endian_at(makerbase)
                    links.append((makerbase+mf,makerbase,mo,f'{label}/Nikon'))
            result['ifds'].append(dict(label=label,offset=pos,offset_base=base,byte_order=order,tags=tags))
            if values.get(0x106)==[32803] and 0x111 in values and 0x117 in values:
                starts,counts=values[0x111],values[0x117]
                if len(starts)!=len(counts):raise ValueError('strip count mismatch')
                for start,count in zip(starts,counts):
                    start+=base
                    if not 0<=start<=start+count<=size:raise ValueError('raw strip bounds')
                    f.seek(start);h=hashlib.sha256();remain=count
                    while remain:
                        block=f.read(min(remain,1024*1024))
                        if not block:raise ValueError('short raw strip')
                        h.update(block);remain-=len(block)
                    result['raw_strips'].append(dict(ifd=label,offset=start,size=count,sha256=h.hexdigest(),
                        width=values.get(0x100),height=values.get(0x101),bits=values.get(0x102),compression=values.get(0x103)))
            for args in links:walk(*args,depth+1)
            nxt=struct.unpack_from(order+'I',table,n*12)[0]
            if nxt:walk(base+nxt,base,order,label+'/next',depth+1)
        order,first=endian_at(0);walk(first,0,order,'IFD0')
    return result


def stats(a,black):
    counts=np.bincount(a.reshape(-1),minlength=65536)
    occupied=np.flatnonzero(counts);n=int(counts.sum());cdf=np.cumsum(counts)
    levels=np.arange(65536,dtype=np.float64)
    mean=float(np.dot(counts,levels)/n)
    variance=float(np.dot(counts,(levels-mean)**2)/n)
    return dict(n=n,min=int(occupied[0]),max=int(occupied[-1]),mean=mean,std=variance**0.5,
        quantiles={str(q):int(np.searchsorted(cdf,max(1,int(np.ceil(n*q))))) for q in (.001,.01,.5,.99,.999)},
        zero_count=int(counts[0]),below_metadata_black=int(counts[:max(0,min(65536,int(black)))].sum()),
        metadata_black=int(black))


def flat_profile(a,pattern,black):
    # Cell averages over 64x64 sensor pixels, then 32 annuli about image centre.
    # Subtract only metadata for this derived profile; stored pixels stay intact.
    h,w=a.shape;out=[]
    for dy in range(2):
        for dx in range(2):
            channel=int(pattern[dy,dx]);plane=a[dy::2,dx::2]
            ny,nx=plane.shape[0]//32,plane.shape[1]//32
            if min(ny,nx)<2:return []
            cells=plane[:ny*32,:nx*32].reshape(ny,32,nx,32).mean(axis=(1,3))-black[channel]
            yy=(np.arange(ny)*64+31+dy-(h-1)/2)/((h-1)/2)
            xx=(np.arange(nx)*64+31+dx-(w-1)/2)/((w-1)/2)
            rr=np.sqrt(yy[:,None]**2+xx[None,:]**2)
            bins=np.minimum((rr/np.sqrt(2)*32).astype(int),31)
            vals=[]
            for k in range(32):
                v=cells[bins==k];vals.append(float(np.median(v)) if v.size else None)
            out.append(dict(phase=[dy,dx],channel_index=channel,median_signal_by_radius=vals))
    return out


def audit(path,kind='unknown'):
    path=Path(path).resolve(strict=True);before=file_sha(path)
    result=dict(path=str(path),kind_supplied_by_user=kind,sha256=before,size=path.stat().st_size,
        rawpy=rawpy.__version__,libraw=list(rawpy.libraw_version),numpy=np.__version__,
        interpretation='Stored NEF code values after LibRaw unpack, no demosaic/postprocess. File pixels may already include camera processing.')
    result['tiff']=tiff_inventory(path)
    with rawpy.imread(str(path)) as raw:
        a=raw.raw_image;v=raw.raw_image_visible;pattern=raw.raw_pattern
        if a.ndim!=2 or pattern is None or pattern.shape!=(2,2):raise ValueError('requires 2x2 Bayer input')
        black=raw.black_level_per_channel;s=raw.sizes._asdict()
        visible_pattern=raw.raw_colors_visible[:2,:2].copy()
        result.update(sizes=s,raw_shape=list(a.shape),visible_shape=list(v.shape),
            stored_pixels_sha256=sha(a.astype('<u2',copy=False).tobytes()),
            visible_pixels_sha256=sha(v.astype('<u2',copy=False).tobytes()),
            black_level=black,white_level=raw.white_level,white_per_channel=raw.camera_white_level_per_channel,
            cfa_pattern=pattern.tolist(),visible_cfa_pattern=visible_pattern.tolist(),color_desc=raw.color_desc.decode('ascii'),phases=[])
        result['recommended_crop_within_raw']=(0<=s['crop_left_margin'] and 0<=s['crop_top_margin'] and
            s['crop_left_margin']+s['crop_width']<=s['raw_width'] and
            s['crop_top_margin']+s['crop_height']<=s['raw_height'])
        for dy in range(2):
            for dx in range(2):
                ch=int(visible_pattern[dy,dx])
                result['phases'].append(dict(phase=[dy,dx],channel_index=ch,**stats(v[dy::2,dx::2],black[ch])))
        if kind=='flat':
            result['flat_radial_profile']=flat_profile(v,visible_pattern,black)
            result['flat_profile_caveat']='Lighting and optical shading remain; one flat is not a hardcoded-ring detection test.'
    result['source_unchanged']=file_sha(path)==before
    assert result['source_unchanged']
    return result


def compare(first,second):
    with rawpy.imread(str(first)) as x,rawpy.imread(str(second)) as y:
        a,b=x.raw_image,y.raw_image
        if a.shape!=b.shape:return dict(comparable=False,reason='different stored RAW dimensions')
        changed=0;delta_min=65535;delta_max=-65535;total=0
        for start in range(0,a.shape[0],128):
            delta=b[start:start+128].astype(np.int32)-a[start:start+128].astype(np.int32)
            changed+=int(np.count_nonzero(delta));total+=int(delta.sum(dtype=np.int64))
            delta_min=min(delta_min,int(delta.min()));delta_max=max(delta_max,int(delta.max()))
        return dict(comparable=True,changed_pixels=changed,total_pixels=int(a.size),
            delta_b_minus_a_min=delta_min,delta_b_minus_a_max=delta_max,mean_delta=total/a.size,
            same_metadata_black=x.black_level_per_channel==y.black_level_per_channel,
            interpretation='Exact stored-code difference; independent exposures also differ from noise and scene changes.')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('files',nargs='+',type=Path)
    p.add_argument('--kind',choices=['unknown','bias','dark','flat','light','fixture'],default='unknown')
    p.add_argument('--output',required=True,type=Path)
    p.add_argument('--compare',action='store_true')
    a=p.parse_args()
    if a.output.exists():p.error('output exists')
    if a.compare and len(a.files)!=2:p.error('--compare requires two inputs')
    result=dict(scope=__doc__,script_sha256=file_sha(__file__),files=[audit(f,a.kind) for f in a.files])
    if a.compare:result['comparison']=compare(*a.files)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding='utf-8')
    print(json.dumps(dict(files=len(result['files']),output=str(a.output),comparison=result.get('comparison'))))


if __name__=='__main__':main()
