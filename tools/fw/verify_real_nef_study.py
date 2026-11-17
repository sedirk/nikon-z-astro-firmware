"""Check evidence integrity, independent unpack, metadata bridges and originals."""
from pathlib import Path
from collections import Counter
import argparse, hashlib, json, struct
import numpy as np
import rawpy
from audit_nef import file_sha

ROOT=Path(__file__).resolve().parents[2]
BASE=ROOT/'analysis/real-nef-2026-11-09'

def load(p):return json.loads(Path(p).read_text(encoding='utf8'))

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();assert not a.output.exists()
    baseline=load(ROOT/'analysis/raw-nef-save-2026-11-08/verification.json')
    report=dict(ok=False,script_sha256=file_sha(__file__),immutable={},counts={},representative_copies=[])
    for path,expected in baseline['immutable'].items():
        actual=file_sha(ROOT/path);assert actual==expected;report['immutable'][path]=actual
    frames=load(BASE/'cfa/result.json');assert frames['ok'] and len(frames['frames'])==166
    assert Counter(x['kind'] for x in frames['frames'])==Counter(flat=37,light30=127,light10=1,dark_other_body=1)
    total=0;independent=0;independent_files=[]
    for entry in frames['frames']:
        r=load(ROOT/entry['result']);out=Path(ROOT/entry['result']).parent
        assert entry['sha256']==r['sha256'] and entry['source_stat_unchanged'] and r['source_stat_unchanged']
        assert r['black_level']==[1008]*4 and r['white_level']==16383
        assert file_sha(out/'cfa.npz')==entry['bin_sha256']
        with np.load(out/'cfa.npz') as z:
            h=z['histograms'];assert h.shape==(4,65536)
            assert np.all(h.sum(axis=1,dtype=np.uint64)==6048*4024//4)
            assert z['mean'].shape==z['median'].shape==(4,125,189)
            assert np.isfinite(z['mean']).all() and np.isfinite(z['median']).all()
            for i,q in enumerate(r['phases']):
                assert q['zero_count']==int(h[i,0])
                assert q['below_metadata_black']==int(h[i,:1008].sum())
                mean=np.dot(h[i].astype(np.float64),np.arange(65536))/q['n']
                assert abs(mean-q['mean'])<1e-10
            total+=int(h.sum())
        if 'independent_unpack' in r:
            v=r['independent_unpack'];assert v['mismatches']==0
            assert (v['row_stride'],v['raw_bytes'],v['pixels'])==(10624,42920960,24498560)
            independent+=v['pixels'];independent_files.append(r['name'])
        if 'local_copy' in r:
            # Hash both NAS originals and the six copies after analysis.
            local=file_sha(r['local_copy']);source=file_sha(r['source'])
            assert local==source==r['sha256']
            report['representative_copies'].append(dict(name=r['name'],sha256=source,bytes=r['bytes']))
    assert len(report['representative_copies'])==6 and len(independent_files)==5
    native=load(BASE/'native-contract-ready/result.json')
    assert native['ok'] and native['original_preserved'] and native['candidate_preserved']
    assert len(native['geometry'])==2 and len(native['files'])==6
    for v in native['files']:
        assert v['exact_vignette_payload_match'] and v['exact_black_payload_match']
        assert v['generated']['bytes']==v['info']['entries']['0x6']['bytes']
        assert bytes.fromhex(v['black_payload']['bytes'])==struct.pack('<4H',*([1008]*4))
    series=load(BASE/'nefinfo-series.json');assert series['ok'] and len(series['files'])==166
    assert {x['name'] for x in series['files']}=={x['name'] for x in frames['frames']}
    plots=load(BASE/'diagnostics-float-bins/result.json');assert plots['groups']==dict(flat=37,dark_other_body=1,light10=1,light30=127)
    assert plots['light30']['method']['spatial']=='float mean'
    for row in plots['input_hashes']:
        folder=BASE/'cfa'/row['name'][:-4]
        assert file_sha(folder/'result.json')==row['result_sha256']
        assert file_sha(folder/'cfa.npz')==row['bins_sha256']
    dark=load(BASE/'bias-dark/result.json');ceiling=load(BASE/'neighborhood-ceiling/result.json')
    decoder=load(BASE/'independent-lossless/result.json')
    assert dark['ok'] and dark['sources_unchanged'] and ceiling['ok'] and decoder['ok']
    assert len(dark['files'])==len(decoder['files'])==5
    independent_dark=0;images={}
    for row in dark['files']:
        digest=file_sha(row['path']);assert digest==row['sha256']==ceiling['input_hashes'][row['name']]
        decoded=next(x for x in decoder['files'] if x['name']==row['name'])
        assert decoded['source_sha256']==digest and decoded['pixels_sha256']==row['full_pixels_sha256']
        assert decoded['mismatches']==0 and decoded['pixels']==24498560
        independent_dark+=decoded['pixels']
        with rawpy.imread(row['path']) as raw:images[row['name']]=raw.raw_image.copy()
    assert ceiling['total_selected']==sum(x['selected_sites'] for x in ceiling['phases'])==112
    assert ceiling['selected_dark_both_equal_max']==sum(x['selected_both_dark_equal_max'] for x in ceiling['phases'])==31
    assert ceiling['selected_bias_all_strict_max']==112
    checked_points=0
    for phase in ceiling['phases']:
        for point in phase['examples']:
            y,x=point['raw_y'],point['raw_x']
            for i,name in enumerate(images):
                q=images[name][y-2:y+3:2,x-2:x+3:2]
                assert q.tolist()==point['same_cfa_patches'][i]
                assert int(q[1,1])==point['centres'][i]
                neighbors=q.reshape(-1)[[0,1,2,3,5,6,7,8]]
                assert int(neighbors.max())==point['neighbor_maxima'][i]
            checked_points+=1
    phases=[(0,0),(0,1),(1,0),(1,1)]
    means=np.asarray([[q[8+dy:4032:2,8+dx:6056:2].mean(dtype=np.float64) for dy,dx in phases] for q in images.values()])
    assert np.max(np.abs(means-np.asarray(dark['file_mean_codes'])))<1e-9
    delta=means[3:].mean(axis=0)-means[:3].mean(axis=0)
    assert np.max(np.abs(delta-[p['delta']['mean'] for p in dark['phases']] ))<1e-9
    modelroot=ROOT/'work/src/z6-qemu-419a1f2a91a1f2d3a0209027c29606475f7fe26f/qemu'
    report['model_sources']={}
    for name,digest in baseline['model_sources'].items():
        assert file_sha(modelroot/name)==digest;report['model_sources'][name]=digest
    report.update(ok=True,counts=dict(files=171,cropped_cfa_pixels=total+5*6048*4024,
        independently_unpacked_pixels=independent+independent_dark,packed_independent_files=independent_files,
        lossless_independent_files=[x['name'] for x in decoder['files']],metadata_roundtrips=6,native_geometry_cases=2,
        bright_bias_sites_reduced_in_both_darks=112,both_dark_values_equal_neighbor_max=31,
        neighborhood_examples_rechecked_against_source=checked_points),
        source_bytes=frames['total_source_bytes'],copied_bytes=sum(x['bytes'] for x in report['representative_copies']),
        nas_policy='All accesses read-only; all 166 retain same size/mtime during analysis; six representative full hashes rechecked afterwards. All five new local samples rehashed.',
        scientific_scope='Existing camera samples and native metadata/geometry contracts. Candidate firmware pixel effects are a separate validation.')
    a.output.write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf8')
    print(json.dumps({k:report[k] for k in ['ok','counts','copied_bytes']},indent=2))

if __name__=='__main__':main()
