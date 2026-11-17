import struct, subprocess, os, sys, json
from pathlib import Path
import numpy as np

ROOT = Path(__file__).resolve().parents[2]
WSL = r'C:\Program Files\WSL\wsl.exe'

def linux_path(p):
    p = str(Path(p).resolve())
    return '/mnt/' + p[0].lower() + '/' + p[3:].replace('\\', '/')

DECODER = linux_path(ROOT / 'analysis/real-nef-2026-11-09/independent-lossless/nikon-lossless14-check')
def decode_nef(path):
    path = Path(path)
    with path.open('rb') as f:
        header = f.read(8)
        order = '<' if header[:2] == b'II' else '>'
        ifd0_offset = struct.unpack_from(order + 'I', header, 4)[0]
        
        strip_offset = None
        strip_size = None
        strip_w = None
        strip_h = None
        preds = None
        
        def scan_ifd(pos, base):
            nonlocal strip_offset, strip_size, strip_w, strip_h, preds
            f.seek(pos)
            cnt = struct.unpack(order + 'H', f.read(2))[0]
            entries = f.read(cnt * 12 + 4)
            sub_links = []
            values = {}
            for i in range(cnt):
                entry = entries[i*12:(i+1)*12]
                tag, kind, count, ptr = struct.unpack(order + 'HHII', entry)
                widths = {1:1, 2:1, 3:2, 4:4, 5:8, 6:1, 7:1, 8:2, 9:4, 10:8, 11:4, 12:8, 13:4}
                if kind in widths:
                    length = count * widths[kind]
                    off = pos + 2 + i*12 + 8 if length <= 4 else base + ptr
                    cur_pos = f.tell()
                    f.seek(off)
                    payload = f.read(length)
                    f.seek(cur_pos)
                    if count <= 16:
                        fmt = {1:'B',3:'H',4:'I',8:'h',9:'i'}.get(kind)
                        if fmt:
                            values[tag] = list(struct.unpack(order + str(count) + fmt, payload))
                    if tag in (0x014a, 0x8769, 0x8825, 0xa005):
                        targets = list(struct.unpack(order + str(count) + 'I', payload))
                        for t in targets:
                            sub_links.append((base + t, base))
                    if tag == 0x927c and payload.startswith(b'Nikon\x00\x02'):
                        makerbase = off + 10
                        cur_p = f.tell()
                        f.seek(makerbase)
                        mb_hdr = f.read(8)
                        mo = '<' if mb_hdr[:2] == b'II' else '>'
                        mf = struct.unpack_from(mo + 'I', mb_hdr, 4)[0]
                        sub_links.append((makerbase + mf, makerbase))
                        f.seek(cur_p)
                    if tag == 0x0096:
                        if payload[:2] == b'F0':
                            preds = struct.unpack_from('<4H', payload, 2)
            if values.get(0x106) == [32803] and 0x111 in values and 0x117 in values:
                w = values.get(0x100, [0])[0]
                h = values.get(0x101, [0])[0]
                if w > 4000:
                    strip_offset = base + values[0x111][0]
                    strip_size = values[0x117][0]
                    strip_w = w
                    strip_h = h
            for target, b in sub_links:
                scan_ifd(target, b)
        scan_ifd(ifd0_offset, 0)

    lp = linux_path(path)
    cmd = [WSL, '-d', 'Ubuntu-24.04', '--', DECODER, lp,
           str(strip_offset), str(strip_size), str(strip_w), str(strip_h),
           *map(str, preds)]
    
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    raw_bytes, stderr = proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"Decode failed for {path}: {stderr.decode()}")
    
    arr = np.frombuffer(raw_bytes, dtype=np.uint16).reshape((strip_h, strip_w))
    return arr

def calc_stats(arr, black=1008):
    h, w = arr.shape
    # Channels: RGGB
    # (0,0)=R, (0,1)=G1, (1,0)=G2, (1,1)=B
    res = {
        'min': int(arr.min()),
        'max': int(arr.max()),
        'mean': float(arr.mean()),
        'std': float(arr.std()),
        'below_black': int(np.count_nonzero(arr < black)),
        'at_zero': int(np.count_nonzero(arr == 0)),
        'channels': {}
    }
    channels = [('R', 0, 0), ('G1', 0, 1), ('G2', 1, 0), ('B', 1, 1)]
    for name, dy, dx in channels:
        ch = arr[dy::2, dx::2]
        res['channels'][name] = {
            'mean': float(ch.mean()),
            'std': float(ch.std()),
            'min': int(ch.min()),
            'max': int(ch.max())
        }
    return res

if __name__ == '__main__':
    samples_dir = ROOT / 'samples/11.13_modified9'
    results = {}

    for nef in sorted(samples_dir.glob('*.NEF')):
        print(f"Decoding {nef.name}...", flush=True)
        arr = decode_nef(nef)
        st = calc_stats(arr)
        results[nef.name] = st
        print(f"  {nef.name}: mean={st['mean']:.2f}, std={st['std']:.2f}, min={st['min']}, max={st['max']}, below_black={st['below_black']}, at_zero={st['at_zero']}")
        for ch_name, ch_st in st['channels'].items():
            print(f"    {ch_name}: mean={ch_st['mean']:.2f}, std={ch_st['std']:.2f}")

    out_json = ROOT / 'analysis/raw-shading-unity-modified9-2026-11-12/samples_stats.json'
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(results, indent=2))
    print("Done! Saved to", out_json)

