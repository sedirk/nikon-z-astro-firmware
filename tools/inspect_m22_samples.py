import pathlib
import rawpy
import numpy as np

sample_dir = pathlib.Path(__file__).resolve().parents[1] / 'samples' / '11.17_modified22'
nefs = sorted(sample_dir.glob('*.NEF'))

for p in nefs:
    with rawpy.imread(str(p)) as raw:
        arr = raw.raw_image_visible.astype(np.float64)
        bl = raw.black_level_per_channel
        # Channel 0: R, Channel 1: Gr, Channel 2: Gb, Channel 3: B
        r = arr[0::2, 0::2]
        # Extract EXIF Shutter Speed (0x829A) and ISO (0x8827)
        shutter = ""
        iso = ""
        b = p.read_bytes()[:0x10000]
        for off in range(0, len(b) - 12, 2):
            tag = int.from_bytes(b[off:off+2], 'little')
            typ = int.from_bytes(b[off+2:off+4], 'little')
            cnt = int.from_bytes(b[off+4:off+8], 'little')
            val = int.from_bytes(b[off+8:off+12], 'little')
            if tag == 0x829A and typ == 5:
                if val + 8 <= len(b):
                    num = int.from_bytes(b[val:val+4], 'little')
                    den = int.from_bytes(b[val+4:val+8], 'little')
                    shutter = f"{num}/{den}s" if den != 1 else f"{num}s"
            elif tag == 0x8827 and typ == 3:
                iso = f"ISO{val & 0xFFFF}"
        
        h, w = r.shape
        roi_r = r[h//4:3*h//4, w//4:3*w//4]
        med = np.median(roi_r)
        std = np.std(roi_r)
        hist, _ = np.histogram(roi_r.flatten(), bins=16384, range=(0, 16384))
        dft = np.abs(np.fft.rfft(hist.astype(np.float64)))
        idx = int(round(0.2276 * 16384))
        comb_val = dft[idx]
        peak_val = np.max(dft[int(0.22*16384):int(0.24*16384)])
        print(f"{p.name} | shutter={shutter:<8} | {iso:<7} | med={med:6.1f} | std={std:5.1f} | comb@0.2276={comb_val:8.0f} | peak={peak_val:8.0f}")
