import json, sys
from pathlib import Path
import numpy as np

# Load decoder function from analyze_modified9_samples
ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(ROOT / 'tools/fw'))
from analyze_modified9_samples import decode_nef

def get_radial_profile(arr, black=1008, num_bins=32):
    h, w = arr.shape
    channels = {'R': (0, 0), 'G1': (0, 1), 'G2': (1, 0), 'B': (1, 1)}
    cy, cx = (h - 1) / 2.0, (w - 1) / 2.0
    r_max = np.sqrt(cy**2 + cx**2)
    
    profiles = {}
    for ch_name, (dy, dx) in channels.items():
        sub = arr[dy::2, dx::2].astype(np.float64) - black
        sub_h, sub_w = sub.shape
        
        # Grid of coordinates
        # Block average 32x32 to be fast and robust against noise
        by, bx = sub_h // 32, sub_w // 32
        cells = sub[:by*32, :bx*32].reshape(by, 32, bx, 32).mean(axis=(1, 3))
        
        yy = (np.arange(by) * 64 + 31 + dy - cy) / cy
        xx = (np.arange(bx) * 64 + 31 + dx - cx) / cx
        rr = np.sqrt(yy[:, None]**2 + xx[None, :]**2) # 0 at center, 1 at edge, sqrt(2) at corner
        
        bins = np.minimum((rr / np.sqrt(2) * num_bins).astype(int), num_bins - 1)
        meds = []
        for b in range(num_bins):
            val = cells[bins == b]
            meds.append(float(np.median(val)) if len(val) else 0.0)
        profiles[ch_name] = meds
    return profiles

# Let's compare FLATs of modified9 with FLATs of modified4 and modified7!
mod9_flat = decode_nef(str(ROOT / 'samples/11.13_modified9/Z61_4945.NEF'))
prof_mod9 = get_radial_profile(mod9_flat)

mod7_flat = decode_nef(str(ROOT / 'samples/11.12_modified7/Z61_4928.NEF'))
prof_mod7 = get_radial_profile(mod7_flat)

mod4_flat = decode_nef(str(ROOT / 'samples/11.10_modified4/Z61_4910.NEF'))
prof_mod4 = get_radial_profile(mod4_flat)

out = {
    'modified9_4945': prof_mod9,
    'modified7_4928': prof_mod7,
    'modified4_4910': prof_mod4
}

# Print Red / Green ratio and Blue / Green ratio across radius!
# In factory / modified4 / modified7, R/G and B/G fluctuate with radius (concentric rings).
# In pure optical lens shading (clean RAW), R/G and B/G are virtually smooth/flat or monotonically varying with lens vignetting, with ZERO oscillating ripple!
print("=== RADIAL COLOR RATIOS (R/G and B/G) ===")
print("Radius bin | Mod4 R/G   Mod4 B/G | Mod7 R/G   Mod7 B/G | Mod9 R/G   Mod9 B/G")
for b in range(0, 32, 2):
    g_m4 = (prof_mod4['G1'][b] + prof_mod4['G2'][b]) / 2.0
    r_m4 = prof_mod4['R'][b] / g_m4 if g_m4 > 0 else 0
    b_m4 = prof_mod4['B'][b] / g_m4 if g_m4 > 0 else 0
    
    g_m7 = (prof_mod7['G1'][b] + prof_mod7['G2'][b]) / 2.0
    r_m7 = prof_mod7['R'][b] / g_m7 if g_m7 > 0 else 0
    b_m7 = prof_mod7['B'][b] / g_m7 if g_m7 > 0 else 0
    
    g_m9 = (prof_mod9['G1'][b] + prof_mod9['G2'][b]) / 2.0
    r_m9 = prof_mod9['R'][b] / g_m9 if g_m9 > 0 else 0
    b_m9 = prof_mod9['B'][b] / g_m9 if g_m9 > 0 else 0
    
    print(f"{b:2d}         | {r_m4:.4f}   {b_m4:.4f} | {r_m7:.4f}   {b_m7:.4f} | {r_m9:.4f}   {b_m9:.4f}")

out_path = ROOT / 'analysis/raw-shading-unity-modified9-2026-11-12/flat_ring_comparison.json'
out_path.write_text(json.dumps(out, indent=2))
print("Saved comparison to", out_path)
