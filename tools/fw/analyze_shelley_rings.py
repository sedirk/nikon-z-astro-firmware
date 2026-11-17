import json, sys
from pathlib import Path
import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(ROOT / 'tools/fw'))
from analyze_modified9_samples import decode_nef

# Let's inspect concentric rings using 2D annular differential!
# In Mark Shelley's analysis of Nikon concentric rings:
# The rings are concentric color ripples in the R/G and B/G ratio.
# Let's compute the difference of R/G with respect to a smoothed polynomial across radius r:

def analyze_shelley_rings(nef_path, num_bins=128):
    arr = decode_nef(nef_path)
    h, w = arr.shape
    cy, cx = (h - 1) / 2.0, (w - 1) / 2.0
    r_max = np.sqrt(cy**2 + cx**2)
    
    # Extract R and G
    r_plane = arr[0::2, 0::2].astype(np.float64) - 1008
    g_plane = (arr[0::2, 1::2].astype(np.float64) + arr[1::2, 0::2].astype(np.float64)) / 2.0 - 1008
    b_plane = arr[1::2, 1::2].astype(np.float64) - 1008
    
    sh, sw = r_plane.shape
    by, bx = 16, 16
    ny, nx = sh // by, sw // bx
    
    r_cells = r_plane[:ny*by, :nx*bx].reshape(ny, by, nx, bx).mean(axis=(1, 3))
    g_cells = g_plane[:ny*by, :nx*bx].reshape(ny, by, nx, bx).mean(axis=(1, 3))
    b_cells = b_plane[:ny*by, :nx*bx].reshape(ny, by, nx, bx).mean(axis=(1, 3))
    
    yy = (np.arange(ny) * 32 + 15 - cy) / cy
    xx = (np.arange(nx) * 32 + 15 - cx) / cx
    rr = np.sqrt(yy[:, None]**2 + xx[None, :]**2)
    
    bins = np.minimum((rr / np.sqrt(2) * num_bins).astype(int), num_bins - 1)
    
    r_profile = []
    g_profile = []
    b_profile = []
    radii = []
    
    for b in range(num_bins):
        mask = (bins == b)
        if np.any(mask):
            radii.append(float(np.mean(rr[mask])))
            r_profile.append(float(np.median(r_cells[mask])))
            g_profile.append(float(np.median(g_cells[mask])))
            b_profile.append(float(np.median(b_cells[mask])))
        else:
            radii.append(b / num_bins * np.sqrt(2))
            r_profile.append(0.0)
            g_profile.append(0.0)
            b_profile.append(0.0)
            
    r_profile = np.array(r_profile)
    g_profile = np.array(g_profile)
    b_profile = np.array(b_profile)
    
    rg_ratio = np.divide(r_profile, g_profile, out=np.zeros_like(r_profile), where=g_profile>10)
    bg_ratio = np.divide(b_profile, g_profile, out=np.zeros_like(b_profile), where=g_profile>10)
    
    # To detect Shelley rings: high-pass filter or polynomial subtraction of R/G and B/G!
    # Fit degree-3 smooth background
    valid = (rg_ratio > 0.1) & (np.array(radii) < 1.0)
    x = np.array(radii)[valid]
    
    poly_rg = np.poly1d(np.polyfit(x, rg_ratio[valid], 3))
    residual_rg = rg_ratio[valid] - poly_rg(x)
    
    poly_bg = np.poly1d(np.polyfit(x, bg_ratio[valid], 3))
    residual_bg = bg_ratio[valid] - poly_bg(x)
    
    # Peak-to-peak ripple and RMS of ripple
    p2p_rg = float(np.ptp(residual_rg))
    rms_rg = float(np.sqrt(np.mean(residual_rg**2)))
    p2p_bg = float(np.ptp(residual_bg))
    rms_bg = float(np.sqrt(np.mean(residual_bg**2)))
    
    return {
        'rms_rg': rms_rg,
        'p2p_rg': p2p_rg,
        'rms_bg': rms_bg,
        'p2p_bg': p2p_bg,
        'radii': list(x),
        'residual_rg': list(residual_rg),
        'residual_bg': list(residual_bg)
    }

print("Analyzing Shelley Rings on FLATs:")
ring_m9 = analyze_shelley_rings(str(ROOT / 'samples/11.13_modified9/Z61_4945.NEF'))
print(f"Modified9 (4945): R/G ripple RMS={ring_m9['rms_rg']:.6f} (P2P={ring_m9['p2p_rg']:.6f}), B/G ripple RMS={ring_m9['rms_bg']:.6f} (P2P={ring_m9['p2p_bg']:.6f})")

ring_m7 = analyze_shelley_rings(str(ROOT / 'samples/11.12_modified7/Z61_4928.NEF'))
print(f"Modified7 (4928): R/G ripple RMS={ring_m7['rms_rg']:.6f} (P2P={ring_m7['p2p_rg']:.6f}), B/G ripple RMS={ring_m7['rms_bg']:.6f} (P2P={ring_m7['p2p_bg']:.6f})")

ring_m4 = analyze_shelley_rings(str(ROOT / 'samples/11.10_modified4/Z61_4910.NEF'))
print(f"Modified4 (4910): R/G ripple RMS={ring_m4['rms_rg']:.6f} (P2P={ring_m4['p2p_rg']:.6f}), B/G ripple RMS={ring_m4['rms_bg']:.6f} (P2P={ring_m4['p2p_bg']:.6f})")
