import json, sys
from pathlib import Path
import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(ROOT / 'tools/fw'))
from analyze_modified9_samples import decode_nef

# Let's inspect the 2D radial structure of FLATs in modified9 vs modified4
flat9 = decode_nef(str(ROOT / 'samples/11.13_modified9/Z61_4945.NEF'))
flat4 = decode_nef(str(ROOT / 'samples/11.10_modified4/Z61_4910.NEF'))

# In modified4 (stock shading table), Red and Blue channels have polynomial curves
# In modified9 (clean unity), Red and Blue are NOT multiplied by the 2D polynomial!
# Let's check center vs edge ratio:
def get_vignetting(arr, black=1008):
    h, w = arr.shape
    cy, cx = h // 2, w // 2
    # Center box 200x200
    center_r = arr[cy-100:cy+100:2, cx-100:cx+100:2].mean() - black
    center_g = (arr[cy-100:cy+100:2, cx-99:cx+100:2].mean() + arr[cy-99:cy+100:2, cx-100:cx+100:2].mean()) / 2.0 - black
    center_b = arr[cy-99:cy+100:2, cx-99:cx+100:2].mean() - black
    
    # Corner box 200x200 (top-left)
    corner_r = arr[50:250:2, 50:250:2].mean() - black
    corner_g = (arr[50:250:2, 51:250:2].mean() + arr[51:250:2, 50:250:2].mean()) / 2.0 - black
    corner_b = arr[51:250:2, 51:250:2].mean() - black
    
    return {
        'center': {'R': center_r, 'G': center_g, 'B': center_b, 'R/G': center_r/center_g, 'B/G': center_b/center_g},
        'corner': {'R': corner_r, 'G': corner_g, 'B': corner_b, 'R/G': corner_r/corner_g, 'B/G': corner_b/corner_g},
        'falloff': {'R': corner_r/center_r, 'G': corner_g/center_g, 'B': corner_b/center_b}
    }

vig9 = get_vignetting(flat9)
vig4 = get_vignetting(flat4)

print("=== VIGNETTING / CORNER FALLOFF COMPARISON ===")
print("Modified9 Falloff (Corner / Center):")
print(f"  R: {vig9['falloff']['R']:.4f}, G: {vig9['falloff']['G']:.4f}, B: {vig9['falloff']['B']:.4f}")
print("Modified4 Falloff (Corner / Center):")
print(f"  R: {vig4['falloff']['R']:.4f}, G: {vig4['falloff']['G']:.4f}, B: {vig4['falloff']['B']:.4f}")
