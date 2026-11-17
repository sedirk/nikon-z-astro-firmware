import json, sys
from pathlib import Path
import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(ROOT / 'tools/fw'))
from analyze_modified9_samples import decode_nef

# Compare DARK Z61_4951 (5s, ISO 1600, modified9) with:
# - modified7 DARK: Z61_4925 (5s, ISO 1600)
# - modified4 DARK: Z61_4914
# - stock / modified1 DARK

dark9 = decode_nef(str(ROOT / 'samples/11.13_modified9/Z61_4951.NEF'))
dark7 = decode_nef(str(ROOT / 'samples/11.12_modified7/Z61_4925.NEF'))

def dark_audit(arr, name):
    # Pixels above 2000 (hot pixels)
    hot_pixels = int(np.count_nonzero(arr > 2000))
    hot_max = int(arr.max())
    below_1008 = int(np.count_nonzero(arr < 1008))
    mean = float(arr.mean())
    std = float(arr.std())
    print(f"{name}: mean={mean:.3f}, std={std:.3f}, min={arr.min()}, max={hot_max}, hot_pixels(>2000)={hot_pixels}, below_black={below_1008}")

dark_audit(dark9, "Modified9 DARK 4951")
dark_audit(dark7, "Modified7 DARK 4925")

# Compare BIAS Z61_4948 (1/8000s, ISO 1600, modified9) with modified7 BIAS Z61_4922
bias9 = decode_nef(str(ROOT / 'samples/11.13_modified9/Z61_4948.NEF'))
bias7 = decode_nef(str(ROOT / 'samples/11.12_modified7/Z61_4922.NEF'))

def bias_audit(arr, name):
    below_1008 = int(np.count_nonzero(arr < 1008))
    print(f"{name}: mean={arr.mean():.3f}, std={arr.std():.3f}, min={arr.min()}, max={arr.max()}, below_black={below_1008}")

bias_audit(bias9, "Modified9 BIAS 4948")
bias_audit(bias7, "Modified7 BIAS 4922")
