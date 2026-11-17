import json, sys
from pathlib import Path
import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(ROOT / 'tools/fw'))
from analyze_modified9_samples import decode_nef

# Compare the exact raw pixel difference between FLAT shots!
# 4945 is modified9 flat.
# Let's inspect the 2D spatial pattern across rows and columns.
f45 = decode_nef(str(ROOT / 'samples/11.13_modified9/Z61_4945.NEF'))
f46 = decode_nef(str(ROOT / 'samples/11.13_modified9/Z61_4946.NEF'))
f47 = decode_nef(str(ROOT / 'samples/11.13_modified9/Z61_4947.NEF'))

print("FLAT 4945 mean:", f45.mean())
print("FLAT 4946 mean:", f46.mean())
print("FLAT 4947 mean:", f47.mean())

# Check PDAF pixel lines (Sony IMX410 has masked PDAF pixels every 12th row):
# In modified1 / stock / modified9, are PDAF rows present?
# PDAF rows have distinct values:
diff_rows = np.abs(np.diff(f45[0::2, 0::2].mean(axis=1)))
print("Row modulation max:", diff_rows.max(), "mean:", diff_rows.mean())
