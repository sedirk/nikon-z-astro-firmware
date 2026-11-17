import os, hashlib, binascii, json
from pathlib import Path

out_dir = Path(__file__).resolve().parent / "outputs" / "Z6-C380-production-modified9-2026-11-12"

manifest = {}
for slot in ['01_TEST_MODIFIED9', '02_DARK_ONLY_MODIFIED1', '03_PREVIOUS_MODIFIED4', '04_STOCK_C380']:
    p = os.path.join(out_dir, slot, 'EG162080.BIN')
    data = open(p, 'rb').read()
    sha = hashlib.sha256(data).hexdigest()
    crc = binascii.crc_hqx(data, 0)
    manifest[f"{slot}/EG162080.BIN"] = {
        "sha256": sha,
        "size": len(data),
        "crc_check": crc == 0
    }
    print(f"{slot}: sha256={sha}, size={len(data)}, crc_check={crc==0}")

with open(os.path.join(out_dir, 'manifest.json'), 'w', encoding='utf-8') as f:
    json.dump(manifest, f, indent=2)

sha_mod9 = manifest['01_TEST_MODIFIED9/EG162080.BIN']['sha256']
sha_mod1 = manifest['02_DARK_ONLY_MODIFIED1/EG162080.BIN']['sha256']
sha_mod4 = manifest['03_PREVIOUS_MODIFIED4/EG162080.BIN']['sha256']
sha_stock = manifest['04_STOCK_C380/EG162080.BIN']['sha256']

verify_content = f'''"""Self-contained offline verifier for Nikon Z6 C3.80 Modified9 Production Package."""
import hashlib, binascii, json, sys
from pathlib import Path

DIR = Path(__file__).resolve().parent

EXPECTED = {{
    "01_TEST_MODIFIED9/EG162080.BIN": "{sha_mod9}",
    "02_DARK_ONLY_MODIFIED1/EG162080.BIN": "{sha_mod1}",
    "03_PREVIOUS_MODIFIED4/EG162080.BIN": "{sha_mod4}",
    "04_STOCK_C380/EG162080.BIN": "{sha_stock}",
}}

print("=== VERIFYING NIKON Z6 MODIFIED9 PRODUCTION PACKAGE ===")
all_ok = True
for rel, h_exp in EXPECTED.items():
    f = DIR / rel
    if not f.exists():
        print("[FAIL] Missing file:", rel)
        all_ok = False
        continue
    data = f.read_bytes()
    if len(data) != 33502842:
        print(f"[FAIL] {{rel}} size mismatch: got {{len(data)}}, expected 33502842")
        all_ok = False
    crc = binascii.crc_hqx(data, 0)
    if crc != 0:
        print(f"[FAIL] {{rel}} CRC16 invalid: {{crc:#x}}")
        all_ok = False
    h_act = hashlib.sha256(data).hexdigest()
    if h_act != h_exp:
        print(f"[FAIL] {{rel}} SHA-256 mismatch: got {{h_act}}, expected {{h_exp}}")
        all_ok = False
    else:
        print(f"[PASS] {{rel}}: OK (CRC=0, SHA256 matches)")

if all_ok:
    print("\\nALL INTEGRITY CHECKS PASSED SUCCESSFULLY!")
else:
    print("\\nINTEGRITY CHECKS FAILED!")
    sys.exit(1)
'''

with open(os.path.join(out_dir, 'verify.py'), 'w', encoding='utf-8') as f:
    f.write(verify_content)

recipe = {
    "candidate": "modified9",
    "base": "stock_eg1620_038000.bi",
    "base_sha256": "1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c",
    "target_sha256": sha_mod9,
    "total_modified_bytes": 83,
    "patches": [
        {
            "name": "dark_current_preserve_hp_clamp1",
            "address": "0x100c2654",
            "original_hex": "00f065fa",
            "patched_hex": "4ff00000",
            "description": "Replace BL 0x100c2b22 with MOV.W r0, #0 (proven dark current restoration from modified1)"
        },
        {
            "name": "dark_current_preserve_hp_clamp2",
            "address": "0x100c267c",
            "original_hex": "00f045fa",
            "patched_hex": "4ff00200",
            "description": "Replace BL 0x100c2b0a with MOV.W r0, #2 (proven dark current restoration from modified1)"
        },
        {
            "name": "dark_current_preserve_hp_clamp3",
            "address": "0x100c2690",
            "original_hex": "90f81a18",
            "patched_hex": "4ff00201",
            "description": "Replace LDRB.W r1, [r0, #2074] with MOV.W r1, #2 (proven dark current restoration from modified1)"
        },
        {
            "name": "safe_shading_unity_helper",
            "address": "0x1002d884",
            "length": 68,
            "original_hex": "00" * 68,
            "patched_hex": "0f4900223c2341f82320013bfbd144f200028a620a65c1f8a020c1f8c82042f22002c2f22002c1f8f4202022a1f8f8200022c1f8fc20a1f8fa200120eff042be54379ac2",
            "description": "Safe in-place shading sanitizer in unreferenced alignment hole. Zeroes 54 radial polynomial terms, sets R, G1, B, G2 DC gains to 16384 (1.000000), sets crosstalk gains to 0, sets top exponents to 0x20, leaves optical center and descriptors intact, tail-calls 0x1011d548 with r0=1."
        },
        {
            "name": "static_builder_tail_hook",
            "address": "0x1017d834",
            "original_hex": "01209ff787fe",
            "patched_hex": "b0f626f8c046",
            "description": "In static front-end builder 0x1017d7b6 (called exclusively during static NEF capture), after all 14 factory operators (ops 01..14) have executed natively and populated all DMA descriptors, hook call to 0x1011d548 via BL 0x1002d884 + NOP."
        },
        {
            "name": "module_crc16",
            "address": "0x12013678",
            "original_hex": "f92d",
            "patched_hex": "5f74",
            "description": "Standard CRC-CCITT (0x1021) checksum at module tail"
        }
    ]
}

with open(os.path.join(out_dir, 'patch-recipe.json'), 'w', encoding='utf-8') as f:
    json.dump(recipe, f, indent=2)

print('Generated manifest.json, verify.py, and patch-recipe.json successfully!')
