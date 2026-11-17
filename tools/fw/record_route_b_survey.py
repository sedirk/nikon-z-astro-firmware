"""Record Route B static frontend operator survey and candidate decision."""
from pathlib import Path
import argparse, json, struct
import numpy as np

ROOT = Path(__file__).resolve().parents[2]
ROUND = ROOT / 'analysis/raw-calibration-access-2026-11-10'

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)

    cal = (ROUND / 'camera-calibration-backup-v3/CAL38.bin').read_bytes()

    # 1. Compare all 22 records of CAL33 (0x47180) and CAL48 (0x47010)
    cal33_records = []
    for grp in range(11):
        for cat in range(2):
            off33 = 0x47180 + grp * 600 + cat * 300
            hdr = cal[off33:off33 + 36]
            vals = np.frombuffer(cal[off33 + 36:off33 + 300], dtype='<u2').reshape(33, 4)
            off48 = 0x47010 + grp * 32 + cat * 16
            r48 = cal[off48:off48 + 16]
            cal33_records.append(dict(
                group=grp, cat=cat, off33=hex(off33),
                hdr_u16=list(struct.unpack('<18H', hdr)),
                hdr_bytes_18_23=list(hdr[0x18:0x24]),
                row0=vals[0].tolist(), row8=vals[8].tolist(), row16=vals[16].tolist(), row17=vals[17].tolist(),
                min_nonzero=int(vals[vals > 0].min()) if np.any(vals > 0) else 0,
                max_val=int(vals.max()),
                r48_u16=list(struct.unpack('<8H', r48)),
                r48_bytes=list(r48[8:16])
            ))
    (a.output / 'cal33_and_cal48_records.json').write_text(json.dumps(cal33_records, indent=2), encoding='utf8')

    # 2. Operator functional classification in 0x1017d7b6
    survey = {
        'total_operators': 14,
        'function_range': '0x1017d7b6..0x1017d83e',
        'operators': [
            {'op': '01_1011d6b8', 'reads_cal': 'CAL38+0x5000..+0x5034', 'writes': 49, 'nz_writes': 3,
             'non_zero_registers': {'0x20068508': 8, '0x2006850c': 137136, '0x20068818': 1},
             'classification': 'Frame geometry / crop parameters (non-spatial)'},
            {'op': '02_1011db02', 'reads_cal': 'CAL38+0x5640..+0x56be', 'writes': 31, 'nz_writes': 10,
             'non_zero_registers': {'0x20068500': 8200, '0x20068548': 1316804, '0x2006854c': 400031744, '0x20068550': 16383, '0x20068560': 198706676, '0x20068564': 131072, '0x20068568': 1073692671, '0x2006856c': 9, '0x20068510': 600, '0x200685a0': 4095},
             'classification': 'Control thresholds / bit11 pre-flash suppression gate target (0x20068500: 0x2808 -> 0x2008 in modified4)'},
            {'op': '03_1011dce0', 'reads_cal': 'CAL38+0x293c0..+0x294c0 (256B, all 0)', 'writes': 64, 'nz_writes': 0,
             'classification': 'All-zero table upload to 0x20068a00..0x20068afc'},
            {'op': '04_1011de9e', 'reads_cal': 'CAL38+0x2db38..+0x2db84 (all 0)', 'writes': 23, 'nz_writes': 0,
             'classification': 'All-zero register upload to 0x200685b4..0x2006860c'},
            {'op': '05_1011e118', 'reads_cal': 'CAL38+0x2dbd0..+0x2dbda (all 0)', 'writes': 147, 'nz_writes': 0,
             'classification': 'All-zero table upload to 0x20068610..0x20068e3c'},
            {'op': '06_1011e150', 'reads_cal': 'CAL38+0x47020..+0x4702e', 'writes': 50, 'nz_writes': 3,
             'non_zero_registers': {'0x2006861c': 1073758208, '0x2006867c': 201329664, '0x200686dc': 65537},
             'classification': 'CAL48 header upload; 48-word table body is all 0'},
            {'op': '07_1011e2ce', 'reads_cal': 'CAL38+0x472ac..+0x473d8 (CAL33)', 'writes': 81, 'nz_writes': 46,
             'classification': 'CAL33 33x4 table body upload (4x17 words to 0x20068f00..8fc8) + 13 header/control registers (0x200686e4..8714). UNIQUE non-zero spatial curve table in static frontend.'},
            {'op': '08_1011e36a', 'reads_cal': 'CAL38+0x48dd0..+0x48dd4', 'writes': 48, 'nz_writes': 4,
             'classification': 'Sub-block 08 writing to shared 48-reg packet 0x20068718..0x200687d4'},
            {'op': '09_1011e494', 'reads_cal': 'CAL38+0x49654..+0x49656', 'writes': 48, 'nz_writes': 6,
             'classification': 'Sub-block 09 writing to shared 48-reg packet 0x20068718..0x200687d4'},
            {'op': '10_1011e58c', 'reads_cal': 'CAL38+0x49cd4..+0x49da0', 'writes': 48, 'nz_writes': 7,
             'classification': 'Sub-block 10 writing to shared 48-reg packet 0x20068718..0x200687d4'},
            {'op': '11_1011e6ba', 'reads_cal': 'CAL38+0x5808c..+0x580bf', 'writes': 48, 'nz_writes': 19,
             'classification': 'Sub-block 11 finalizing shared 48-reg packet 0x20068718..0x200687d4 (shift-invariant 9-tap local kernel weights)'},
            {'op': '12_1011e940', 'reads_cal': 'CAL38+0xbbe78..+0xbbe82', 'writes': 8, 'nz_writes': 2,
             'non_zero_registers': {'0x200687e8': 268439552, '0x200687ec': 268439552},
             'classification': 'Q12 unity gain scaling (4096 / 0x10001000)'},
            {'op': '13_1011eb1e', 'reads_cal': 'CAL38+0xbc560..+0xbc566', 'writes': 3, 'nz_writes': 0,
             'classification': 'All-zero upload to 0x200687f8..0x20068800'},
            {'op': '14_1011ebb8', 'reads_cal': 'CAL38+0xbc940..+0xbc94a', 'writes': 3, 'nz_writes': 1,
             'non_zero_registers': {'0x20068808': 1008},
             'classification': 'BlackLevel baseline 1008 upload'}
        ]
    }
    (a.output / 'operators_survey.json').write_text(json.dumps(survey, indent=2), encoding='utf8')

    # 3. Decision rationale
    decision = {
        'route_b_finding': 'Only operator 07_1011e2ce (CAL33) carries a non-zero, spatially varying multi-point curve table across the 14 frontend stages.',
        'table_mutation_rejected': 'Mutating the 33x4 table body to constant 16384 while leaving group 0 header attributes (+16=182, +1e=32, +18=1, +1a=1) produces an unobserved Frankenstein state not matching factory group 4-9 (+16=180, +1e=0, +18=0, +1a=0).',
        'single_variable_candidate': 'modified7',
        'target_control': 'CAL33 +0x1a (RAM 0xc29a3749 -> MMIO 0x20068704: 1 -> 0)',
        'baseline_restoration': '+0x18 restored to 1 (reverting modified6 back to modified4 baseline)',
        'code_modification': 'In 0x1017d7b6..0x1017d83e rearranged block, change movw r1, #0x3748 to #0x3749 at 0x1017d7f2. Exactly 1 byte instruction change vs modified6, 72 code bytes diff vs modified4, preserving ID35 transmission and all 10 inherited patches.'
    }
    (a.output / 'candidate_decision.json').write_text(json.dumps(decision, indent=2), encoding='utf8')
    print(json.dumps(dict(ok=True, records=len(cal33_records), operators=len(survey['operators']))))

if __name__ == '__main__':
    main()
