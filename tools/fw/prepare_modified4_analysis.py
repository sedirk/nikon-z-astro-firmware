"""Fork the established flat method into a separate modified4 study; no old edits."""
from pathlib import Path
import hashlib, json

ROOT = Path(__file__).resolve().parents[2]
source = ROOT/'tools/fw/analyze_modified3_flats.py'
target = ROOT/'tools/fw/analyze_modified4_flats.py'
text = source.read_text(encoding='utf8')
replacements = [
    ('Compare real modified2/modified3 flats', 'Compare real modified3/modified4 flats'),
    ('Earlier modified2 repeats provide context, not paired controls.', 'No modified4 darks supplied; the flat comparison does not test dark suppression.'),
    ('from modified3_study_common import', 'from modified4_study_common import'),
    ("names=('modified2_flat','modified3_flat','modified2_earlier_flat')", "names=('modified3_flat','modified4_flat')"),
    ("old=np.load(ROOT/'analysis/modified2-flat-2026-11-09/cfa-comparison/maps.npz')\n    need(np.array_equal(codes[-2:],old['codes'][2:4]),'Earlier modified2 codes not reproduced')\n    need(np.array_equal(rs[-2:],old['ratios'][2:4]),'Earlier modified2 ratios not reproduced')\n    result['earlier_frozen_arrays_exact']=True",
     "old=np.load(ROOT/'analysis/modified3-real-2026-11-09/flats/maps.npz')\n    old_idx=[list(old['ids']).index(i) for i in GROUPS['modified3_flat']]\n    need(np.array_equal(codes[:3],old['codes'][old_idx]),'Frozen modified3 codes not reproduced')\n    need(np.array_equal(rs[:3],old['ratios'][old_idx]),'Frozen modified3 ratios not reproduced')\n    result['modified3_frozen_arrays_exact']=True"),
]
for before, after in replacements:
    if text.count(before) != 1:
        raise ValueError('Unexpected source text count: '+before)
    text = text.replace(before, after)
with target.open('x', encoding='utf8') as f:
    f.write(text)
print(json.dumps(dict(source=str(source), source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
    target=str(target), target_sha256=hashlib.sha256(target.read_bytes()).hexdigest(), replacements=len(replacements))))
