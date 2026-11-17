"""Create Modified11 patch recipe from Modified10."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
m10_recipe = json.loads((ROOT / 'patches/z6-c380-modified10-fullsize-convergence.json').read_text(encoding='utf8'))

m11_recipe = dict(m10_recipe)
m11_recipe['parent_candidate'] = 'modified10-fullsize-front-raw-spatial-neutral'
m11_recipe['parent_sha256'] = '85b1889bb82c81cdd42cfa4358e72cab12598882f7453a8dbea70ffe9ef6deb4'

cand = dict(m10_recipe['candidates'][0])
cand['id'] = 'modified11-production-convergence'
cand['scope'] = 'Inherit Modified10 (12 sites: dark preserve 3 sites, vignette neutral 3 sites, spatial17 neutral 3 sites, frontend 2D unity sanitizer 2 sites, fullsize front raw preserve 1 site). Add 1-site front-end 4-channel digital gain unity lock at 0x10122cba (18 bytes).'
cand['intent'] = 'Achieve final production convergence for Nikon Z6 C3.80 Astro Firmware: (1) preserve dark current and hot pixels without neighborhood clamping, (2) bypass all backend ISP and neutralize front-end 2D polynomial shading, (3) neutralize front-end 4-channel digital multipliers to 1.0x unity gain (Q12=0x1000=4096) to completely eliminate histogram comb teeth (missing codes) and concentric chromatic rings.'

new_edit = dict(
    group='modified11_frontend_digital_gain_unity',
    address='0x10122cba',
    before='41b1086818604868586088689860c868d860',
    after='41f20000186058609860d86000bf00bf00bf',
    instruction_before='cbz r1, #0x10122cce; ldr r0, [r1]; str r0, [r3]; ldr r0, [r1, #4]; str r0, [r3, #4]; ldr r0, [r1, #8]; str r0, [r3, #8]; ldr r0, [r1, #0xc]; str r0, [r3, #0xc]',
    instruction_after='movw r0, #0x1000; str r0, [r3]; str r0, [r3, #4]; str r0, [r3, #8]; str r0, [r3, #0xc]; nop; nop; nop'
)

cand['edits'] = cand['edits'] + [new_edit]
cand['edits'].sort(key=lambda e: int(e['address'], 16))
m11_recipe['candidates'] = [cand]

out_path = ROOT / 'patches/z6-c380-modified11-production-convergence.json'
out_path.write_text(json.dumps(m11_recipe, indent=2, ensure_ascii=False), encoding='utf8')
print('Successfully created', out_path)
print('Total edits in Modified11:', len(cand['edits']))
for i, e in enumerate(cand['edits']):
    addr = e['address']
    grp = e['group']
    print(f'  {i+1:2d}. {addr}: {grp}')
