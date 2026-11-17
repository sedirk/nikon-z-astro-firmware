"""Prepare a narrowly scoped numeric-control LAB recipe, never an install kit."""
from pathlib import Path
import json
from probe_raw_candidates import ROOT, sha

def main():
    output=ROOT/'patches/z6-c380-front-bit11-off-lab.json'
    assert not output.exists()
    catalog=json.loads((ROOT/'patches/z6-c380-spatial-neutral-lab.json').read_text())
    candidate=catalog['candidates'][0]
    candidate['id']='modified3-front-bit11-off-lab'
    catalog['status']='LAB ONLY: numeric front bit11 disable experiment; ISP stage identity and physical ring effect unresolved; not preflash reviewed'
    candidate['scope']='Inherit modified3 exactly. Replace only the static-exposure input read at 100f64b4 with native override value 2. Does not edit owner objects, shared policy builder, calibration payloads, updater or RAW pointers. Static exposure is not established to be NEF-exclusive.'
    candidate['intent']='Test a single front policy bit using the existing native off branch. This is not an identified ring-removal patch; zero synthetic calibration can already leave the bit clear.'
    candidate['edits'].append(dict(address='0x100f64b4',before='90f85902',after='4ff00200',
        instruction_before='ldrb.w r0, [r0, #0x259]',instruction_after='mov.w r0, #2',
        reason='Static input+45 -> context+5d -> original 1011d866 writes control[2]=0 -> master bit11 cleared; preserve original flags and source objects.'))
    catalog['physical_reference']=dict(version='modified3',sha256='a8ec90a9b55b2eefcd46e13b0f6acd0b7aa1bc4d9d127d701dee89154b8b04bd',
        report='docs/MODIFIED3_REAL_NEF_2026-11-09.md',result='Dark point regression retained; current screen-flat broad rings not overall improved.')
    output.write_text(json.dumps(catalog,indent=2),encoding='utf8')
    print(json.dumps(dict(recipe=str(output),sha256=sha(output.read_bytes()))))

if __name__=='__main__':main()
