"""Recovery-copy rejection checks using local fixtures, never a real card."""
from pathlib import Path
import argparse, binascii, json, subprocess, sys
from verify_modified5_recovery import PATHS, REVOKED, check_card, check_kit, need
from record_modified5_failure import ROOT


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--kit',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();out=a.output.resolve();need(out.is_relative_to(ROOT/'analysis'),'Local fixture destination')
    out.mkdir(parents=True,exist_ok=False);card=out/'LOCAL_FIXTURE_NOT_A_CARD';card.mkdir()
    file=card/'EG162080.BIN';rows=[];check_kit(a.kit)
    def case(name,mode,expected,message=None):
        try:detail=check_card(card,mode);accepted=True
        except ValueError as exc:detail=dict(error=str(exc));accepted=False
        need(accepted==expected,'Unexpected acceptance: '+name)
        if message:need(message in detail.get('error',''),'Wrong rejection: '+name)
        rows.append(dict(name=name,mode=mode,expected_accept=expected,accepted=accepted,detail=detail))
    for source in PATHS:
        file.write_bytes((a.kit/PATHS[source]).read_bytes())
        for mode in PATHS:case(source+'_as_'+mode,mode,source==mode)
    recalled=ROOT/'analysis/modified5-failure-2026-11-10/quarantine/modified5-EG162080.BIN.RECALLED'
    file.write_bytes(recalled.read_bytes())
    for mode in PATHS:case('recalled_m5_as_'+mode,mode,False,'RECALLED modified5')
    original=(a.kit/PATHS['modified4']).read_bytes();file.write_bytes(original)
    for index,name in enumerate(('Z_6_0380.BIN','EG162080.BIN.bak','extra.bi','old.LAB')):
        extra=card/name;extra.write_bytes(b'fixture');case('extra_'+name,'modified4',False,'exactly one')
        extra.rename(card/('discard_'+str(index)+'.fixture'))
    wrong=card/'EG172080.BIN';file.rename(wrong);case('wrong_model_filename','modified4',False);wrong.rename(file)
    corrupt=bytearray(original);corrupt[0x100]^=1;file.write_bytes(corrupt);case('damaged_bytes','modified4',False,'hash')
    corrupt[-2:]=binascii.crc_hqx(corrupt[:-2],0).to_bytes(2,'big')
    file.write_bytes(corrupt);case('damaged_bytes_recomputed_crc','modified4',False,'hash')
    file.write_bytes(b'truncated');case('truncated','modified4',False,'size')
    file.rename(card/'TRUNCATED.fixture');case('no_firmware','modified4',False,'exactly one')
    for label,args,expected,fragment in (
        ('cli_kit',[],0,'"ok": true'),
        ('cli_non_root',['--card-root',str(card),'--mode','modified4'],1,'actual Windows drive root'),
        ('cli_mode_without_card',['--mode','modified4'],1,'requires --card-root'),
        ('cli_card_without_mode',['--card-root',str(card)],1,'is required')):
        p=subprocess.run([sys.executable,'-O',str(a.kit/'verify.py'),'--kit',str(a.kit),*args],capture_output=True,text=True)
        need(p.returncode==expected and fragment in p.stdout+p.stderr,label)
        rows.append(dict(name=label,exit_code=p.returncode,stdout=p.stdout,stderr=p.stderr,optimized=True))
    target=ROOT/'outputs/RECALL_GUARD_TEST_MUST_NOT_EXIST';need(not target.exists(),'Guard fixture exists')
    p=subprocess.run([sys.executable,'-O',str(ROOT/'tools/fw/package_id35_preflash.py'),'--output',str(target)],capture_output=True,text=True)
    need(p.returncode!=0 and 'RECALLED modified5' in p.stderr and not target.exists(),'Old packager recall gate')
    rows.append(dict(name='old_packager_rejects_recalled_hash',exit_code=p.returncode,stderr=p.stderr,no_output_created=True))
    for name in (Path(__file__).name,'verify_modified5_recovery.py','package_id35_preflash.py'):
        (out/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    (out/'result.json').write_bytes(json.dumps(dict(ok=True,cases=rows,revoked_sha256=REVOKED,actual_card_accessed=False,physical_flash=False),indent=2).encode('utf8'))
    print(json.dumps(dict(ok=True,cases=len(rows))))


if __name__=='__main__':main()
