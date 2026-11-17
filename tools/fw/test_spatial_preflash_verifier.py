"""Reject incorrect copies/modes using local fixtures, never a camera or card."""
from pathlib import Path
import argparse,binascii,json,shutil,subprocess,sys
from verify_spatial_preflash_kit import PATHS,need,check_card_contents,check_kit
from review_spatial_preflash import ROOT

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--kit',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();out=a.output.resolve();need(out.is_relative_to(ROOT/'analysis'),'Fixture destination')
    out.mkdir(parents=True,exist_ok=False);card=out/'LOCAL_FIXTURE_NOT_A_CARD';card.mkdir();file=card/'EG162080.BIN';rows=[]
    check_kit(a.kit)
    def case(label,mode,want):
        try:detail=check_card_contents(card,mode);accepted=True
        except ValueError as exc:detail=dict(error=str(exc));accepted=False
        need(accepted==want,'Unexpected verifier result '+label)
        rows.append(dict(case=label,mode=mode,expected_accept=want,actual_accept=accepted,detail=detail))
    for source in PATHS:
        file.write_bytes((a.kit/PATHS[source]).read_bytes())
        for mode in PATHS:case(source+'_as_'+mode,mode,source==mode)
    candidate=(a.kit/PATHS['test']).read_bytes();file.write_bytes(candidate)
    extra=card/'Z_6_0380.BIN';extra.write_bytes(b'extra');case('two_files','test',False);extra.rename(card/'EXTRA.fixture')
    extra=card/'EG162080.BIN.bak';extra.write_bytes(b'extra');case('hidden_backup_extension','test',False);extra.rename(card/'BACKUP.fixture')
    wrong=card/'EG172080.BIN';file.rename(wrong);case('wrong_model_filename','test',False);wrong.rename(file)
    broken=bytearray(candidate);broken[0x177868]^=1;file.write_bytes(broken);case('one_byte_damage','test',False)
    broken[-2:]=binascii.crc_hqx(broken[:-2],0).to_bytes(2,'big');file.write_bytes(broken);case('wrong_bytes_valid_crc','test',False)
    file.write_bytes(b'truncated');case('truncated','test',False);file.rename(card/'TRUNCATED.fixture');case('empty_root','test',False)
    for label,args,message in (
        ('cli_nonroot',['--card-root',str(card),'--mode','test'],'actual Windows drive root'),
        ('cli_mode_without_card',['--mode','test'],'requires --card-root'),
        ('cli_card_without_mode',['--card-root',str(card)],'is required')):
        result=subprocess.run([sys.executable,'-O',str(a.kit/'verify.py'),'--kit',str(a.kit),*args],capture_output=True,text=True)
        need(result.returncode==1 and message in result.stderr,'CLI '+label)
        rows.append(dict(case=label,exit_code=result.returncode,stderr=result.stderr,python_optimized=True))
    bad=out/'BAD_MANIFEST_ONLY';bad.mkdir();manifest=json.loads((a.kit/'manifest.json').read_text())
    manifest['files'][0]['path']='../../outside.bin';(bad/'manifest.json').write_text(json.dumps(manifest),encoding='utf8')
    try:check_kit(bad)
    except ValueError as exc:need(str(exc)=='Unexpected manifest paths','Wrong manifest failure')
    else:raise ValueError('Traversal accepted')
    rows.append(dict(case='manifest_traversal',rejected=True))
    result=dict(ok=True,cases=rows,actual_card_accessed=False,physical_flash=False)
    (out/'result.json').write_text(json.dumps(result,indent=2),encoding='utf8')
    for name in (Path(__file__).name,'verify_spatial_preflash_kit.py'):shutil.copyfile(ROOT/'tools/fw'/name,out/name)
    print(json.dumps(dict(ok=True,cases=len(rows))))
if __name__=='__main__':main()
