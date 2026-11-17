"""Fail-closed delivery verifier checks on local fixtures, never an actual card."""
from pathlib import Path
import argparse,binascii,json,subprocess,sys
from verify_vignette_preflash_kit import PATHS,need,check_card_contents,check_kit
from review_vignette_preflash import ROOT


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kit',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();out=args.output.resolve();need(out.is_relative_to(ROOT/'analysis'),'Fixture destination')
    out.mkdir(parents=True,exist_ok=False);card=out/'LOCAL_FIXTURE_NOT_A_CARD';card.mkdir()
    file=card/'EG162080.BIN';rows=[]
    check_kit(args.kit)
    def case(label,mode,want):
        try:detail=check_card_contents(card,mode);accepted=True
        except ValueError as exc:detail=dict(error=str(exc));accepted=False
        need(accepted==want,'Unexpected verifier result: '+label)
        rows.append(dict(case=label,mode=mode,expected_accept=want,actual_accept=accepted,detail=detail))
    for source in PATHS:
        file.write_bytes((args.kit/PATHS[source]).read_bytes())
        for mode in PATHS:case(source+'_as_'+mode,mode,source==mode)
    candidate=(args.kit/PATHS['test']).read_bytes();file.write_bytes(candidate)
    extra=card/'Z_6_0380.BIN';extra.write_bytes(b'extra');case('two_firmware_files','test',False);extra.rename(card/'EXTRA.fixture')
    extra=card/'EG162080.BIN.bak';extra.write_bytes(b'extra');case('hidden_backup_extension','test',False);extra.rename(card/'BACKUP.fixture')
    wrong=card/'EG172080.BIN';file.rename(wrong);case('wrong_model_filename','test',False);wrong.rename(file)
    damaged=bytearray(candidate);damaged[0xa28b5]^=1;file.write_bytes(damaged);case('one_byte_damage','test',False)
    damaged[-2:]=binascii.crc_hqx(damaged[:-2],0).to_bytes(2,'big')
    file.write_bytes(damaged);case('wrong_bytes_even_with_repaired_crc','test',False)
    file.write_bytes(b'truncated');case('truncated_copy','test',False);file.rename(card/'TRUNCATED.fixture')
    for label,extra_args,message in (
        ('cli_nonroot',['--card-root',str(card),'--mode','test'],'actual Windows drive root'),
        ('cli_mode_without_card',['--mode','test'],'requires --card-root'),
        ('cli_card_without_mode',['--card-root',str(card)],'is required')):
        result=subprocess.run([sys.executable,'-O',str(args.kit/'verify.py'),'--kit',str(args.kit),*extra_args],capture_output=True,text=True)
        need(result.returncode==1 and message in result.stderr,'CLI validation failed: '+label)
        rows.append(dict(case=label,exit_code=result.returncode,stderr=result.stderr,python_optimized=True))
    # Manifest path injection is rejected before following or reading that path.
    kit_fixture=out/'BAD_MANIFEST_ONLY';kit_fixture.mkdir()
    manifest=json.loads((args.kit/'manifest.json').read_text())
    manifest['files'][0]['path']='../../outside.bin'
    (kit_fixture/'manifest.json').write_text(json.dumps(manifest),encoding='utf8')
    try:check_kit(kit_fixture)
    except ValueError as exc:need(str(exc)=='Unexpected manifest paths','Wrong manifest failure')
    else:raise ValueError('Manifest traversal accepted')
    rows.append(dict(case='manifest_paths_fail_closed',rejected=True))
    result=dict(ok=True,cases=rows,actual_card_accessed=False,physical_flash=False)
    (out/'result.json').write_text(json.dumps(result,indent=2),encoding='utf8')
    for name in (Path(__file__).name,'verify_vignette_preflash_kit.py'):
        (out/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    print(json.dumps(dict(ok=True,cases=len(rows),actual_card_accessed=False)))


if __name__=='__main__':main()
