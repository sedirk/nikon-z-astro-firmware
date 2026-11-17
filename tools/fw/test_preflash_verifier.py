"""Exercise fail-closed card selection checks on disposable local fixtures."""
from pathlib import Path
import argparse,json,shutil,subprocess,sys
from verify_preflash_kit import check_card_contents,need
ROOT=Path(__file__).resolve().parents[2]

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();out=a.output.resolve();need(out.is_relative_to(ROOT/'analysis'),'Fixtures must stay in analysis')
    out.mkdir(parents=True,exist_ok=False);card=out/'LOCAL_FIXTURE_NOT_A_CARD';card.mkdir()
    kit=ROOT/'outputs/Z6-C380-preflash-reviewed-2026-11-09';file=card/'EG162080.BIN'
    shutil.copyfile(kit/'01_TEST/EG162080.BIN',file);rows=[]
    def case(label,mode,want):
        try:r=check_card_contents(card,mode);passed=True
        except ValueError as exc:r=dict(error=str(exc));passed=False
        need(passed==want,'Unexpected verifier outcome: '+label)
        rows.append(dict(case=label,expected_accept=want,actual_accept=passed,detail=r))
    case('candidate_bytes','test',True)
    case('candidate_mistaken_for_rollback','rollback',False)
    extra=card/'Z_6_0380.bin';extra.write_bytes(b'x');case('mixed_firmware_files','test',False)
    extra.rename(card/'EXTRA.fixture')
    wrong=card/'WRONG.BIN';file.rename(wrong);case('wrong_filename','test',False);wrong.rename(file)
    with file.open('r+b') as f:
        f.seek(0xa2654);old=f.read(1);f.seek(0xa2654);f.write(bytes([old[0]^1]))
    case('one_byte_damaged','test',False)
    file.write_bytes(b'not a firmware');case('truncated_copy','test',False)
    # Keep the final damaged fixture out of a .BIN filename after testing.
    file.rename(card/'TRUNCATED.fixture')
    result=subprocess.run([sys.executable,'-O',str(kit/'verify.py'),'--card-root',str(card),'--mode','test'],capture_output=True,text=True)
    need(result.returncode==1 and 'actual Windows drive root' in result.stderr,'CLI did not enforce root')
    rows.append(dict(case='cli_nonroot_path_rejected_even_with_python_O',exit_code=result.returncode,stderr=result.stderr))
    (out/'result.json').write_text(json.dumps(dict(ok=True,cases=rows,actual_card_accessed=False),indent=2),encoding='utf8')
    (out/Path(__file__).name).write_bytes(Path(__file__).read_bytes())
    print(json.dumps(dict(ok=True,cases=len(rows),actual_card_accessed=False)))
if __name__=='__main__':main()
