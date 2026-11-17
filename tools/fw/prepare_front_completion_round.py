"""Open a new evidence round after user-confirmed physical recovery; keep frozen rounds unchanged."""
from pathlib import Path
import datetime,hashlib,json,subprocess

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'analysis/raw-front-completion-2026-11-10'

def main():
    OUT.mkdir(parents=True,exist_ok=True)
    backup=OUT/'progress-before';backup.mkdir(exist_ok=False)
    for name in ('README.md','docs/PROJECT_GOALS.md','docs/NEXT_STEPS.md'):
        p=ROOT/name;(backup/name.replace('/','-')).write_bytes(p.read_bytes())
    report=dict(local_date='2026-11-10',recorded_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        user_statement='现已恢复，请沿着已有记录继续探究，请往实现破解固件真正生产收敛；最终目标是保留暗电流、关闭静态NEF写入前的RAW校正并消除彩圈。',
        recovered=True,evidence_level='User-reported physical recovery after the preceding rollback instructions.',
        expected_recovery='modified4 as recommended; no new on-camera hash measurement or NEF supplied in this reply.',
        causal_scope='Strengthens regression association with the four modified5 edit ranges, not attribution to a specific instruction or hardware block.',
        recalled_modified5_stays_recalled=True,new_flash_performed_by_assistant=False)
    (OUT/'physical-recovery.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf8')
    (OUT/'git-status-before.txt').write_bytes(subprocess.run(['git','status','--short'],cwd=ROOT,capture_output=True,check=True).stdout)
    result=subprocess.run(['powershell','-NoProfile','-Command',"Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -match 'VID_04B0' -or $_.FriendlyName -match 'Nikon' } | Select-Object Class,FriendlyName,InstanceId,Status | ConvertTo-Json -Depth 3"],capture_output=True)
    (OUT/'nikon-device-inventory.stdout').write_bytes(result.stdout);(OUT/'nikon-device-inventory.stderr').write_bytes(result.stderr)
    assert result.returncode==0
    (OUT/'device-inventory.json').write_text(json.dumps(dict(exit_code=0,nikon_match_present=bool(result.stdout.strip()),read_only_pnp_inventory=True,usb_commands_sent=False),indent=2),encoding='utf8')
    print(json.dumps(dict(ok=True,recovery_reported=True,nikon_match_present=bool(result.stdout.strip()))))

if __name__=='__main__':main()
