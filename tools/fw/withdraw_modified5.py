"""Recall the failed ready-to-flash artifacts after preparing verified recovery."""
from pathlib import Path
import json
from record_modified5_failure import ROOT,ROUND,KIT,OLD,M5,sha,write,rec
from verify_modified5_recovery import check_kit

def main():
    (KIT/'verify.py').write_bytes((ROOT/'tools/fw/verify_modified5_recovery.py').read_bytes())
    (KIT/'START_HERE.txt').write_bytes((ROOT/'docs/Z6_MODIFIED5_RECOVERY_2026-11-10.txt').read_bytes())
    check_kit(KIT)
    quarantine=ROUND/'quarantine';quarantine.mkdir(exist_ok=False);moves=[]
    for source,name,expected in (
       (OLD/'01_TEST_MODIFIED5/EG162080.BIN','modified5-EG162080.BIN.RECALLED',M5),
       (OLD.with_suffix('.zip'),'Z6-C380-id35-static-2026-11-09.RECALLED.zip','bf76b45c572d41765142e823767d342bd3868c3f1dcdbb4a2103def18e620d11')):
        source=source.resolve(strict=True);target=(quarantine/name).resolve()
        assert source.is_relative_to(ROOT/'outputs') and target.is_relative_to(ROUND/'quarantine')
        assert source.is_file() and not target.exists() and sha(source.read_bytes())==expected
        oldpath=source.relative_to(ROOT).as_posix();source.rename(target)
        assert sha(target.read_bytes())==expected
        moves.append(dict(old_path=oldpath,new_path=target.relative_to(ROOT).as_posix(),sha256=expected,bytes=target.stat().st_size))
    notice='''2026-11-10：modified5 已撤回，禁止再次安装。
实机报告按快门卡住、Err并自动重启。原离线通过记录保留为历史，不代表实机通过。
测试固件和原ZIP已移动到 analysis/modified5-failure-2026-11-10/quarantine，字节和哈希保持。
请使用 outputs/Z6-C380-recovery-from-modified5-2026-11-10 内的恢复文件及其verify.py。
本目录旧verify.py会因测试固件已撤回而失败，这是预期行为；回退校验请用新恢复包。
'''
    (OLD/'RECALLED_2026-11-10.txt').write_bytes(notice.encode('utf8'))
    (OLD/'01_TEST_MODIFIED5/RECALLED_DO_NOT_INSTALL.txt').write_bytes(notice.encode('utf8'))
    for name in ('README.md','docs/PROJECT_GOALS.md','docs/NEXT_STEPS.md'):
        p=ROOT/name;old=p.read_bytes();backup=(ROUND/'progress-before'/name.replace('/','-')).read_bytes();assert old==backup
        title,tail=old.decode('utf8').replace('\r\n','\n').split('\n',1)
        link='docs/Z6_MODIFIED5_RECOVERY_2026-11-10.txt' if name=='README.md' else 'Z6_MODIFIED5_RECOVERY_2026-11-10.txt'
        add=f'\n**2026-11-10 紧急更新：modified5 因实机快门卡住、Err／重启循环已撤回。** 原离线审查不覆盖该实机故障；停止重复测试。先用[恢复说明]({link})恢复逐字节等同modified4的文件，保留已验证暗场补丁。当前优先级是确认恢复正常、定位ID35控制与完成时序，后续取消基于“单次复跑成功”放行的做法。以下为历史状态。\n'
        p.write_bytes((title+'\n'+add+tail).encode('utf8'))
    write(ROUND/'recall.json',dict(ok=True,status='MODIFIED5_RECALLED_PHYSICAL_CAPTURE_FAILURE',moves=moves,
        recovery_kit=KIT.relative_to(ROOT).as_posix(),failed_artifacts_preserved=True,old_frozen_reports_unchanged=True,
        physical_recovery_pending=True))
    write(KIT/'delivery-files.json',dict(files=[rec(p) for p in sorted(KIT.rglob('*')) if p.is_file()]))
    print(json.dumps(dict(ok=True,moved=len(moves),recovery=str(KIT))))

if __name__=='__main__':main()
