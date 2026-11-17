"""Record the physical regression and prepare exact-byte recovery before recall."""
from pathlib import Path
import binascii,datetime,hashlib,json,subprocess

ROOT=Path(__file__).resolve().parents[2]
ROUND=ROOT/'analysis/modified5-failure-2026-11-10'
KIT=ROOT/'outputs/Z6-C380-recovery-from-modified5-2026-11-10'
OLD=ROOT/'outputs/Z6-C380-id35-static-reviewed-2026-11-09'
M5='76474a8977a3bf4b456fe68f9594110714a04c09b4ec575f019ba27fadd0d2d7'
M4='bdf30026dc9d18b09a5ca9332369d126729d63a36013e94b8b20cf6638a4ef1b'
M1='eeded80d4009204ba9760b6e20436aea3f6a37ce4ed6331ca662b839164a8875'
STOCK='1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
BASE=0x10020000
NEW=((0x10179d54,'0020','0420'),(0x1011c756,'05460e464ff6ff77','074620f004050e46'),
 (0x1011c764,'b8420ed0','1c280ed2'),
 (0x1011c78a,'526900eb8000484902eb0010843990f84025ca6190f8412581f8202090f8422581f8262090f84305c8670846f4f727fa2fe0',
  '526950235843121802f5a86247488438137807b1234600bf00bfc361537880f82030937880f82630d378c367f4f727fa2fe0'))
def sha(b):return hashlib.sha256(b).hexdigest()
def write(p,j):p.write_bytes(json.dumps(j,ensure_ascii=False,indent=2).encode('utf8'))
def rec(p):return dict(path=p.relative_to(ROOT).as_posix(),sha256=sha(p.read_bytes()),bytes=p.stat().st_size)

def main():
    ROUND.mkdir(parents=True,exist_ok=True);KIT.mkdir(parents=True,exist_ok=False)
    snap=ROUND/'progress-before';snap.mkdir(exist_ok=False)
    for name in ('README.md','docs/NEXT_STEPS.md','docs/PROJECT_GOALS.md'):
        (snap/name.replace('/','-')).write_bytes((ROOT/name).read_bytes())
    (ROUND/'git-status-before.txt').write_bytes(subprocess.run(['git','status','--short'],cwd=ROOT,capture_output=True,check=True).stdout)
    original=OLD/'01_TEST_MODIFIED5/EG162080.BIN';b=original.read_bytes()
    assert sha(b)==M5 and len(b)==33502842 and binascii.crc_hqx(b,0)==0
    restored=bytearray(b)
    for pc,old,new in NEW:
        off=pc-BASE;old,new=bytes.fromhex(old),bytes.fromhex(new)
        assert restored[off:off+len(new)]==new
        restored[off:off+len(old)]=old
    restored[-2:]=binascii.crc_hqx(restored[:-2],0).to_bytes(2,'big')
    baseline=(ROOT/'outputs/Z6-C380-front-bit11-reviewed-2026-11-09/01_TEST_MODIFIED4/EG162080.BIN').read_bytes()
    assert restored==baseline and sha(restored)==M4
    paths={'modified4':'01_RECOVER_MODIFIED4/EG162080.BIN','modified1':'02_DARK_ONLY_MODIFIED1/EG162080.BIN',
           'stock':'03_STOCK_C380/EG162080.BIN'}
    sources={'modified4':bytes(restored),
      'modified1':(ROOT/'outputs/Z6-C380-preflash-reviewed-2026-11-09/01_TEST/EG162080.BIN').read_bytes(),
      'stock':(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()}
    hashes={'modified4':M4,'modified1':M1,'stock':STOCK}
    for name,blob in sources.items():
        assert sha(blob)==hashes[name] and binascii.crc_hqx(blob,0)==0
        p=KIT/paths[name];p.parent.mkdir();p.write_bytes(blob)
    write(KIT/'manifest.json',dict(schema='z6-m5-recovery-1',status='RECOVERY_ONLY_NO_NEW_RING_PATCH',
        revoked_sha256=M5,default='modified4',module_sha256=hashes,paths=paths,
        files=[rec(KIT/paths[n]) for n in paths],
        fact='modified4 recovery is exact reversal of all four modified5 edit regions plus CRC, identical to the previously used modified4.',
        limits='Physical recovery result pending user; no new ID35 disable behavior or ring-removal claim.'))
    write(ROUND/'incident.json',dict(date='2026-11-10',classification='USER_REPORTED_PHYSICAL_CAPTURE_FAILURE',
        revoked_candidate='modified5',revoked_sha256=M5,
        user_report='实机测试，无法释放快门，按下快门后机器卡住，然后err，然后自动重启，重启后显示快门已经关闭，叫我按下快门键才能重新拍摄，我按下快门键后，依旧没法正常拍摄，循环上述流程；快门速度等其他参数均与刚刚一致',
        evidence_source='User report in this conversation, not a captured camera trace.',
        verified_by_user_report=['Capture hangs after shutter press','Err then automatic restart','Restart requests shutter recovery','Retry repeats failure'],
        unknown=['Exact hardware failure stage','Underlying error code/callback','Whether rollback restores capture','Shutter mode pending user reply'],
        action='Withdraw modified5, restore exact modified4 first, investigate software and hardware enable/descriptor dependencies.',
        raw_pixel_effect=None,root_cause=None,do_not_bypass=['Shutter protection','Watchdog/error reporting','Capture completion waits']))
    write(ROUND/'recovery-reconstruction.json',dict(ok=True,failed_sha256=M5,recovered_sha256=M4,
        changed_regions=len(NEW),same_size=True,exact_match_previous_modified4=True,
        all_modified5_edits_reverted=True,existing_ten_edits_preserved=True,
        parent_modules={n:rec(KIT/paths[n]) for n in paths}))
    print(json.dumps(dict(ok=True,recovery=str(KIT),sha256=M4)))

if __name__=='__main__':main()
