"""Finalize, hash and freeze modified2 preflash delivery without altering sources."""
from pathlib import Path
import datetime, hashlib, json, re, sys, zipfile
from review_vignette_preflash import ROOT, SOURCES
from verify_vignette_preflash_kit import DIGESTS, need, sha, check_kit
from verify_preflash_kit import check_kit as check_previous_kit

ROUND=ROOT/'analysis/vignette-preflash-2026-11-09'
KIT=ROOT/'outputs/Z6-C380-vignette-neutral-reviewed-2026-11-09'
ARCHIVE=KIT.with_suffix('.zip')
REPORT=ROOT/'docs/VIGNETTE_PREFLASH_REVIEW_2026-11-09.md'
EXPECTED_FAILURES={'04-abi-retained-state','05-abi-retained-state-v2','06-abi-retained-state-v3'}


def read(path):return json.loads(path.read_text(encoding='utf8'))


def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1<<20),b''):h.update(block)
    return h.hexdigest()


def record(path,root=ROOT):
    return dict(path=path.relative_to(root).as_posix(),bytes=path.stat().st_size,sha256=digest(path))


def write(path,value):
    need(not path.exists(),'Refusing overwrite: '+str(path))
    path.write_text(json.dumps(value,indent=2,ensure_ascii=False),encoding='utf8')


def progress():
    out=ROUND/'progress-update';out.mkdir(exist_ok=False)
    blocks={
    'README.md':'''\n**2026-11-09 最新：257 项曲线中性化 modified2 已通过安装前离线审查，测试包与两种回退文件已备齐。**保留当前 modified1 暗场补丁；新文件相对 modified1 仅多 6 个代码字节及 2 个 CRC 字节。本轮 1,024 次入口／ABI 检查、64 步保留状态切换、正向及两种回退方向的原厂更新检查通过。实机 modified2 的开机、NEF、消圈和回退尚待验收。请先在当前 modified1 拍同条件 A 组，再刷候选拍 B 组。[安装前审查](docs/VIGNETTE_PREFLASH_REVIEW_2026-11-09.md)、[测试包入口](outputs/Z6-C380-vignette-neutral-reviewed-2026-11-09/START_HERE.txt)、[平场步骤](docs/Z6_VIGNETTE_FLAT_COMPARE_2026-11-09.txt)。以下各阶段状态按时间阅读。\n''',
    'docs/NEXT_STEPS.md':'''\n## 当前优先级（2026-11-09，modified2 安装前审查完成）\n\n[安装前审查](VIGNETTE_PREFLASH_REVIEW_2026-11-09.md)已完成，候选与上轮 LAB 字节相同，现可进入受控实机测试；[安装与回退步骤](Z6_VIGNETTE_INSTALL_2026-11-09.txt)和[平场比较步骤](Z6_VIGNETTE_FLAT_COMPARE_2026-11-09.txt)已交付。\n\n1. 当前 modified1 先拍固定几何、固定光圈／ISO、三曝光级 A 组；更新一次后复拍同条件 B 组，快门较慢的主组与旧 1/8000 秒条件分开。\n2. 新 NEF 先验完整解码、位深、黑位、饱和及 NEFInfo6，再比较浮点 CFA 的 R/G、B/G 环边与台阶；标签变化与实际像素变化分开。\n3. 用同条件 5 秒暗场回归冻结的 112 点及背景；两组 17 项表、四偏移与 RAW 路由仍保持原修改范围。\n4. 根据实际需要回到包内 modified1（保留暗场补丁）或 stock（撤销两项修改），菜单正常才适用；首次实际回退另记事实。\n5. 若新支线只改变增益／暗角或标签，继续两组 17 项表与固定前端标定；不将这一份候选称为全部 RAW 校正关闭或消圈完成。\n\n下方保留历史计划。\n''',
    'docs/PROJECT_GOALS.md':'''\n## 当前推进（2026-11-09，modified2 实机测试准备就绪）\n\n最终目标保持不变。保留已在真机暗场见效的 modified1，新增 257 项曲线中性化的 modified2 已完成离线安装前审查，并独立交付测试文件、modified1 回退和原版回退。下一步是同条件平场 A/B、保存 NEF 像素及 112 点回归验收；实际消圈、所有 RAW 校正关闭和真实回退继续单独记录。见[安装前审查](VIGNETTE_PREFLASH_REVIEW_2026-11-09.md)。\n'''}
    rows=[]
    for relative,block in blocks.items():
        path=ROOT/relative;before=path.read_bytes();text=before.decode('utf8')
        need('VIGNETTE_PREFLASH_REVIEW_2026-11-09.md' not in text,'Progress already updated')
        backup=out/('before-'+relative.replace('/','-'));backup.write_bytes(before)
        first,rest=text.split('\n',1);path.write_bytes((first+'\n'+block+'\n'+rest).encode('utf8'))
        rows.append(dict(path=relative,before_copy=str(backup.relative_to(ROOT)),before_sha256=sha(before),after_sha256=digest(path)))
    write(out/'changes.json',dict(changes=rows,updated_utc=datetime.datetime.now(datetime.timezone.utc).isoformat()))
    print(json.dumps(dict(updated=len(rows))))


def archive():
    check_kit(KIT)
    need(read(ROUND/'verifier-controls/result.json')['ok'],'Verifier controls failed')
    need(not ARCHIVE.exists(),'Archive already exists')
    with zipfile.ZipFile(ARCHIVE,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
        for path in sorted(KIT.rglob('*')):
            if path.is_file():z.write(path,KIT.name+'/'+path.relative_to(KIT).as_posix())
    check_archive()


def check_archive():
    checked=[]
    with zipfile.ZipFile(ARCHIVE,'r') as z:
        need(z.testzip() is None,'ZIP CRC failure')
        expected={KIT.name+'/'+p.relative_to(KIT).as_posix():p for p in KIT.rglob('*') if p.is_file()}
        need(len(z.namelist())==len(expected) and set(z.namelist())==set(expected),'ZIP file selection mismatch')
        for name,path in expected.items():
            h=hashlib.sha256()
            with z.open(name) as f:
                for block in iter(lambda:f.read(1<<20),b''):h.update(block)
            need(h.hexdigest()==digest(path),'ZIP file changed: '+name)
            checked.append(dict(path=name,sha256=h.hexdigest()))
    value=dict(ok=True,archive=record(ARCHIVE),files=checked,extracted_or_written_to_card=False)
    write(ROUND/'archive-verification.json',value)
    print(json.dumps(dict(ok=True,archive=value['archive'],zip_files=len(checked))))


def verify():
    kit_check=check_kit(KIT)
    check_previous_kit(ROOT/'outputs/Z6-C380-preflash-reviewed-2026-11-09')
    for mode,path in SOURCES.items():need(digest(path)==DIGESTS[mode],'Preserved input changed')
    need(digest(ROOT/'firmware/original/Z_6_0380.bin')=='ff978ffdf77c58c0b861a06e16d432d5886969f3cdd05d62f6c8e82e8a4cea54','Official source changed')
    frozen=read(ROOT/'analysis/raw-ring-controls-2026-11-09/evidence-index.json')
    for row in frozen['files']:need(digest(ROOT/row['path'])==row['sha256'],'Frozen file changed')
    fields=read(ROOT/'analysis/raw-ring-controls-2026-11-09/nef-fields/result.json')
    for row in fields['files']:need(digest(Path(row['path']))==row['sha256'],'Flat input changed')
    state=read(ROUND/'state-final/result.json');updater=read(ROUND/'updater/result.json')
    static=read(ROUND/'static/result.json');controls=read(ROUND/'verifier-controls/result.json')
    need(all(x['ok'] for x in (state,updater,static,controls)),'Unpassed review')
    need(len(state['abi'])==1024 and state['abi_pairs']==512 and len(state['transitions'])==64,'State counts')
    need(len(updater['file_checks'])==7 and len(updater['scheduler'])==5,'Updater counts')
    need(len(controls['cases'])==19,'Verifier count')
    for mode,source in (('test','01_TEST_MODIFIED2'),('modified1','02_BACK_TO_MODIFIED1'),('stock','03_STOCK_C380')):
        need(digest(KIT/source/'EG162080.BIN')==DIGESTS[mode],'Delivery bytes changed')
    for source,target in (('docs/Z6_VIGNETTE_INSTALL_2026-11-09.txt','START_HERE.txt'),
                          ('docs/Z6_VIGNETTE_FLAT_COMPARE_2026-11-09.txt','FLAT_COMPARE.txt'),
                          ('docs/VIGNETTE_PREFLASH_REVIEW_2026-11-09.md','REVIEW.md')):
        need((ROOT/source).read_bytes()==(KIT/target).read_bytes(),'Delivery instructions differ')
    archived=read(ROUND/'archive-verification.json')
    need(archived['ok'] and digest(ARCHIVE)==archived['archive']['sha256'],'ZIP changed')
    primary=read(ROUND/'primary-sources/manifest.json')
    need(len(primary)==3 and all(r.get('http_status')==200 and 'error' not in r for r in primary),'Primary sources incomplete')
    for row in primary:need(digest(Path(row['path']))==row['sha256'],'Source snapshot changed')
    changes=read(ROUND/'progress-update/changes.json')
    for row in changes['changes']:
        need(digest(ROOT/row['path'])==row['after_sha256'],'Progress changed')
        need(digest(ROOT/row['before_copy'])==row['before_sha256'],'Progress backup changed')
    commands=[]
    for path in sorted((ROUND/'commands').glob('*/command.json')):
        value=read(path)
        if 'exit_code' not in value:continue  # current recorder finalizes after return
        expected=int(path.parent.name in EXPECTED_FAILURES)
        need(value['exit_code']==expected,'Unexpected failed command: '+path.parent.name)
        commands.append(dict(name=path.parent.name,exit_code=value['exit_code']))
    value=dict(ok=True,kit=kit_check,archive=archived['archive'],preserved_prior_files=len(frozen['files']),
        source_flats_unchanged=len(fields['files']),original_and_modified1_preserved=True,
        abi_calls=1024,abi_pairs=512,retained_state_steps=64,updater_file_cases=7,scheduler_cases=5,
        verifier_cases=19,commands=commands,new_firmware_bytes_added_this_round=False,
        verdict='Passed offline review for controlled physical test',physical_modified2_boot=False,
        physical_modified2_nef=False,physical_rollback_verified=False,ring_removal_verified=False)
    write(ROUND/'verification.json',value)
    print(json.dumps({k:v for k,v in value.items() if k not in ('commands','kit')},indent=2))


def index():
    need(read(ROUND/'verification.json')['ok'],'Final verification required')
    snapshots=ROUND/'source-snapshots';snapshots.mkdir(exist_ok=False)
    names=('review_vignette_preflash.py','verify_vignette_preflash_kit.py','probe_vignette_preflash_state.py',
        'probe_vignette_preflash_updater.py','probe_preflash_review.py','probe_eg_update_route.py',
        'probe_still_vignette_neutral.py','probe_still_neighborhood_off.py','probe_raw_candidates.py',
        'build_raw_candidates.py','package_vignette_preflash.py','test_vignette_preflash_verifier.py',
        'record_research_command.py','inspect_native.py','archive_preflash_sources.py',Path(__file__).name)
    for name in names:(snapshots/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    documents=ROUND/'document-snapshots';documents.mkdir(exist_ok=False)
    for relative in ('README.md','docs/NEXT_STEPS.md','docs/PROJECT_GOALS.md',
        'docs/VIGNETTE_PREFLASH_REVIEW_2026-11-09.md','docs/Z6_VIGNETTE_INSTALL_2026-11-09.txt',
        'docs/Z6_VIGNETTE_FLAT_COMPARE_2026-11-09.txt'):
        (documents/relative.replace('/','-')).write_bytes((ROOT/relative).read_bytes())
    commands=[]
    for path in sorted((ROUND/'commands').glob('*/command.json')):
        value=read(path);need(value.get('exit_code')==int(path.parent.name in EXPECTED_FAILURES),'Command not finalized')
        commands.append(dict(name=path.parent.name,**value))
    value=dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),argv=sys.argv,
        status='Frozen preflash-review evidence. No modified2 physical operation or ring-removal claim.',
        files=[record(p) for p in sorted(ROUND.rglob('*')) if p.is_file()],
        delivery_files=[record(p) for p in sorted(KIT.rglob('*')) if p.is_file()]+[record(ARCHIVE)],
        commands=commands)
    write(ROUND/'evidence-index.json',value)
    print(json.dumps(dict(indexed_files=len(value['files']),delivery_files=len(value['delivery_files']),commands=len(commands))))


if __name__=='__main__':
    {'progress':progress,'archive':archive,'verify':verify,'index':index}[sys.argv[1]]()
