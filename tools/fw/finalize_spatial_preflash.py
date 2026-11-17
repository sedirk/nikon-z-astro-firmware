"""Freeze the modified3 preflash review, delivery and progress without source edits."""
from pathlib import Path
import ast,datetime,hashlib,json,shutil,subprocess,sys,zipfile
from review_spatial_preflash import ROOT,ROUND,SOURCES
from verify_spatial_preflash_kit import PATHS,DIGESTS,need,check_kit,read_module
from finalize_spatial_neutral import pinned

KIT=ROOT/'outputs/Z6-C380-spatial-neutral-reviewed-2026-11-09'
ZIP=KIT.with_suffix('.zip');REPORT=ROOT/'docs/SPATIAL_PREFLASH_REVIEW_2026-11-09.md'
FAILURES={'02-qemu-modified2':'Input fixture overlapped interpolation workspace; superseded by 06.',
          '04-qemu-modified2-diagnostic':'Same invalid layout, captured memory evidence; corrected before 06/07.'}
SCRIPTS=('review_spatial_preflash.py','verify_spatial_preflash_kit.py','probe_spatial_preflash_updater.py',
         'qemu_spatial_preflash.py','assess_spatial_preflash.py','package_spatial_preflash.py',
         'test_spatial_preflash_verifier.py','finalize_spatial_preflash.py','probe_preflash_review.py',
         'probe_eg_update_route.py','record_research_command.py','inspect_native.py')
DOCS=('README.md','docs/NEXT_STEPS.md','docs/PROJECT_GOALS.md','docs/SPATIAL_PREFLASH_REVIEW_2026-11-09.md',
      'docs/Z6_SPATIAL_INSTALL_2026-11-09.txt','docs/Z6_SPATIAL_FLAT_COMPARE_2026-11-09.txt')
def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for part in iter(lambda:f.read(1<<20),b''):h.update(part)
    return h.hexdigest()
def read(p):return json.loads(p.read_text(encoding='utf8'))
def save(p,obj):
    with p.open('x',encoding='utf8') as f:json.dump(obj,f,indent=2,ensure_ascii=False)
def record(p):return dict(path=p.relative_to(ROOT).as_posix(),bytes=p.stat().st_size,sha256=digest(p))
def commands(allow_current=False):
    rows=[]
    for p in sorted((ROUND/'commands').glob('*/command.json')):
        d=read(p);name=p.parent.name
        if 'exit_code' not in d:
            need(allow_current,'Incomplete command '+name);continue
        need(d['exit_code']==int(name in FAILURES),'Unexpected exit status '+name)
        rows.append(dict(name=name,**d,disposition=FAILURES.get(name,'completed')))
    return rows
def progress():
    need(read(ROUND/'assessment.json')['ok'],'Assessment required');check_kit(KIT)
    folder=ROUND/'progress-update';folder.mkdir(exist_ok=False)
    blocks={
      'README.md':'''\n**2026-11-09 最新：modified3 两组 17 项空间表中性化已完成离线安装前审查，测试包和三种回退齐备。** 保留暗场与 257 项修改，沿用上一轮 LAB 的确切字节。两版本 QEMU 取景/菜单对照、16 组非零参数跨引擎核对、6 个文件更新方向和 4 个成功擦写调度方向通过。修改位于共用空间模块；真实镜头取景、modified3 NEF、消圈与回退待实测。先在当前 modified2 拍固定布置 A，再安装一次拍 B。[审查报告](docs/SPATIAL_PREFLASH_REVIEW_2026-11-09.md)、[测试包入口](outputs/Z6-C380-spatial-neutral-reviewed-2026-11-09/START_HERE.txt)、[ZIP](outputs/Z6-C380-spatial-neutral-reviewed-2026-11-09.zip)、[平场步骤](docs/Z6_SPATIAL_FLAT_COMPARE_2026-11-09.txt)。\n''',
      'docs/NEXT_STEPS.md':'''\n## 当前优先级（2026-11-09，modified3 实机对照准备完成）\n\n[modified3 审查](SPATIAL_PREFLASH_REVIEW_2026-11-09.md)通过；三条新指令与上一轮 LAB 完全一致，暗场和 257 项修改继承。已交付测试、modified2/modified1/stock 三种回退、固定哈希校验器和[取样步骤](Z6_SPATIAL_FLAT_COMPARE_2026-11-09.txt)。\n\n1. 当前 modified2 先拍固定布置 A，随后一次更新拍 B；普通 NEF 确认保存/回放后再做平场，优先较慢快门、多信号级。\n2. 新 NEF 分别验完整解码、黑位、NEFInfo7 active/坐标系数，以及 CFA 色彩比例和环边。旧 A 因位置/焦点可能改变仅作背景参考。\n3. 同版本回归冻结的 112 点和 5 秒暗场；先限单张静态 NEF，共用模块对真实镜头取景、JPEG、视频另项验收。\n4. 按真实像素结果决定保留/撤销本次 17 项支线。若宽环/细密环持续，回到固定标定 14 字段控制与具体处理阶段的对应关系，不继续靠元数据归零结项。\n5. 需要回退且菜单可用时优先 modified2；真实回退结果独立记录。原固件、机身标定及已验证暗场补丁继续保留。\n\n以下为此前计划，当前候选以本次确切哈希和报告为准。\n''',
      'docs/PROJECT_GOALS.md':'''\n## 当前推进（2026-11-09，modified3 测试包已交付）\n\n最终目标不变。针对两组 17 项空间表的候选已完成离线安装前审查并交付测试包、三种回退和校验工具；原固件、暗场补丁及 257 项控制保留。原厂调用/内存/配置、QEMU 启动/取景与非零参数交叉验证、升级/回退调度分层记录。新版本真实 NEF 消圈、暗场回归和真实模式兼容性是下一阶段验收；模拟器合成图与配置归零不计为实机成果。见[审查报告](SPATIAL_PREFLASH_REVIEW_2026-11-09.md)。\n'''}
    changes=[]
    for name,block in blocks.items():
        p=ROOT/name;before=p.read_bytes();need(before==(ROUND/'progress-before'/Path(name).name).read_bytes(),'Concurrent progress edit '+name)
        text=before.decode('utf8');need('SPATIAL_PREFLASH_REVIEW_2026-11-09.md' not in text,'Already updated')
        backup=folder/('before-'+name.replace('/','-'));backup.write_bytes(before)
        first,rest=text.split('\n',1);p.write_bytes((first+'\n'+block+'\n'+rest).encode('utf8'))
        changes.append(dict(path=name,before_copy=backup.relative_to(ROOT).as_posix(),before_sha256=digest(backup),after_sha256=digest(p)))
    save(folder/'changes.json',dict(changes=changes));print(json.dumps(dict(updated=len(changes))))
def archive():
    check_kit(KIT);need(read(ROUND/'verifier-controls/result.json')['ok'],'Verifier controls missing')
    with zipfile.ZipFile(ZIP,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
        for p in sorted(KIT.rglob('*')):
            if p.is_file():z.write(p,KIT.name+'/'+p.relative_to(KIT).as_posix())
    checked=[]
    with zipfile.ZipFile(ZIP) as z:
        need(z.testzip() is None,'ZIP CRC')
        expected={KIT.name+'/'+p.relative_to(KIT).as_posix():p for p in KIT.rglob('*') if p.is_file()}
        need(len(z.namelist())==len(expected) and set(z.namelist())==set(expected),'ZIP entries')
        for name,p in expected.items():
            h=hashlib.sha256()
            with z.open(name) as f:
                for part in iter(lambda:f.read(1<<20),b''):h.update(part)
            need(h.hexdigest()==digest(p),'ZIP content '+name);checked.append(dict(path=name,sha256=h.hexdigest()))
    save(ROUND/'archive-verification.json',dict(ok=True,archive=record(ZIP),files=checked))
    print(json.dumps(dict(ok=True,archive=record(ZIP),files=len(checked))))
def verify():
    kit=check_kit(KIT);pins=pinned()
    for mode,p in SOURCES.items():read_module(p,mode)
    frozen=[]
    for name in ('raw-spatial-neutral-2026-11-09','vignette-preflash-2026-11-09','modified2-flat-2026-11-09'):
        p=ROOT/'analysis'/name/'evidence-index.json';d=read(p)
        for row in d['files']:need(digest(ROOT/row['path'])==row['sha256'],'Prior frozen evidence altered '+row['path'])
        frozen.append(dict(index=p.relative_to(ROOT).as_posix(),files=len(d['files'])))
    assessment=read(ROUND/'assessment.json');need(assessment['ok'],'Assessment failed')
    for row in assessment['qemu_runs']:need(digest(ROOT/row['path'])==row['sha256'],'QEMU evidence changed')
    controls=read(ROUND/'verifier-controls/result.json');need(controls['ok'] and len(controls['cases'])==27,'Verifier coverage')
    for source,target in (('docs/Z6_SPATIAL_INSTALL_2026-11-09.txt','START_HERE.txt'),
        ('docs/Z6_SPATIAL_FLAT_COMPARE_2026-11-09.txt','FLAT_COMPARE.txt'),('docs/SPATIAL_PREFLASH_REVIEW_2026-11-09.md','REVIEW.md'),
        ('tools/fw/verify_spatial_preflash_kit.py','verify.py')):
        need((ROOT/source).read_bytes()==(KIT/target).read_bytes(),'Delivery text differs')
    archived=read(ROUND/'archive-verification.json');need(archived['ok'] and digest(ZIP)==archived['archive']['sha256'],'Archive changed')
    for row in read(ROUND/'progress-update/changes.json')['changes']:
        need(digest(ROOT/row['path'])==row['after_sha256'] and digest(ROOT/row['before_copy'])==row['before_sha256'],'Progress changed')
    for name in SCRIPTS:ast.parse((ROOT/'tools/fw'/name).read_text(encoding='utf8'))
    (ROUND/'git-status-after.txt').write_bytes(subprocess.run(['git','status','--short'],cwd=ROOT,capture_output=True,check=True).stdout)
    save(ROUND/'verification.json',dict(ok=True,candidate_sha256=DIGESTS['test'],kit=kit,archive=archived['archive'],
        pinned_inputs=pins,prior_frozen=frozen,verifier_cases=27,accepted_qemu_runs=4,cross_engine_cases=16,
        update_file_cases=9,scheduler_cases=6,commands=commands(allow_current=True),recorded_failures=FAILURES,
        new_code_edits_since_lab=False,original_and_existing_patches_preserved=True,card_access=False,physical_flash=False,
        physical_ring_removal_verified=False,verdict=assessment['verdict']))
    print(json.dumps(dict(ok=True,candidate_sha256=DIGESTS['test'],prior_frozen=frozen,verifier_cases=27)))
def index():
    need(read(ROUND/'verification.json')['ok'],'Verification missing');cmds=commands()
    scripts=ROUND/'source-snapshots';scripts.mkdir(exist_ok=False)
    for name in SCRIPTS:shutil.copyfile(ROOT/'tools/fw'/name,scripts/name)
    docs=ROUND/'document-snapshots';docs.mkdir(exist_ok=False)
    for name in DOCS:shutil.copyfile(ROOT/name,docs/name.replace('/','-'))
    rows=[record(p) for p in sorted(ROUND.rglob('*')) if p.is_file()]
    delivered=[record(p) for p in sorted(KIT.rglob('*')) if p.is_file()]+[record(ZIP)]
    save(ROUND/'evidence-index.json',dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),argv=sys.argv,
        files=rows,delivery_files=delivered,commands=cmds,status='Frozen exact modified3 controlled-test delivery; offline verification only; no real modified3 NEF or ring-removal claim.'))
    print(json.dumps(dict(indexed_files=len(rows),delivery_files=len(delivered),commands=len(cmds))))
if __name__=='__main__':{'progress':progress,'archive':archive,'verify':verify,'index':index}[sys.argv[1]]()
