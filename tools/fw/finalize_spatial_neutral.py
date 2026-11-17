"""Preserve and index a new spatial-control research round, never old evidence."""
from pathlib import Path
import argparse, binascii, datetime, hashlib, json, re, shutil, subprocess, sys

ROOT = Path(__file__).resolve().parents[2]
ROUND = ROOT/'analysis/raw-spatial-neutral-2026-11-09'
REPORT = ROOT/'docs/RAW_SPATIAL_NEUTRAL_2026-11-09.md'
MODULE = ROUND/'lab-module/neighborhood-vignette-spatial-neutral-lab.bi'
RECIPE = ROOT/'patches/z6-c380-spatial-neutral-lab.json'
PINS = {
 'firmware/original/Z_6_0380.bin': 'ff978ffdf77c58c0b861a06e16d432d5886969f3cdd05d62f6c8e82e8a4cea54',
 'firmware/decoded/eg1620_038000.bi': '1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c',
 'outputs/Z6-C380-preflash-reviewed-2026-11-09/01_TEST/EG162080.BIN': 'eeded80d4009204ba9760b6e20436aea3f6a37ce4ed6331ca662b839164a8875',
 'outputs/Z6-C380-vignette-neutral-reviewed-2026-11-09/01_TEST_MODIFIED2/EG162080.BIN': '6790186e7e088ae7c504677be052aecdbf3868616207bfda5606b36d37149038',
 'samples/11.9_modified1/Z61_4864.NEF': '4d2dbc968980e33c517f3569e84723d67a17460697c037b19640914f16122077',
 'samples/11.9_modified1/Z61_4865.NEF': 'b7fc7bcb28eb2883b76477c15ce36fc58f0f28c6b86939b533bac1602204dc0c',
 'samples/11.9_modified2/Z61_4870.NEF': '71065d2251dbe842f7d9b1e3ead6647238709f7e8e87c3452918619dd343aa86',
 'samples/11.9_modified2/Z61_4873.NEF': '1960c62e25b61135e296c09c61cb00e3564943b788d9bfb79142cfdd3f0657d0',
}

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def save(path, obj):
    with path.open('x', encoding='utf8') as f: json.dump(obj, f, indent=2, ensure_ascii=False)
def pinned():
    rows = []
    for name, digest in PINS.items():
        got = sha(ROOT/name)
        if got != digest: raise ValueError(f'Pinned input changed: {name}')
        rows.append(dict(path=name, size=(ROOT/name).stat().st_size, sha256=got))
    return rows

def read(path):return json.loads(path.read_text(encoding='utf8'))
def need(value,message):
    if not value:raise ValueError(message)

FAILURES={
    '02-static-gates':'CLI address omitted 0x; no firmware execution; superseded by 03.',
    '15-precomputed-chains':'Historical field input path incorrect; superseded by 20.',
    '16-precomputed-chains-v2':'Test incorrectly required both metadata flags zero; fixed !inhibit assertion; superseded by 20.',
    '17-shared-controls':'Same metadata-flag assertion error; superseded by 21.',
}

def commands(allow_running=False):
    rows=[]
    for path in sorted((ROUND/'commands').glob('*/command.json')):
        row=read(path);name=path.parent.name
        if 'exit_code' not in row:
            need(allow_running,'Incomplete command '+name);continue
        if row['exit_code']:
            need(name in FAILURES,'Unexpected failed command '+name)
            row['disposition']=FAILURES[name]
        else:need(name not in FAILURES,'Failure ledger contradicts command '+name)
        rows.append(dict(name=name,**row))
    return rows

def assess():
    pins=pinned();build=read(ROUND/'lab-module/build.json');recipe=read(RECIPE)
    need(sha(RECIPE)==build['catalog_sha256'],'Recipe changed after build')
    stock=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    prior=(ROOT/'outputs/Z6-C380-vignette-neutral-reviewed-2026-11-09/01_TEST_MODIFIED2/EG162080.BIN').read_bytes()
    lab=MODULE.read_bytes();candidate=build['candidates'][0]
    need(sha(MODULE)==candidate['output_sha256'],'LAB hash differs')
    need(len(stock)==len(prior)==len(lab)==33502842,'Module size mismatch')
    need(binascii.crc_hqx(lab,0)==0,'LAB CRC')
    edits=recipe['candidates'][0]['edits'];base=int(recipe['load_base'],0)
    need(len(edits)==9,'Unexpected edit count')
    expected=bytearray(stock)
    for i,e in enumerate(edits):
        off=int(e['address'],0)-base;before=bytes.fromhex(e['before']);after=bytes.fromhex(e['after'])
        need(stock[off:off+len(before)]==before,'Preimage mismatch')
        expected[off:off+len(after)]=after
        if i<6:need(prior[off:off+len(after)]==after and lab[off:off+len(after)]==after,'Inherited edit altered')
    expected[-2:]=binascii.crc_hqx(expected[:-2],0).to_bytes(2,'big')
    need(expected==lab,'Rebuilt module differs')
    restored=bytearray(lab)
    for e in edits[6:]:
        off=int(e['address'],0)-base;restored[off:off+2]=prior[off:off+2]
    restored[-2:]=prior[-2:];need(restored==prior,'Exact modified2 restoration failed')
    for e in edits:
        off=int(e['address'],0)-base;before=bytes.fromhex(e['before']);restored[off:off+len(before)]=before
    restored[-2:]=stock[-2:];need(restored==stock,'Exact stock restoration failed')
    diff=[hex(i) for i,(a,b) in enumerate(zip(prior,lab)) if a!=b]
    need(len(diff)==7,'Unexpected delta vs modified2')
    summary={};allowed={0x700,*range(0x1200,0x1248,4)}
    for name,nrows,npairs in (('precomputed-chains-v3',32,16),('shared-controls-v2',512,256),('front-policy-probe',160,80)):
        data=read(ROUND/name/'result.json')
        need(data['ok'] and len(data['rows'])==nrows and len(data['comparisons'])==npairs,'Incomplete '+name)
        entry=dict(rows=nrows,pairs=npairs)
        if name!='front-policy-probe':
            offsets={int(k,16) for row in data['comparisons'] for k in row['changed_registers']}
            need(offsets==allowed,'Unexpected MMIO delta '+name)
            entry['observed_changed_mmio_offsets']=[hex(x) for x in sorted(offsets)]
        else:
            words={r['word'] for r in data['rows'] if r['fixture']['ctx38']}
            need(words=={'0x2006'},'Override word incorrect')
            need(all(c['identical'] for c in data['comparisons']),'Front policy changed between variants')
        summary[name]=entry
    safety=read(ROUND/'safety-probe/result.json');callers=read(ROUND/'actual-callers/result.json')
    need(safety['ok'] and callers['ok'],'Safety/callers failed')
    need([len(safety[x]) for x in ('abi','sequence','guards')]==[256,64,4],'Safety coverage incomplete')
    need(len(callers['callers'])==4,'Caller coverage incomplete')
    for row in callers['callers']:
        state=bytes.fromhex(row['precomputed_hex'])
        active=row['variant']=='modified2'
        need(bool(any(state[0x26:0x6a]))==active,'Caller table differential missing')
        need(state[0x1d]==int(active),'Caller active differential missing')
    summary['safety']={k:len(safety[k]) for k in ('abi','sequence','guards')}
    summary['actual_callers']=4
    value=dict(ok=True,created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        evidence='Native offline code/configuration; no new physical NEFs or flash',candidate_sha256=sha(MODULE),
        candidate_size=len(lab),changes_vs_modified2=diff,changed_bytes_vs_stock=len(candidate['changed_byte_offsets']),
        inherited_dark_and_vignette_edits_exact=True,module_crc_remainder=0,
        exact_restoration_to_modified2_and_stock=True,checks=summary,pinned_inputs=pins,
        stage='LAB; shared consumers; installation review and real image validation outstanding',
        fixed_body_calibration_modified=False,hardware_pixels_verified=False,new_install_kit=False)
    save(ROUND/'assessment.json',value)
    print(json.dumps(value,indent=2))

def progress():
    need(read(ROUND/'assessment.json')['ok'],'Assessment required')
    folder=ROUND/'progress-update';folder.mkdir(exist_ok=False)
    blocks={
    'README.md':'''\n**2026-11-09 最新离线进展：两组 17 项空间表中性化副本已完成。** 新增三条 16 位指令，保留 modified1 暗场补丁与 modified2 的 257 项中性化。新确认静态路径先预生成再复制；完整静态调用者、64 次保存参数链（零/非零暗角输入各 32 次）、512 次控制组合、ABI/连续状态检查均通过。机身固定标定定位到 `0x20068500` 的 14 字段控制及原厂覆盖条件。本轮没有新实拍或刷机；副本位于共用模块，仍是 LAB，安装前须审查其它调用方影响。[本轮报告](docs/RAW_SPATIAL_NEUTRAL_2026-11-09.md)、[配方](patches/z6-c380-spatial-neutral-lab.json)。以下按历史进展阅读。\n''',
    'docs/NEXT_STEPS.md':'''\n## 当前优先级（2026-11-09，两组 17 项表 LAB）\n\n[本轮报告](RAW_SPATIAL_NEUTRAL_2026-11-09.md)：新候选已经覆盖静态预生成与整块复制，两表归零、active=0；坐标政策保留，暗场和 257 项修改继承。三条新指令位于共用模块，现阶段为离线实验副本。\n\n1. 对已构建哈希做安装前审查：补充其它共用构造器、启动/取景和状态切换影响；如需静态专用范围，在静态调用层收窄。旧 modified2 审查不自动适用于此副本。\n2. 审查后用当前 modified2 作 A、新候选作 B；固定机位/焦点/光源、多信号级，主组较慢快门，旧 1/8000 秒单独比较。验收浮点 CFA、NEFInfo7 与实际环边，参数中性和消圈分项记录。\n3. 新版本继续回归冻结 112 点、5 秒 dark、黑位与独立解码，保留已获实拍支持的暗场修改。\n4. 固定标定沿 `1011db02 → 1011d7a4 → 1010adf6 → 20068500` 追位到处理阶段及实际状态来源。`context+38` 非零输出 `0x2006`，不是所有字段关闭；空配置包会保留旧寄存器值。真实机身标定原样保留。\n\n下方为此前轮次计划，新的候选状态以上述报告为准。\n''',
    'docs/PROJECT_GOALS.md':'''\n## 当前推进（2026-11-09，两组 17 项空间表）\n\n最终目标不变。本轮制成保留暗场与 257 项修改的两组 17 项中性化 LAB 副本，覆盖原厂静态预生成/复制/上传并保留坐标政策；ABI、旧状态覆盖、系数载荷绕过等离线检查通过。固定标定已定位控制字和运行覆盖条件，仍保持其内容原样。新副本的共用调用范围、安装前检查和真实 NEF 消圈/暗场回归分别验收；不将私有 MMIO 或元数据变化等同实机像素成果。见[本轮报告](RAW_SPATIAL_NEUTRAL_2026-11-09.md)。\n'''}
    changes=[]
    for name,block in blocks.items():
        path=ROOT/name;before=path.read_bytes()
        need(before==(ROUND/'progress-before'/Path(name).name).read_bytes(),'Progress changed during research '+name)
        content=before.decode('utf8');need('RAW_SPATIAL_NEUTRAL_2026-11-09.md' not in content,'Already updated')
        backup=folder/('before-'+name.replace('/','-'));backup.write_bytes(before)
        first,rest=content.split('\n',1);path.write_bytes((first+'\n'+block+'\n'+rest).encode('utf8'))
        changes.append(dict(path=name,before_copy=backup.relative_to(ROOT).as_posix(),before_sha256=sha(backup),after_sha256=sha(path)))
    save(folder/'changes.json',dict(changes=changes));print(json.dumps(dict(updated=len(changes))))

def verify():
    need(read(ROUND/'assessment.json')['ok'],'Assessment missing');pins=pinned()
    supplemental=read(ROUND/'nonzero-vignette-control/result.json')
    need(supplemental['ok'] and len(supplemental['rows'])==32 and len(supplemental['comparisons'])==16,'Nonzero control incomplete')
    need(supplemental['input_vignette_coefficients']==[2122853,-1812904,1751073,0],'Wrong nonzero vignette input')
    need(supplemental['input_spatial_coefficients']==[142,-79,0,-74,-6,61],'Wrong spatial input')
    offsets={int(k,16) for row in supplemental['comparisons'] for k in row['changed_registers']}
    need(offsets=={0x700,*range(0x1200,0x1248,4)},'Supplemental MMIO delta')
    need(sha(Path(supplemental['field_input']))==supplemental['field_input_sha256'],'Supplemental source changed')
    baseline=read(ROUND/'baseline.json');frozen=[]
    for name,expected in baseline['prior_evidence_indexes'].items():
        path=ROOT/'analysis'/name/'evidence-index.json';need(sha(path)==expected,'Prior index changed')
        prior=read(path)
        for row in prior['files']:need(sha(ROOT/row['path'])==row['sha256'],'Prior evidence changed: '+row['path'])
        frozen.append(dict(index=path.relative_to(ROOT).as_posix(),files_checked=len(prior['files'])))
    for link in re.findall(r'\]\(([^)]+)\)',REPORT.read_text(encoding='utf8')):
        if not link.startswith(('https:','http:')):need((REPORT.parent/link).exists(),'Missing report target '+link)
    for row in read(ROUND/'progress-update/changes.json')['changes']:
        need(sha(ROOT/row['path'])==row['after_sha256'],'Progress changed')
        need(sha(ROOT/row['before_copy'])==row['before_sha256'],'Before snapshot changed')
    need(sha(RECIPE)==read(ROUND/'lab-module/build.json')['catalog_sha256'],'Recipe changed')
    need(sha(MODULE)==read(ROUND/'assessment.json')['candidate_sha256'],'Candidate changed')
    completed=commands(allow_running=True)
    need({r['name'] for r in completed if r['exit_code']}==set(FAILURES),'Failed-command ledger incomplete')
    (ROUND/'git-status-after.txt').write_bytes(subprocess.run(['git','status','--short'],cwd=ROOT,capture_output=True,check=True).stdout)
    save(ROUND/'verification.json',dict(ok=True,pinned_inputs=pins,prior_frozen=frozen,
        report_sha256=sha(REPORT),candidate_sha256=sha(MODULE),completed_commands=completed,
        supplemental_nonzero_vignette_control=dict(rows=32,pairs=16,ok=True),total_chain_rows=64,total_chain_pairs=32,
        recorded_failed_commands=FAILURES,physical_ring_removal_tested=False,new_installation_kit=False,
        original_and_delivered_firmware_preserved=True))
    print(json.dumps(dict(ok=True,pinned=len(pins),prior_frozen=frozen,completed_commands=len(completed))))

def index():
    need(read(ROUND/'verification.json')['ok'],'Verification missing')
    all_commands=commands()
    scripts=ROUND/'script-snapshots';scripts.mkdir(exist_ok=False)
    for name in ('finalize_spatial_neutral.py','prepare_spatial_neutral_candidate.py','probe_spatial_neutral.py',
        'probe_front_master_policy.py','probe_spatial_neutral_safety.py','probe_raw_candidates.py',
        'probe_flat_spatial_controls.py','probe_still_vignette_neutral.py','probe_still_neighborhood_off.py',
        'build_raw_candidates.py','inspect_native.py','record_research_command.py'):
        shutil.copyfile(ROOT/'tools/fw'/name,scripts/name)
    docs=ROUND/'document-snapshots';docs.mkdir(exist_ok=False)
    for name in ('docs/RAW_SPATIAL_NEUTRAL_2026-11-09.md','README.md','docs/NEXT_STEPS.md','docs/PROJECT_GOALS.md'):
        shutil.copyfile(ROOT/name,docs/name.replace('/','-'))
    rows=[dict(path=p.relative_to(ROOT).as_posix(),bytes=p.stat().st_size,sha256=sha(p))
          for p in sorted(ROUND.rglob('*')) if p.is_file()]
    save(ROUND/'evidence-index.json',dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        argv=sys.argv,files=rows,commands=all_commands,
        status='Frozen native offline spatial LAB and numeric fixed-calibration policy evidence. No new physical image or install kit.'))
    print(json.dumps(dict(indexed_files=len(rows),commands=len(all_commands),failed_commands_recorded=len(FAILURES))))

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('action', choices=['start','assess','progress','verify','index'])
    args=ap.parse_args()
    ROUND.mkdir(exist_ok=True)
    if args.action=='start':
        rows=pinned()
        snapshots=ROUND/'progress-before';snapshots.mkdir(exist_ok=False)
        for name in ('README.md','docs/NEXT_STEPS.md','docs/PROJECT_GOALS.md'):
            shutil.copyfile(ROOT/name,snapshots/Path(name).name)
        git=subprocess.run(['git','status','--short'],cwd=ROOT,capture_output=True,check=True)
        (ROUND/'git-status-before.txt').write_bytes(git.stdout)
        save(ROUND/'baseline.json',dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            pinned_inputs=rows,user_scope='Trace the two 17-entry spatial tables and fixed body calibration; preserve original and verified dark patch; experiments on copies; distinguish native offline configuration from physical pixel effects.',
            prior_evidence_indexes={name:sha(ROOT/'analysis'/name/'evidence-index.json') for name in
                ('raw-ring-controls-2026-11-09','vignette-preflash-2026-11-09','modified2-flat-2026-11-09')}))
        print(json.dumps(dict(ok=True,pinned_inputs=len(rows))))
    else:{'assess':assess,'progress':progress,'verify':verify,'index':index}[args.action]()

if __name__=='__main__':main()
