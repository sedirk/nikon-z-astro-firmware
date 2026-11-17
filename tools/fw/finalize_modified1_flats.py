"""Preserve previous progress documents and verify/index the first tablet flats."""
from pathlib import Path
import datetime,hashlib,json,re,sys
import numpy as np
from audit_nef import file_sha

ROOT=Path(__file__).resolve().parents[2]
BASE=ROOT/'analysis/modified1-flat-2026-11-09'

def need(value,text):
    if not value:raise ValueError(text)
def read(p):return json.loads(p.read_text(encoding='utf8'))
def write(p,d):p.write_text(json.dumps(d,indent=2,ensure_ascii=False,allow_nan=False),encoding='utf8')

def update():
    out=BASE/'progress-update';out.mkdir(parents=True,exist_ok=False);changes=[]
    blocks={
    'README.md':'''\n**2026-11-09 最新优先级：彩圈。**新增两张候选平场（4864/4865，唯卓仕 16/1.8＋平板光源），独立解码 48,997,120 个码值一致。R/G、B/G 存在可重复的宽环状起伏，边缘条带在两帧中显著变化；记录为待分离来源的实拍结构，消圈继续验收。下一步优先延长屏幕曝光、低 ISO 多曝光级、光源方向对照，再做同条件原版比较。[本轮平场报告](docs/MODIFIED1_FLATS_2026-11-09.md)及[结果图](analysis/modified1-flat-2026-11-09/summary-v2/flat-first-result.png)。此前 112 点邻域抑制的实机结果仍保留，下面各阶段计划按历史记录阅读。\n''',
    'docs/NEXT_STEPS.md':'''\n## 当前优先级（2026-11-09，两张候选平场之后）\n\n用户将彩圈列为最高优先级。[当前平场结果](MODIFIED1_FLATS_2026-11-09.md)：两张同曝光样本均有宽环状颜色起伏；屏幕条带和照明空间变化已单独记录。\n\n1. **保持当前候选，先降低平场干扰。** 可另起 ISO 100、固定 f/8 的试拍组，1/30 秒起试，再按实际亮度拍多曝光级；每档不过曝，不把改变光圈的差别记为固件效果。\n2. **固定相机，旋转光源作干扰对照。** 180° 平板旋转可帮助识别随屏幕变化的结构；没有移动的结构仍需区分镜头／径向光源／机内处理。合适的稳定漫射光源优先。\n3. **取得可重复的多信号级特征后做原版比较。** 同机身、同镜头、同光圈和同照明，在一次原版回退后复拍。不要用旧 NAS 的另一机身或另一镜头算改善幅度。\n4. **逆向围绕真实特征推进。** 将颜色通道、空间位置和曝光依赖约束接回固定标定、空间参数生成及 RAW 写回；不把宽颜色渐变直接命名为某一参数表。\n5. **暗信号工作保留为并行目标。** 已有 112 点邻域抑制实拍突破；短曝光暗场、实际回退和稳定性待后续条件补齐。\n\n下方保留此前阶段安排，当前先后顺序以上述彩圈路线为准。\n''',
    'docs/PROJECT_GOALS.md':'''\n## 当前观察（2026-11-09，彩圈优先）\n\n最终目标不变。用户当前首先验收彩圈。两张候选平场已进入真实 RAW 的 R/G、B/G 空间分析：存在可重复的宽环状颜色结构及变化的边缘条带，正区分光源／镜头与机内校正，尚未记为消圈完成。实拍条件、处理控制及后续最小取样见[平场报告](MODIFIED1_FLATS_2026-11-09.md)。此前局部强暗信号保留的实机成果保持有效。\n'''}
    for rel,block in blocks.items():
        path=ROOT/rel;before=path.read_bytes();text=before.decode('utf8')
        need('MODIFIED1_FLATS_2026-11-09.md' not in text,'Flat milestone already installed')
        first,rest=text.split('\n',1);after=(first+'\n'+block+'\n'+rest).encode('utf8')
        backup=out/('before-'+rel.replace('/','-'));backup.write_bytes(before);path.write_bytes(after)
        changes.append(dict(path=rel,before_copy=str(backup.relative_to(ROOT)),before_sha256=hashlib.sha256(before).hexdigest(),after_sha256=hashlib.sha256(after).hexdigest()))
    write(out/'changes.json',dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),changes=changes,
        reason='User prioritizes colour rings; first two candidate flats analyzed'))
    write(BASE/'reference.json',dict(url='https://www.markshelley.co.uk/Astronomy/NikonConcentricRings/nikon_hardcoded_correction.html',
        title="Nikon's Hardcoded Image Correction",author='Mark Shelley',page_last_updated='2023-09-12',
        checked_date='2026-11-09',retrieval='web tool opened primary page',
        used_for='Diagnostic method: fixed aperture, exposure sequence, lower ISO for visibility, floating-point bias-subtracted CFA ratios.',
        distinction='Published stock-camera observation, not evidence of this candidate removing rings.'))
    print(json.dumps(dict(updated=len(changes))))

def verify():
    target=BASE/'verification.json';need(not target.exists(),'Verification already exists')
    audit=read(BASE/'raw-audit.json');spatial=read(BASE/'spatial/result.json');dec=read(BASE/'independent-decoding/result.json')
    scales=read(BASE/'scale-controls/result.json');summary=read(BASE/'summary-v2/result.json');checks=[]
    need(audit['files'] and all(x['source_unchanged'] for x in audit['files']),'Audit source checks')
    for case in audit['files']+spatial['bias_sources']:
        need(file_sha(case['path'])==case['sha256'],'Source NEF changed: '+case['path']);checks.append(case['path'])
    old=read(ROOT/'analysis/modified1-nef-2026-11-09/pixels-v2/result.json')
    for case in old['files']:need(file_sha(case['path'])==case['sha256'],'Prior NEF changed')
    need(dec['ok'] and dec['total_pixels']==48997120 and len(dec['files'])==2,'Incomplete independent decoder check')
    for row in dec['files']:need(row['mismatches']==0,'Pixel decoder mismatch')
    need(spatial['ok'] and scales['ok'] and scales['scalar_check_count']==64 and summary['ok'],'Study checks failed')
    for f in spatial['files']:
        need(sum(x['n'] for x in f['phases'])==6048*4024,'Active count mismatch')
        need(sum(x['saturated'] for x in f['phases'])==0,'Unexpected saturation')
    with np.load(BASE/'spatial/maps.npz') as z:
        need(z['codes'].dtype==np.float64 and z['codes'].shape==(2,4,251,378),'Binning layout differs')
        need(np.all(np.isfinite(z['ratios'])),'Invalid ratio')
        need(np.allclose(z['ratio_difference_percent'],100*(z['ratios'][1]/z['ratios'][0]-1),rtol=0,atol=1e-12),'Ratio delta mismatch')
    pins={'firmware/original/Z_6_0380.bin':'ff978ffdf77c58c0b861a06e16d432d5886969f3cdd05d62f6c8e82e8a4cea54',
          'firmware/decoded/eg1620_038000.bi':'1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c',
          'outputs/Z6-C380-preflash-reviewed-2026-11-09/01_TEST/EG162080.BIN':'eeded80d4009204ba9760b6e20436aea3f6a37ce4ed6331ca662b839164a8875'}
    for rel,want in pins.items():need(file_sha(ROOT/rel)==want,'Firmware hash differs: '+rel)
    for row in read(BASE/'progress-update/changes.json')['changes']:
        need(file_sha(ROOT/row['path'])==row['after_sha256'],'Progress file changed')
        need(file_sha(ROOT/row['before_copy'])==row['before_sha256'],'Progress backup changed')
    report=ROOT/'docs/MODIFIED1_FLATS_2026-11-09.md'
    for link in re.findall(r'\]\(([^)]+)\)',report.read_text(encoding='utf8')):
        if not link.startswith('https:'):need((report.parent/link).exists(),'Missing report target '+link)
    commands=[]
    for f in sorted((BASE/'commands').glob('*/command.json')):
        v=read(f)
        # The verification command itself is finalized by its parent afterwards.
        if 'exit_code' in v:
            want=1 if f.parent.name=='09-verification' else 0
            need(v['exit_code']==want,'Unexpected recorded command failure')
            commands.append(dict(path=str(f.relative_to(ROOT)),exit_code=v['exit_code']))
    need(len(commands)==9,'Unexpected prior command count')
    write(target,dict(ok=True,created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        new_flat_files_unchanged=2,bias_files_unchanged=3,prior_sample_files_unchanged=len(old['files']),
        independent_decoded_values=dec['total_pixels'],independent_pixel_mismatches=0,scalar_block_checks=64,
        firmware_hashes=pins,report_sha256=file_sha(report),completed_commands_before_this_check=commands,
        corrected_verifier_issue='Initial verifier expected 128, but 2 frames x 8 sites x 4 phases is 64 successful scalar checks. Count corrected; numerical data unchanged; failed command and script retained.',
        interpretation='Integrity/method checks, not firmware ring-removal certification'))
    print(json.dumps(dict(ok=True,independent_pixels=dec['total_pixels'],scalar_checks=64)))

def index():
    target=BASE/'evidence-index.json';need(not target.exists(),'Index already exists')
    need(read(BASE/'verification.json')['ok'],'Study not verified')
    scripts=BASE/'script-snapshots';scripts.mkdir(exist_ok=False)
    names=['audit_nef.py','inventory_nas_nef.py','record_research_command.py','analyze_modified1_flats.py',
           'verify_modified1_decode.py','check_modified1_flat_scales.py','summarize_modified1_flat_shapes.py','finalize_modified1_flats.py']
    for name in names:(scripts/name).write_bytes((ROOT/'tools/fw'/name).read_bytes())
    docs=BASE/'document-snapshots';docs.mkdir(exist_ok=False)
    for rel in ['docs/MODIFIED1_FLATS_2026-11-09.md','README.md','docs/NEXT_STEPS.md','docs/PROJECT_GOALS.md']:
        (docs/rel.replace('/','-')).write_bytes((ROOT/rel).read_bytes())
    rows=[dict(path=str(f.relative_to(ROOT)),bytes=f.stat().st_size,sha256=file_sha(f)) for f in sorted(BASE.rglob('*')) if f.is_file()]
    commands=[dict(name=f.parent.name,**read(f)) for f in (BASE/'commands').glob('*/command.json')]
    need(len(commands)==10 and all(v.get('exit_code')==(1 if v['name']=='09-verification' else 0) for v in commands),'Formal command records incomplete')
    write(target,dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),argv=sys.argv,
        files=rows,command_count=len(commands),script_snapshot_count=len(names),
        status='Frozen round; later progress doc changes should be preserved in a new round'))
    print(json.dumps(dict(indexed_files=len(rows),commands=len(commands),script_snapshots=len(names))))

if __name__=='__main__':
    mode=sys.argv[1] if len(sys.argv)>1 else ''
    if mode=='update':update()
    elif mode=='verify':verify()
    elif mode=='index':index()
    else:raise SystemExit('Use update, verify or index')
