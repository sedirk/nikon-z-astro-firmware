"""Package the exact reviewed modified5 and explicit modified4/m1/stock rollbacks."""
from pathlib import Path
import argparse,datetime,json
from review_id35_preflash import ROOT,ROUND,SOURCES
from verify_id35_preflash_kit import PATHS,DIGESTS,need,read_module,sha,check_kit

def record(p,root):return dict(path=p.relative_to(root).as_posix(),bytes=p.stat().st_size,sha256=sha(p.read_bytes()))
def main():
    need(DIGESTS['test']!='76474a8977a3bf4b456fe68f9594110714a04c09b4ec575f019ba27fadd0d2d7',
         'RECALLED modified5: physical mechanical-shutter Err/restart. Do not repackage; use the 2026-11-10 recovery kit. Historical offline approval is superseded.')
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True)
    out=ap.parse_args().output.resolve();need(out.is_relative_to(ROOT/'outputs'),'Output location')
    a=json.loads((ROUND/'assessment.json').read_text());need(a['ok'] and a['candidate_sha256']==DIGESTS['test'],'Review mismatch')
    evidence=[]
    for name in ['assessment.json','static/result.json','updater/result.json','native-state/result.json']:
        p=ROUND/name;need(json.loads(p.read_text())['ok'],'Failed review '+name);evidence.append(record(p,ROOT))
    evidence+=a['qemu_runs']
    out.mkdir(parents=True,exist_ok=False)
    for mode,p in SOURCES.items():
        target=out/PATHS[mode];target.parent.mkdir();target.write_bytes(read_module(p,mode))
    for source,target in (
        ('docs/Z6_ID35_INSTALL_2026-11-09.txt','START_HERE.txt'),
        ('docs/Z6_ID35_FLAT_COMPARE_2026-11-09.txt','FLAT_COMPARE.txt'),
        ('docs/ID35_PREFLASH_REVIEW_2026-11-09.md','REVIEW.md'),
        ('tools/fw/verify_id35_preflash_kit.py','verify.py'),
        ('outputs/Z6-C380-preflash-reviewed-2026-11-09/baseline112.json','baseline112.json')):
        (out/target).write_bytes((ROOT/source).read_bytes())
    recipe=json.loads((ROOT/'patches/z6-c380-id35-static-call-off-lab.json').read_text())
    recipe['historical_status']=recipe['status'];recipe['status']='Exact LAB bytes passed bounded offline preflash review for controlled modified5 testing.'
    recipe['delivery_sha256']=DIGESTS['test'];recipe['installation_review_complete']=True
    recipe['review_scope']=a['risk_scope'];recipe['review_evidence']=evidence
    recipe['known_qemu_timeout']=a['qemu_timeout_audit']
    (out/'patch-recipe.json').write_text(json.dumps(recipe,indent=2),encoding='utf8')
    (out/'SHOT_LOG_TEMPLATE.txt').write_text('''Z6 modified5 拍摄记录（另存副本填写）
A modified4 / B modified5 / C 回退（明确实际版本）：
卡上文件 SHA-256、校验结果、更新完成时间及提示：
机身、镜头、焦距、光圈、手动焦点、VR、快门方式：
NEF 位深/压缩/尺寸；降噪及其它校正菜单：
光源画面、亮度、扩散/膜；相机距离、角度、位置是否保持：
室温、开机时长、拍摄间隔和顺序：

普通单张 NEF、保存/回放/放大情况：
三次单张拍摄后取景/回放/拨轮；关机重开后再次试拍：
平场低/中/高信号档的快门和各三张文件名：
dark ISO1600 5秒三张文件名：
bias ISO1600最短快门三张文件名：
可选历史高速平场 ISO1600 f/1.8 1/8000秒文件名：
是否移动或调焦、PWM条带、过曝、黑帧、卡顿、其它异常：
是否回退、所用版本/哈希及实际结果：
''',encoding='utf8')
    manifest=dict(schema=5,created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        model='First-generation Nikon Z6',version='C3.80',candidate='modified5',verdict=a['verdict'],
        basis='Exact modified4 parent, prior 244 native differential pairs and new install/state review; no modified5 physical results.',
        static_capture_scope=True,nef_exclusive=False,prior_lab_bytes_unchanged=True,
        physical_modified5_boot=False,physical_modified5_nef=False,physical_dark_regression=False,ring_removal_verified=False,
        module_sha256=DIGESTS,evidence=evidence,known_qemu_timeout=a['qemu_timeout_audit'],
        original_container=dict(path='firmware/original/Z_6_0380.bin',sha256='ff978ffdf77c58c0b861a06e16d432d5886969f3cdd05d62f6c8e82e8a4cea54'),
        files=[record(p,out) for p in sorted(out.rglob('*')) if p.is_file()])
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf8')
    print(json.dumps(dict(output=str(out),ok=True,**check_kit(out)),indent=2))

if __name__=='__main__':main()
