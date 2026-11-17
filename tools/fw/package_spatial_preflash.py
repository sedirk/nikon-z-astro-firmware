"""Package exact reviewed modified3 bytes with three explicit rollback choices."""
from pathlib import Path
import argparse,datetime,json,shutil
from review_spatial_preflash import ROOT,ROUND,SOURCES
from verify_spatial_preflash_kit import PATHS,DIGESTS,need,read_module,sha,check_kit

def record(path,root):return dict(path=path.relative_to(root).as_posix(),bytes=path.stat().st_size,sha256=sha(path.read_bytes()))
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    out=a.output.resolve();need(out.is_relative_to(ROOT/'outputs'),'Output outside project outputs')
    assessment=json.loads((ROUND/'assessment.json').read_text());need(assessment['ok'],'Review not accepted')
    need(assessment['candidate_sha256']==DIGESTS['test'],'Review for another candidate')
    evidence=[]
    for name in ('assessment.json','static/result.json','updater/result.json','qemu-modified2-final/result.json',
                 'qemu-modified3/result.json','qemu-menu-modified2-final/result.json','qemu-menu-modified3-final/result.json'):
        path=ROUND/name;need(json.loads(path.read_text())['ok'],'Review file failed '+name);evidence.append(record(path,ROOT))
    out.mkdir(parents=True,exist_ok=False)
    for mode,path in SOURCES.items():
        data=read_module(path,mode);target=out/PATHS[mode];target.parent.mkdir();target.write_bytes(data)
    for source,target in (
        ('docs/Z6_SPATIAL_INSTALL_2026-11-09.txt','START_HERE.txt'),
        ('docs/Z6_SPATIAL_FLAT_COMPARE_2026-11-09.txt','FLAT_COMPARE.txt'),
        ('docs/SPATIAL_PREFLASH_REVIEW_2026-11-09.md','REVIEW.md'),
        ('tools/fw/verify_spatial_preflash_kit.py','verify.py'),
        ('outputs/Z6-C380-preflash-reviewed-2026-11-09/baseline112.json','baseline112.json')):
        shutil.copyfile(ROOT/source,out/target)
    recipe=json.loads((ROOT/'patches/z6-c380-spatial-neutral-lab.json').read_text())
    recipe['historical_status']=recipe['status']
    recipe['status']='Exact bytes reviewed for controlled modified3 physical test; shared scope, physical boot/recovery/ring removal pending.'
    recipe['delivery_sha256']=DIGESTS['test'];recipe['review_evidence']=evidence
    (out/'patch-recipe.json').write_text(json.dumps(recipe,indent=2),encoding='utf8')
    (out/'SHOT_LOG_TEMPLATE.txt').write_text('''Z6 modified3 拍摄记录（另存副本填写）
A modified2 / B modified3 / C 回退（明确版本）：
卡上校验结果、SHA-256、更新完成时间：
机身型号、编号、菜单版本：
镜头、焦距、光圈、手动对焦、VR、快门方式：
NEF 位深、压缩、尺寸；降噪、暗角及其它校正菜单：
光源画面、亮度、膜/扩散、相机和平板位置/角度/距离：
开机时间、室温大致情况、拍摄间隔、是否移动装置：

普通试拍 NEF / 保存、回放、取景情况：
主平场（固定 ISO/光圈）：
低信号 快门 / 3 个文件名：
中信号 快门 / 3 个文件名：
高信号 快门 / 3 个文件名：
dark ISO1600 5 秒 / 3 个文件名：
bias 同 ISO 最短快门 / 3 个文件名：
可选高速平场 ISO1600 f1.8 1/8000 / 文件名：
其它组（明确与主组区别）：
条带、明显过曝或异常记录：
是否实际回退、文件版本、结果：
''',encoding='utf8')
    manifest=dict(schema=3,created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),model='First-generation Nikon Z6',
        version='C3.80',candidate='modified3',verdict=assessment['verdict'],basis='User supplied physical modified1 darks and modified2 flats; this candidate has offline evidence only.',
        shared_spatial_scope=True,prior_lab_bytes_unchanged=True,module_sha256=DIGESTS,evidence=evidence,
        original_container=dict(path='firmware/original/Z_6_0380.bin',sha256='ff978ffdf77c58c0b861a06e16d432d5886969f3cdd05d62f6c8e82e8a4cea54'),
        files=[record(p,out) for p in sorted(out.rglob('*')) if p.is_file()])
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf8')
    print(json.dumps(dict(output=str(out),ok=True,**check_kit(out)),indent=2))
if __name__=='__main__':main()
