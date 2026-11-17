"""Assemble the exact reviewed modified2 files and two separate recovery choices."""
from pathlib import Path
import argparse, datetime, json, shutil
from review_vignette_preflash import SOURCES, ROOT
from verify_vignette_preflash_kit import PATHS, DIGESTS, read_module, check_kit, need, sha

ROUND=ROOT/'analysis/vignette-preflash-2026-11-09'


def row(path, root):
    data=path.read_bytes()
    return dict(path=path.relative_to(root).as_posix(), bytes=len(data), sha256=sha(data))


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();out=args.output.resolve();need(out.is_relative_to(ROOT/'outputs'),'Output outside project outputs')
    evidence=[]
    for relative in ('static/result.json','state-final/result.json','updater/result.json'):
        path=ROUND/relative;data=json.loads(path.read_text())
        need(data['ok'],'Review failed: '+relative);evidence.append(row(path,ROOT))
    need(len(json.loads((ROUND/'state-final/result.json').read_text())['transitions'])==64,'Incomplete state test')
    out.mkdir(parents=True,exist_ok=False)
    for mode,source in SOURCES.items():
        data=read_module(source,mode);target=out/PATHS[mode];target.parent.mkdir();target.write_bytes(data)
    for source,target in (
        ('docs/Z6_VIGNETTE_INSTALL_2026-11-09.txt','START_HERE.txt'),
        ('docs/Z6_VIGNETTE_FLAT_COMPARE_2026-11-09.txt','FLAT_COMPARE.txt'),
        ('docs/VIGNETTE_PREFLASH_REVIEW_2026-11-09.md','REVIEW.md'),
        ('tools/fw/verify_vignette_preflash_kit.py','verify.py'),
        ('outputs/Z6-C380-preflash-reviewed-2026-11-09/baseline112.json','baseline112.json')):
        shutil.copyfile(ROOT/source,out/target)
    recipe=json.loads((ROOT/'patches/z6-c380-still-vignette-neutral-lab.json').read_text())
    recipe['historical_status']=recipe['status']
    recipe['status']='Exact bytes preflash-reviewed on 2026-11-09 for controlled modified2 hardware test; physical boot, recovery and ring removal pending.'
    recipe['delivery_sha256']=DIGESTS['test']
    recipe['review_evidence']=evidence
    (out/'patch-recipe.json').write_text(json.dumps(recipe,indent=2,ensure_ascii=False),encoding='utf8')
    (out/'SHOT_LOG_TEMPLATE.txt').write_text('''Z6 modified2 平场／暗场记录（复制后填写）
组别：A modified1 / B modified2 / C 回退后（明确 modified1 或 stock）：
刷入文件 SHA-256、卡上校验结果和更新完成时间：
相机型号、C 版本、机身编号（可沿用已有记录）：
镜头、焦距、光圈、对焦位置、VR、快门方式：
NEF 位深、压缩、FX/尺寸：
暗角档位、其它镜头校正、两项降噪、自动 ISO：
平板画面、亮度、方向、距离和位置是否移动：
室温大致情况、开机多久、拍摄间隔：

slow_flat：ISO / f / 实际快门 / 3 个文件名 / 时间
  低信号：
  中信号：
  高信号：
bias_iso100：实际 ISO / 最短快门 / 3 个文件名
dark_iso1600_5s：实际 ISO / 快门 / 3 个文件名
fast_flat（可选）：ISO1600 f1.8 1/8000 / 3 个文件名
rotate180（可选）：条件 / 文件名
普通 NEF 完整解码结果：
PWM／饱和／位置变化／相机报错等观察：
实际回退是否进行、所用文件和结果：
''',encoding='utf8')
    manifest=dict(schema=2,created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        model='First-generation Nikon Z6',version='C3.80',candidate='modified2',
        verdict='Offline preflash review passed; controlled physical test candidate',
        basis='User installed project modified1 and supplied physical NEFs; modified2 physical operation pending',
        prior_lab_bytes_unchanged=True,module_sha256=DIGESTS,evidence=evidence,
        original_container=dict(path='firmware/original/Z_6_0380.bin',sha256='ff978ffdf77c58c0b861a06e16d432d5886969f3cdd05d62f6c8e82e8a4cea54'),
        files=[row(p,out) for p in sorted(out.rglob('*')) if p.is_file()])
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf8')
    print(json.dumps(dict(output=str(out),**check_kit(out)),indent=2))


if __name__=='__main__':main()
