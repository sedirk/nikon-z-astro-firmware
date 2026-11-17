"""Package a single independently tested Z6 C3.80 experimental EG module.

Original files stay in place. No camera/card operation, composite RAW patch,
firmware version spoofing, upgrade-check patch or outer-container signing.
"""
from pathlib import Path
import argparse,datetime,hashlib,json
from build_raw_candidates import apply_candidate
from verify_neighborhood_package import reconstruct

ROOT=Path(__file__).resolve().parents[2]
DIR=ROOT/'analysis/raw-control-convergence-2026-11-09'
TEXT='''Nikon Z6 C3.80：静态邻域控制关闭候选

状态：原厂控制链与原厂升级文件检查已离线验证；尚未进行真机安装和候选 NEF 验收。
这是供下一阶段实机实验审阅的单一候选，不是已验收的天文 RAW 固件。

candidate/EG162080.BIN 是完整的原厂 EG 模块副本，仅修改三条指令
（10 个代码字节）并重算模块 CRC（2 字节），总共变化 12 字节。
作用范围是静态参数生成器正常分支：分类=0、两路 override=强制关闭。
它在所测原厂链路中使 bank+584 和 bank+594 为零。
四路负偏移、0x720、空间表、BlackLevel 和 RAW 输出选择维持原路径。
没有合并此前全尺寸输入保留补丁，没有加快门声、菜单或第三方载入器。

升级文件入口：原厂 EG1620??.BIN 单模块路径。
原版 C3.80 指令已执行文件名识别、版本读取、完整文件 CRC、组件预检，
以及写入前缓冲准备；实验停在 flash 写入原语之前，未调用该原语。
文件服务使用只读主机适配器，OS 锁、通知和显示配置使用显式夹具。
上述结果对应离线代码路径，不代表相机已经刷入或恢复测试完成。
实验包不会自动操作相机或存储卡。暂不提供自动刷写脚本。

重要更正：项目先前的 Z_6_0380 风格整包只验证了 CRC，保留了旧 SHA-1
文件头。本轮已撤出该整包安装路线；本包 EG 模块不使用那层整包摘要。
单模块路径是原固件已有入口，未修改原厂升级检查。

本机检查（仅标准 Python 库）：
  python verify_or_restore.py
如需重建原始 EG 副本（输出文件必须不存在）：
  python verify_or_restore.py --restore-to 原版EG副本.BIN
重建结果须符合 manifest 中的原版 SHA-256。
这只是逐字节重建，不等于验证过相机的故障恢复。
原始完整固件继续保存在项目 firmware/original/Z_6_0380.bin。

下一阶段像素验收：
1. 使用建立 112 点基线的同一机身（样本机身 8006677），ISO 1600、
   14 位无损、全尺寸，长曝降噪与高 ISO 降噪关闭；保留原版条件记录。
2. 以原版/候选/恢复原版的匹配暗场与 bias 比较，记录曝光、温度或间隔、
   快门方式及实际文件哈希；5 秒先复用已有条件，不把温度漂移当补丁作用。
3. 使用 baseline112.json 的完整 RAW 零基坐标，核对中心值、最近同色八邻域
   最大值、delta=中心-max8 和 8 DN 分布；统计新点及正常邻域作对照。
4. 邻域关系改变仅验收这条候选。暗电流保留需曝光/温度序列和外部暗场校准；
   消圈需多信号级平场、R/G 与 B/G 空间剖面及实际叠加验证，仍分项推进。
5. 检查 NEF 解码、像素几何、饱和、短/长曝光及连拍稳定性后，再确定支持范围。

native_evidence.json 列出本包对应的运行结果哈希；recipe.json 为精确修改配方。
完整命令、反汇编、内存差分及失败记录在项目
analysis/raw-control-convergence-2026-11-09/，报告在
docs/RAW_CONTROL_CONVERGENCE_2026-11-09.md。
'''

def sha(b):return hashlib.sha256(b).hexdigest()
def load(p):return json.loads(p.read_text(encoding='utf8'))

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();original=ROOT/'firmware/decoded/eg1620_038000.bi'
    data=original.read_bytes();catalog_path=ROOT/'patches/z6-c380-still-neighborhood-off.json'
    catalog=load(catalog_path);candidate,recipe=apply_candidate(data,catalog,catalog['candidates'][0])
    assert candidate==(DIR/'module/still-neighborhood-gates-off.bi').read_bytes()
    assert reconstruct(candidate,recipe)==data
    evidence=[]
    for folder in ('native-matrix','encoder-bridge','eg-preflash-contract'):
        path=DIR/folder/'result.json';r=load(path);assert r['ok']
        if folder=='native-matrix':assert len(r['matrix'])==1296 and len(r['comparisons'])==16
        elif folder=='encoder-bridge':assert len(r['chains'])==32 and len(r['comparisons'])==16
        else:
            assert len(r['cases'])==6
            for row in r['cases']:
                if row['label'] in ('candidate','candidate_full_display'):
                    assert row['sha256']==sha(candidate) and row['integrity_return']==0
                    assert row['preflash']['stopped_before']=='0x1014a674'
        evidence.append(dict(path=path.relative_to(ROOT).as_posix(),sha256=sha(path.read_bytes())))
    a.output.mkdir(parents=True,exist_ok=False);(a.output/'candidate').mkdir()
    (a.output/'candidate/EG162080.BIN').write_bytes(candidate)
    (a.output/'recipe.json').write_text(json.dumps(recipe,indent=2),encoding='utf8')
    (a.output/'native_evidence.json').write_text(json.dumps(evidence,indent=2),encoding='utf8')
    fp=load(ROOT/'analysis/raw-neighborhood-2026-11-09/fingerprint/result.json')
    baseline={k:fp[k] for k in ('source_sha256','coordinates','kernel_R_B','kernel_G1_G2','formula','discovery112','targets')}
    baseline.update(body_serial='8006677',geometry=[4040,6064],iso=1600,dark_exposure_seconds=5,
        warning='Discovery-selected original-firmware sites; confirm the same body/settings. No candidate capture has been supplied.')
    (a.output/'baseline112.json').write_text(json.dumps(baseline,indent=2),encoding='utf8')
    (a.output/'verify_or_restore.py').write_bytes((ROOT/'tools/fw/verify_neighborhood_package.py').read_bytes())
    (a.output/'README.txt').write_text(TEXT,encoding='utf8')
    manifest=dict(schema=1,id=recipe['id'],model='Nikon Z6 first generation',version='C3.80',
        status='Experimental EG module; native control/file-preflight verified; physical installation and pixels pending',
        created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),recipe=recipe,
        builder_sha256=sha(Path(__file__).read_bytes()),catalog_sha256=sha(catalog_path.read_bytes()),
        package_route='original raw EG1620??.BIN path',outer_container_included=False,
        original_unchanged=original.read_bytes()==data,combined_candidate=False,
        physical_installation_verified=False,physical_recovery_verified=False,raw_pixel_effect_verified=False,
        files=[dict(path=q.relative_to(a.output).as_posix(),bytes=q.stat().st_size,sha256=sha(q.read_bytes()))
            for q in sorted(a.output.rglob('*')) if q.is_file()])
    (a.output/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf8')
    print(json.dumps(dict(ok=True,output=str(a.output),module_sha256=sha(candidate),files=len(manifest['files']))))

if __name__=='__main__':main()
