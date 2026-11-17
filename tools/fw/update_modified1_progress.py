"""Record a first physical NEF milestone with preserved pre-edit documents."""
from pathlib import Path
import datetime,hashlib,json
ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'analysis/modified1-nef-2026-11-09/progress-update'
def digest(b):return hashlib.sha256(b).hexdigest()
def main():
    OUT.mkdir(parents=True,exist_ok=False);changes=[]
    blocks={
    'README.md':'''\n**2026-11-09 最新实机结果：**用户已刷入三指令邻域关闭候选并提供 7 张新 NEF。冻结的 112 个目标点在原版两张 5 秒 dark 中全部符合 max8＋8×k，在候选三张中均为 0/112；强暗信号实际保留到 NEF。新文件 171,489,920 个码值经独立解码逐一一致。[实拍报告](docs/MODIFIED1_REAL_NEF_2026-11-09.md)与[对照图](analysis/modified1-nef-2026-11-09/assessment/modified1-evidence.png)为当前状态；下一步优先短曝光与实际回退对照，整体暗电流和消圈继续分项验收。\n\n以下为此前研究记录；包内“尚未实拍”等状态反映各自生成时间。\n''',
    'docs/NEXT_STEPS.md':'''\n## 当前优先级（2026-11-09，首次候选实机 NEF）\n\n[新实拍证据](MODIFIED1_REAL_NEF_2026-11-09.md)：7 张候选 NEF 完整解码；112 点的原版邻域指纹在三张候选 5 秒暗场全部消失。对应原厂控制链现在有真实保存像素支持，优先扩大有效条件与可用性。\n\n1. **先固定已有实机结果。** 保持当前候选不叠加改动，增加 0.1/0.5/1/5 秒的同条件暗场与 bias，避免 5 秒下热点饱和，测非饱和曝光增长。\n2. **用一次实际回退复拍检验可逆性。** 同时段原版补 3 bias 和 3 张 5 秒 dark，查看冻结 112 点指纹是否恢复；记录温度、时间和菜单更新完成状态。\n3. **把效果范围做成可用支持表。** ISO、曝光、机械/电子快门、单张/连拍、普通星点与外部暗场校准逐项验收；不重复已经通过的离线矩阵来代替相机稳定性。\n4. **区分两路控制的作用，随后逐项推进其他校正。** 当前三处修改整体有效的实拍证据已取得，+584/+594 各子路径的职责保持未分离状态；四负偏移、0x720、前端固定标定和空间表继续独立追踪。\n5. **彩圈转入同机身平场验证。** 用固定光学条件、多信号级 R/G 和 B/G 剖面；不把这次热点保留扩大为彩圈已经解决。\n\n以下为先前阶段计划，涉及“等待首次 NEF”的事项已由本轮样本推进。\n''',
    'docs/PROJECT_GOALS.md':'''\n## 当前进展（2026-11-09，首次实机 NEF）\n\n最终目标保持不变。三指令邻域关闭候选已由用户刷入并产出 7 张可完整解码的 NEF；预先冻结的 112 点在三张候选暗场中全部脱离原版 max8＋8×k 指纹，强暗信号保存到文件。该局部处理的实机效果取得明确证据；暗电流整体统计、所有 RAW 校正、彩圈、实际回退和稳定性分别继续验收。详见[本轮实拍报告](MODIFIED1_REAL_NEF_2026-11-09.md)。下方保留既定需求和各历史阶段描述。\n'''}
    for rel,block in blocks.items():
        path=ROOT/rel;before=path.read_bytes();text=before.decode('utf8');first,rest=text.split('\n',1)
        if '最新实机结果' in text or '首次候选实机 NEF' in text:raise ValueError('Milestone already applied')
        after=(first+'\n'+block+'\n'+rest).encode('utf8')
        backup=OUT/('before-'+rel.replace('/','-'));backup.write_bytes(before);path.write_bytes(after)
        changes.append(dict(path=rel,before_sha256=digest(before),after_sha256=digest(after),before_copy=str(backup.relative_to(ROOT))))
    (OUT/'changes.json').write_text(json.dumps(dict(utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        reason='First candidate physical NEFs supplied and analyzed',changes=changes),indent=2),encoding='utf8')
    (OUT/Path(__file__).name).write_bytes(Path(__file__).read_bytes())
    print(json.dumps(dict(updated=len(changes),backups=str(OUT))))
if __name__=='__main__':main()
