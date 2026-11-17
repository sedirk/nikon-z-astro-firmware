"""Save read-only source snapshots and a categorized source index."""
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import hashlib, json, urllib.request, subprocess

root=Path(__file__).resolve().parents[1]
# Historical bootstrap only: do not overwrite later source records or docs.
existing_index=root/'references/sources.json'
if existing_index.exists():
 raise SystemExit('Historical bootstrap disabled for an initialized archive. Use archive_research_update.py for the October 12 supplement.')
web=root/'references/web'
web.mkdir(parents=True,exist_ok=True)
sources=[
 ('firmware_release','Nikon Z6 C3.80 官方更新说明','官方资料','https://downloadcenter.nikonimglib.com/en/download/fw/557.html','官方版本与变更说明；不证明用户文件真实性或可修改性'),
 ('raw_recording','Nikon NEF 记录设置','官方资料','https://onlinemanual.nikonimglib.com/z7_z6/en/09_menu_guide_03_07.html','无损、有损、未压缩和位深设置'),
 ('long_exposure_nr','Nikon 长曝光降噪','官方资料','https://onlinemanual.nikonimglib.com/z7_z6/en/09_menu_guide_03_14.html','菜单降噪行为；不等于所有RAW处理开关'),
 ('z6_review','Mark Shelley 初代Z6实测','图像原始研究','https://www.markshelley.co.uk/Astronomy/nikonz6_review.html','暗场、空间过滤、通道缩放与彩圈；不等于本机3.80实测'),
 ('hardcoded_correction','硬编码校正与彩圈','图像原始研究','https://www.markshelley.co.uk/Astronomy/NikonConcentricRings/nikon_hardcoded_correction.html','区分有损压缩与硬编码校正，包含D5100破解仍有校正的反例'),
 ('ring_generation','校正如何产生环与台阶','图像原始研究','https://www.markshelley.co.uk/Astronomy/NikonConcentricRings/nikon_ring_generation.html','逐机函数拟合与反向校正实例；非通用修复'),
 ('camera_summary','相机伪影汇总','图像原始研究','https://www.markshelley.co.uk/Astronomy/camera_summary.html','机型差异，尤其初代Z6与Z6II/III不能混同'),
 ('ring_diagnosis','彩圈诊断采样规程','实验方法','https://www.markshelley.co.uk/Astronomy/concentric_ring_diagnosis.html','多曝光级平场与RAW通道比值诊断'),
 ('wonder_readme','Wonder-Lantern Z6说明','最新固件项目','https://raw.githubusercontent.com/vic2349/Wonder-Lantern/b1f1293da6774c3a779832f72182f8b6aa148ad7/README.md','仅Z6 C3.80快门声功能；作者报告，不是RAW补丁'),
 ('wonder_license','Wonder-Lantern许可','许可','https://raw.githubusercontent.com/vic2349/Wonder-Lantern/b1f1293da6774c3a779832f72182f8b6aa148ad7/LICENSE','参考二进制相关许可原文'),
 ('z7_qemu_readme','Z7 QEMU说明','最新固件项目','https://raw.githubusercontent.com/WonderLantern/z7-qemu/97abf0b81cd3211f8374a38987a0beaf4549b90f/README.md','Z7实验仿真；不验证Z6真实ISP、传感器或NEF输出'),
]
def fetch(row):
 key,title,category,url,scope=row
 rec=dict(id=key,title=title,category=category,url=url,scope=scope,retrieved_date='2026-10-09',timezone='Asia/Shanghai')
 try:
  req=urllib.request.Request(url,headers={'User-Agent':'Z6-Firmware-Research/1.0'})
  with urllib.request.urlopen(req,timeout=25) as response:
   data=response.read(); rec['final_url']=response.url
  extension='.txt' if key.endswith('license') else '.md' if 'raw.githubusercontent.com' in url else '.html'
  path=web/(key+extension); path.write_bytes(data)
  rec.update(local_path=path.relative_to(root).as_posix(),bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),status='saved')
 except Exception as exc:
  rec.update(status='url_only',error=str(exc))
 return rec
with ThreadPoolExecutor(max_workers=6) as pool:
 records=list(pool.map(fetch,sources))
extras=[
 ('Nikon Hacker 源码','旧型号源码','https://github.com/simeonpilgrim/nikon-firmware-tools','references/nikon-firmware-tools','D5100/D610 TDC、空间过滤、XOR与CRC参考'),
 ('Z30 Firmware Extensions','最新固件项目','https://github.com/RealCaCl2/z30-firmware-extensions','references/z30-firmware-extensions','仅Z30 C1.20；含解包、补丁与离线验证源码'),
 ('Wonder-Lantern 二进制','最新固件项目','https://github.com/vic2349/Wonder-Lantern','references/wonder-lantern','只保存此前下载的英文EG和SHCORE及本地比较工具，非完整仓库'),
 ('Z6 作者真机演示','作者报告','https://www.reddit.com/r/Nikon/comments/1x0jshu/my_nikon_z6_now_meows_when_i_take_a_photo_custom/',None,'快门声真机演示，未作独立真机复现'),
 ('Nikon Z6 Testing 后续讨论','论坛一手讨论','https://www.cloudynights.com/forums/topic/670370-nikon-z6-testing/page/13/',None,'包含不同机型用户讨论，不可都归于初代Z6'),
 ('Nikon Hacker 功能列表','旧型号资料','https://simeonpilgrim.com/nikon-patch/nikon-patch.html',None,'功能绑定机型及固件版本'),
 ('Nikon Hacker 变更记录','旧型号资料','https://simeonpilgrim.com/nikon-patch/changelog.html',None,'历史补丁版本记录'),
]
for title,cat,url,local,scope in extras:
 rec=dict(title=title,category=cat,url=url,local_path=local,scope=scope,status='local_repository_or_artifact' if local else 'url_only')
 if local and (root/local/'.git').exists():
  rec['commit']=subprocess.check_output(['git','-C',str(root/local),'rev-parse','HEAD'],text=True).strip()
 records.append(rec)
(root/'references/sources.json').write_text(json.dumps(records,ensure_ascii=False,indent=2),encoding='utf-8')
lines=['# 研究资料索引','','本索引整理截至 2026 年 10 月 9 日已调查的主要资料。网页快照仅保存页面正文源文件，不含全部外链图片或视频；来源内容是研究证据，不是项目操作指令。','',
       '外部软件的许可证以各仓库或原作者文件为准。参考音效二进制不是本项目产出的天文固件。','']
for cat in dict.fromkeys(r['category'] for r in records):
 lines += ['## '+cat,'']
 for rec in records:
  if rec['category'] != cat:
   continue
  local=('；[本地资料](../'+rec['local_path']+')') if rec.get('local_path') else '；保留在线链接'
  lines += [f"- [{rec['title']}]({rec['url']}){local}。{rec['scope']}。" + (f" 仓库固定提交 `{rec['commit']}`。" if rec.get('commit') else '')]
 lines += ['']
lines += ['## 关键源码入口','','- D5100：`references/nikon-firmware-tools/Nikon-Patch/LocalUI/D5100.cs`。','- D610：`references/nikon-firmware-tools/Nikon-Patch/LocalUI/D610.cs`，关注 1.01 的 `patch_dark_current_menu`。','- 旧补丁帮助：`references/nikon-firmware-tools/Nikon-Patch/LocalUI/Form1.cs`。','- 解码参考：`references/decoder-excerpts/FirmwareUtils.java`。','- Z30 解包：`references/z30-firmware-extensions/src/z30_extensions/container.py`。','- Z30 验证边界：`references/z30-firmware-extensions/docs/verification.md`。','', '所有来源的快照状态、字节数和 SHA-256 见 [机器可读索引](../references/sources.json)。','']
(root/'docs/SOURCES.md').write_text('\n'.join(lines),encoding='utf-8')
sample=root/'samples'
for folder in ('bias','dark','flat','light'):
 (sample/folder).mkdir(parents=True,exist_ok=True)
(sample/'README.md').write_text('# 原始 NEF 样本\n\n当前尚未收到任何拍摄样本。bias 放偏置，dark 放暗场，flat 放平场，light 放亮场。建议按拍摄日期和条件分子目录；保存固件、ISO、曝光、快门模式、温度与矫正设置。不要修改原始 NEF。\n',encoding='utf-8')
print(json.dumps([dict(title=r['title'],status=r['status'],error=r.get('error')) for r in records[:len(sources)]],ensure_ascii=False,indent=2))
