from pathlib import Path
import hashlib, json, re, argparse

root=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description='Build static evidence report; no firmware modification or camera access.')
parser.add_argument('--output',default='outputs/Z6_0380_static_analysis_current.json')
args=parser.parse_args()
report=json.loads((root/'analysis/z6_analysis.json').read_text(encoding='utf-8'))
comparison=json.loads((root/'references/wonder-lantern/comparison.json').read_text(encoding='utf-8'))
report['investigation_date']='2026-10-09 (Asia/Shanghai)'
report['scope_zh']='初代 Nikon Z6 C3.80 固件可修改性与天文RAW目标的可行性分析；静态分析，没有连接或刷写相机。'
report['conclusion_zh']={
 'confirmed_locally':[
  '提供的文件可用已公开 Nikon 标准周期 XOR 算法解码；先跳过32字节外前缀，body前32字节保持空格。',
  '模块目录、边界、连续覆盖、整包CRC及4个模块CRC全部通过。',
  '未修改body重新编码后与原输入逐字节相同；原输入文件哈希未改变。',
  'Wonder-Lantern英文EG与该文件的原始EG等长，相差5020字节，公开SHA-256匹配README，模块CRC余数为0。'],
 'supported_by_author_report':[
  'Wonder-Lantern作者2026-10-08发布Z6 C3.80自定义快门声固件及真机演示；本次没有独立真机复现。'],
 'not_established':[
  '尚未定位并验证Z6关闭暗信号修正、RAW空间过滤、通道预缩放或硬编码颜色阴影校正的补丁。',
  'CRC和原样往返不能证明修改后相机会接受固件；没有全面逆向启动/更新完整性机制，也没有证明不存在其他验证。',
  '可读服务名称只是调查线索，不等于功能入口、硬件寄存器、补丁偏移或已确认的NEF像素处理路径。',
  '源码/作者演示/二进制差异证据不能证明任意机身稳定可用或保证故障恢复。',
  '公开实测报告不等于本用户机身与3.80版本的实测，仍须用原始NEF建立基线。'],
 'assessment_zh':'具备开展Z6定向RAW补丁逆向研究的现实条件；不能交付已验证的去彩圈/全关闭RAW处理固件。'
}
report['wonder_lantern_comparison']=comparison
report['wonder_lantern_comparison']['source_url']='https://github.com/vic2349/Wonder-Lantern'
data=(root/'firmware/decoded/eg1620_038000.bi').read_bytes()
targets=[b'CaptureSensorSer',b'NonVolatileMemor',b'FrontEndService',b'BackEndService',b'ImageCalcService',b'ImageFormatServi',b'CaptureSequenceS',b'PixelMappingServ',b'AdjustmentServic',b'AdjustmentDataSe',b'AImageProcessDriv',b'BImageProcessServ',b'CPipelineService',b'IMPRAWRS',b'IMPRAW',b'STGRAW']
report['research_string_anchors_not_patch_sites']=[]
for term in targets:
 pos=data.find(term+b'\0')
 if pos>=0:
  report['research_string_anchors_not_patch_sites'].append({'ascii':term.decode(),'eg_file_offset_hex':hex(pos)})
report['next_research_steps_zh']=[
 '建立该机身原版C3.80 NEF基线：14-bit无损/未压缩；记录所有拍摄设置、ISO、温度和快门模式。',
 '用多个曝光级的均匀平场，浮点减bias后分析R/G、B/G空间台阶；单独分析暗场黑裁切和空间过滤。',
 '在EG中做代码交叉引用和调用链/寄存器追踪，确认静态NEF从读出到编码的实际管线；服务名只是起点。',
 '分别确认颜色阴影校正、热像素过滤、暗信号/偏置处理及通道缩放的可控性；查明逐机标定参数来源。',
 '只有确认处理语义、原字节、版本身份、运行路径与恢复条件后，再设计单功能可开关补丁及真机A/B验收。'
]
report['sources']=[
 {'role':'Nikon Z6 C3.80 official release','url':'https://downloadcenter.nikonimglib.com/en/download/fw/557.html'},
 {'role':'Public XOR implementation used for static decoder','url':'https://github.com/simeonpilgrim/nikon-firmware-tools/blob/de8019ee30db7fe7bc61e520da289078ae82dcaa/Java/Emulator/src/main/com/nikonhacker/encoding/FirmwareUtils.java'},
 {'role':'Z6 C3.80 custom shutter sound','url':'https://github.com/vic2349/Wonder-Lantern'},
 {'role':'Author hardware demonstration','url':'https://www.reddit.com/r/Nikon/comments/1x0jshu/my_nikon_z6_now_meows_when_i_take_a_photo_custom/'},
 {'role':'Z30 C1.20 source project; not a Z6 RAW patch','url':'https://github.com/RealCaCl2/z30-firmware-extensions'},
 {'role':'Z7 emulator; not real-camera RAW validation','url':'https://github.com/WonderLantern/z7-qemu'},
 {'role':'D5100 old dark-current patch','url':'https://github.com/simeonpilgrim/nikon-firmware-tools/blob/de8019ee30db7fe7bc61e520da289078ae82dcaa/Nikon-Patch/LocalUI/D5100.cs#L215-L224'},
 {'role':'D610 1.01 old menu patch','url':'https://github.com/simeonpilgrim/nikon-firmware-tools/blob/de8019ee30db7fe7bc61e520da289078ae82dcaa/Nikon-Patch/LocalUI/D610.cs#L147-L170'},
 {'role':'Z6 dark frame and filtering research','url':'https://www.markshelley.co.uk/Astronomy/nikonz6_review.html'},
 {'role':'Nikon hardcoded correction and D5100 counterexample','url':'https://www.markshelley.co.uk/Astronomy/NikonConcentricRings/nikon_hardcoded_correction.html'},
 {'role':'Per-body shading model','url':'https://www.markshelley.co.uk/Astronomy/NikonConcentricRings/nikon_ring_generation.html'},
 {'role':'Recent camera-specific summary','url':'https://www.markshelley.co.uk/Astronomy/camera_summary.html#NikonZ6_Z7'},
 {'role':'Flat-field test protocol','url':'https://www.markshelley.co.uk/Astronomy/concentric_ring_diagnosis.html'},
 {'role':'Official RAW compression settings','url':'https://onlinemanual.nikonimglib.com/z7_z6/en/09_menu_guide_03_07.html'},
]
report['original_input_sha256_after_analysis']=hashlib.sha256(Path(report['source']).read_bytes()).hexdigest()
assert report['original_input_sha256_after_analysis']==report['sha256']
output=root/args.output
output.parent.mkdir(parents=True,exist_ok=True)
with output.open('x',encoding='utf-8') as fp:
 json.dump(report,fp,ensure_ascii=False,indent=2)
assert json.loads(output.read_text(encoding='utf-8'))['wonder_lantern_comparison']['different_byte_count']==5020
print(str(output))
print('Evidence JSON validated. Original input unchanged. No flashable deliverable generated.')
