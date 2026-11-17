"""Verify organized files, documentation links and baseline; write inventory."""
from pathlib import Path
import hashlib, json, re, subprocess
from datetime import datetime
from zoneinfo import ZoneInfo

root=Path(__file__).resolve().parents[1]
original=root/'firmware/original/Z_6_0380.bin'
assert hashlib.sha256(original.read_bytes()).hexdigest()=='ff978ffdf77c58c0b861a06e16d432d5886969f3cdd05d62f6c8e82e8a4cea54'
report=json.loads((root/'outputs/Z6_0380_static_analysis_current.json').read_text(encoding='utf-8'))
assert Path(report['source'])==original
assert report['unmodified_roundtrip_byte_identical']
assert report['wonder_lantern_comparison']['different_byte_count']==5020
for entry in report['modules']:
 assert hashlib.sha256((root/'firmware/decoded'/entry['name']).read_bytes()).hexdigest()==entry['sha256']
docs=[root/'README.md',*(root/'docs').glob('*.md'),root/'samples/README.md']
for doc in docs:
 text=doc.read_text(encoding='utf-8')
 assert '\ufffd' not in text,doc
 for target in re.findall(r'\]\(([^)]+)\)',text):
  if not target.startswith(('http:','https:','#')):
   assert (doc.parent/target.split('#')[0]).exists(),(doc,target)
migration=json.loads((root/'manifests/migration_files.json').read_text(encoding='utf-8-sig'))
assert all(not Path(row['original_path']).exists() for row in migration)
assert all(Path(row['destination_path']).exists() for row in migration)
repo_status={}
for name in ('nikon-firmware-tools','z30-firmware-extensions'):
 status=subprocess.check_output(['git','-C',str(root/'references'/name),'status','--porcelain'],text=True)
 assert not status.strip(),(name,status)
 repo_status[name]='clean'
records=[]
sources=json.loads((root/'references/sources.json').read_text(encoding='utf-8'))
for source in sources:
 if source['status']=='saved':
  data=(root/source['local_path']).read_bytes()
  assert len(data)==source['bytes'],source['local_path']
  assert hashlib.sha256(data).hexdigest()==source['sha256'],source['local_path']
for file in sorted(root.rglob('*')):
 if file.relative_to(root).parts[0]=='.git':
  continue
 if file.is_file() and file.name not in ('project_inventory.json','project_verification.json'):
  records.append(dict(path=file.relative_to(root).as_posix(),bytes=file.stat().st_size,sha256=hashlib.sha256(file.read_bytes()).hexdigest()))
(root/'manifests/project_inventory.json').write_text(json.dumps(records,ensure_ascii=False,indent=2),encoding='utf-8')
result=dict(date=datetime.now(ZoneInfo('Asia/Shanghai')).date().isoformat(),input_hash_valid=True,module_hashes_valid=True,documentation_local_links_valid=True,source_snapshot_hashes_valid=True,
 original_source_files_absent=True,all_migrated_files_present=True,repositories=repo_status,
 inventory_file_count=len(records),inventory_bytes=sum(r['bytes'] for r in records),
 snapshots_saved=sum(r['status']=='saved' for r in json.loads((root/'references/sources.json').read_text(encoding='utf-8'))))
(root/'manifests/project_verification.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
print(json.dumps(result,indent=2))
