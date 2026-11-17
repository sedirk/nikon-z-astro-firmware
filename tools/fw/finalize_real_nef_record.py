"""Index this research round, preserve script versions, and check report links."""
from pathlib import Path
import ast,datetime,hashlib,json,re,subprocess,sys

ROOT=Path(__file__).resolve().parents[2];BASE=ROOT/'analysis/real-nef-2026-11-09'
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def load(p):return json.loads(Path(p).read_text(encoding='utf8'))

verification=load(BASE/'verification-final.json');assert verification['ok']
assert not (BASE/'record.json').exists()
snapshot=BASE/'script-snapshots';snapshot.mkdir(exist_ok=False)
scripts=['prepare_real_nef_tools.py','inventory_nas_nef.py','analyze_nas_nef.py','plot_real_nef.py',
    'bridge_real_nef_contract.py','extract_nefinfo_series.py','analyze_bias_dark.py',
    'probe_neighborhood_ceiling.py','verify_lossless14_samples.py','verify_real_nef_study.py',
    'finalize_real_nef_record.py','audit_nef.py','record_research_command.py',
    'probe_raw_candidates.py','probe_release_contract.py','nikon_lossless14_check.cpp']
script_rows=[]
for name in scripts:
    p=ROOT/'tools/fw'/name;data=p.read_bytes()
    if p.suffix=='.py':ast.parse(data.decode('utf8'),filename=name)
    (snapshot/name).write_bytes(data);script_rows.append(dict(source=str(p.relative_to(ROOT)),sha256=sha(p)))
# Recover the first plot source exactly from the saved second-version source;
# retain the first display and processing control rather than replacing it.
v1=(BASE/'flat-diagnostics-v2/plot-source.py').read_text(encoding='utf8')
v1=v1.replace("def robust_correlation(a,b):\n    aa=np.clip(a,*np.percentile(a,[.5,99.5]));bb=np.clip(b,*np.percentile(b,[.5,99.5]))\n    return correlation(aa,bb)\n",'')
v1=v1.replace("                alternating_half_winsorized_correlation=robust_correlation(aa[inner],bb[inner]),\n",'')
v1=v1.replace("                temporal_half_winsorized_correlation=robust_correlation(ee[inner],ll[inner]),\n",'')
v1=v1.replace("            lo,hi=np.percentile(v,[1,99])\n            kw=dict(vmin=lo,vmax=hi) if j==0 else dict(vmin=-lim,vmax=lim)",
              "            kw={} if j==0 else dict(vmin=-lim,vmax=lim)")
v1=v1.replace('直接图色标取 1–99 百分位；高通仅用于观察，不自动区分光学与机内处理',
              '高通仅用于观察；照明、光学、灰尘和机内处理共同包含在图中')
expected=load(BASE/'flat-diagnostics/result.json')['script_sha256']
recovered=hashlib.sha256(v1.encode('utf8')).hexdigest()==expected
if recovered:(BASE/'flat-diagnostics/plot-source-recovered.py').write_text(v1,encoding='utf8')

deps=subprocess.run([sys.executable,'-m','pip','freeze'],capture_output=True,check=True)
(BASE/'python-dependencies.txt').write_bytes(deps.stdout)
commands=[];pending=[]
for p in sorted((BASE/'commands').glob('*/command.json')):
    c=load(p);row=dict(path=str(p.relative_to(ROOT)),**c)
    if 'exit_code' in c:commands.append(row)
    else:pending.append(row)
failures=[c for c in commands if c['exit_code']]
assert len(failures)==1 and '09-native-sample-contract' in failures[0]['path']

doc=ROOT/'docs/REAL_NEF_BASELINE_2026-11-09.md';links=[]
for target in re.findall(r'!?\[[^\]]*\]\(([^)]+)\)',doc.read_text(encoding='utf8')):
    if '://' in target or target.startswith('#'):continue
    path=(doc.parent/target.split('#')[0]).resolve()
    assert path.exists() or path==BASE/'record.json',target
    links.append(str(path.relative_to(ROOT)))
docs=['README.md','docs/REAL_NEF_BASELINE_2026-11-09.md','docs/NEXT_STEPS.md',
      'docs/PROJECT_GOALS.md','docs/RAW_TARGET_MAP_2026-11-03.md','docs/Z6_SAMPLE_CAPTURE_2026-11-08.md','.gitignore']
inventory=[]
for p in sorted(BASE.rglob('*')):
    if not p.is_file() or p==BASE/'record.json':continue
    # The current recorder is still open; its final output is checked afterwards.
    if any(p.is_relative_to(ROOT/Path(c['path']).parent) for c in pending):continue
    inventory.append(dict(path=str(p.relative_to(ROOT)),bytes=p.stat().st_size,sha256=sha(p)))
record=dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),date_local='2026-11-09 Asia/Shanghai',
    scope='171 existing real NEFs; original baseline, decoder checks, native metadata and geometry; no camera firmware installation.',
    verification=verification,source_policy='NAS read-only. Six verified copies; five new local samples used in place.',
    user_confirmations=['Z61_4850 is a capped dark.','samples/11.9 contains newly captured bias/dark.'],
    scripts=script_rows,first_plot_source_exactly_recovered=recovered,
    documents=[dict(path=x,sha256=sha(ROOT/x)) for x in docs],checked_local_report_links=links,
    commands=commands,pending_recorders_at_index_time=pending,expected_failed_commands=failures,
    files=inventory,git_commit_created=False,
    setup_notes=['Initial NAS listing and tool discovery preceded the recorded scientific commands.',
        'An exploratory PowerShell one-line hex print hit a quoting SyntaxError; a here-string read succeeded.',
        'The first native metadata attempt required six copies while only five were present; rerun with the same script passed.',
        'Median-binned light maps retained as processing controls; final spatial interpretation uses float bins with mean and temporal-median controls.'])
(BASE/'record.json').write_text(json.dumps(record,indent=2,ensure_ascii=False),encoding='utf8')
print(json.dumps(dict(files=len(inventory),scripts=len(scripts),links=len(links),commands=len(commands),
    expected_failures=len(failures),first_plot_source_exactly_recovered=recovered,verification_ok=True),indent=2))
