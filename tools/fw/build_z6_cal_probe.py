"""Build the fixed CAL38 read-only probe; never runs the resulting executable."""
from pathlib import Path
import argparse,hashlib,json,os,subprocess
ROOT=Path(__file__).resolve().parents[2]
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--session',action='store_true');a=p.parse_args()
    out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    msvc_env=os.environ.get('MSVC_TOOLS_DIR')
    base=Path(msvc_env) if msvc_env else next((Path(pf)/'Microsoft Visual Studio/2022/Community/VC/Tools/MSVC' for pf in (os.environ.get('ProgramFiles',r'C:\Program Files'),) if (Path(pf)/'Microsoft Visual Studio/2022/Community/VC/Tools/MSVC').exists()),Path(os.environ.get('ProgramFiles',r'C:\Program Files'))/'Microsoft Visual Studio/18/Community/VC/Tools/MSVC')
    tool=sorted(base.iterdir(),key=lambda p:tuple(map(int,p.name.split('.'))))[-1]
    sdk=Path(os.environ.get('ProgramFiles(x86)',r'C:\Program Files (x86)'))/'Windows Kits/10';version=os.environ.get('WINDOWS_SDK_VERSION','10.0.26100.0')
    compiler=tool/'bin/Hostx64/x64/cl.exe';assert compiler.is_file()
    env=dict(os.environ);env['PATH']=str(compiler.parent)+os.pathsep+env['PATH']
    env['INCLUDE']=';'.join(map(str,[tool/'include',*[sdk/'Include'/version/x for x in ('ucrt','shared','um','winrt')]]))
    env['LIB']=';'.join(map(str,[tool/'lib/x64',sdk/'Lib'/version/'ucrt/x64',sdk/'Lib'/version/'um/x64']))
    sources={}
    for name in ('z6_wpd_cal_probe.cpp','z6_wpd_inventory.cpp','z6_wpd_cal_session.cpp'):
        b=(ROOT/'tools/fw'/name).read_bytes();(out/name).write_bytes(b);sources[name]=hashlib.sha256(b).hexdigest()
    stem='z6_wpd_cal_session' if a.session else 'z6_wpd_cal_probe'
    argv=[str(compiler),'/nologo','/EHsc','/std:c++17','/W4','/MT','/O2','/utf-8',str(out/(stem+'.cpp')),'/Fo'+str(out/'probe.obj'),'/Fe'+str(out/(stem+'.exe')),'/link','ole32.lib','oleaut32.lib','propsys.lib','PortableDeviceGuids.lib']
    r=subprocess.run(argv,env=env,cwd=out,capture_output=True)
    (out/'build.stdout').write_bytes(r.stdout);(out/'build.stderr').write_bytes(r.stderr)
    report=dict(ok=r.returncode==0,argv=argv,exit_code=r.returncode,source_sha256=sources,compiler=str(compiler),sdk_version=version,camera_accessed=False)
    if r.returncode==0:report['exe_sha256']=hashlib.sha256((out/(stem+'.exe')).read_bytes()).hexdigest()
    (out/'build.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    print(r.stdout.decode('utf8','replace'));print(r.stderr.decode('utf8','replace'));print(json.dumps(report));return r.returncode
if __name__=='__main__':raise SystemExit(main())
