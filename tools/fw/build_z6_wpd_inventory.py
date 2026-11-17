"""Build only the source-reviewed WPD identity/opcode reader using installed MSVC."""
from pathlib import Path
import argparse,hashlib,json,os,subprocess

ROOT=Path(__file__).resolve().parents[2]

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    msvc_env=os.environ.get('MSVC_TOOLS_DIR')
    vs=Path(msvc_env) if msvc_env else next((Path(pf)/'Microsoft Visual Studio/2022/Community/VC/Tools/MSVC' for pf in (os.environ.get('ProgramFiles',r'C:\Program Files'),) if (Path(pf)/'Microsoft Visual Studio/2022/Community/VC/Tools/MSVC').exists()),Path(os.environ.get('ProgramFiles',r'C:\Program Files'))/'Microsoft Visual Studio/18/Community/VC/Tools/MSVC')
    tool=sorted(vs.iterdir(),key=lambda p:tuple(map(int,p.name.split('.'))))[-1]
    sdk=Path(os.environ.get('ProgramFiles(x86)',r'C:\Program Files (x86)'))/'Windows Kits/10';version=os.environ.get('WINDOWS_SDK_VERSION','10.0.26100.0')
    compiler=tool/'bin/Hostx64/x64/cl.exe';assert compiler.is_file()
    env=dict(os.environ);env['PATH']=str(compiler.parent)+os.pathsep+env['PATH']
    env['INCLUDE']=';'.join(map(str,[tool/'include',sdk/'Include'/version/'ucrt',sdk/'Include'/version/'shared',sdk/'Include'/version/'um',sdk/'Include'/version/'winrt']))
    env['LIB']=';'.join(map(str,[tool/'lib/x64',sdk/'Lib'/version/'ucrt/x64',sdk/'Lib'/version/'um/x64']))
    source=ROOT/'tools/fw/z6_wpd_inventory.cpp';(out/source.name).write_bytes(source.read_bytes())
    argv=[str(compiler),'/nologo','/EHsc','/std:c++17','/W4','/MT','/O2','/utf-8',str(source),'/Fo'+str(out/'inventory.obj'),'/Fe'+str(out/'z6_wpd_inventory.exe'),'/link','ole32.lib','oleaut32.lib','propsys.lib','PortableDeviceGuids.lib']
    p=subprocess.run(argv,env=env,cwd=out,capture_output=True)
    (out/'build.stdout').write_bytes(p.stdout);(out/'build.stderr').write_bytes(p.stderr)
    report=dict(ok=p.returncode==0,argv=argv,exit_code=p.returncode,source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),compiler=str(compiler),sdk_version=version,camera_accessed=False)
    if p.returncode==0:report['exe_sha256']=hashlib.sha256((out/'z6_wpd_inventory.exe').read_bytes()).hexdigest()
    (out/'build.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    print(p.stdout.decode('utf8','replace'));print(p.stderr.decode('utf8','replace'));print(json.dumps(report))
    raise SystemExit(p.returncode)

if __name__=='__main__':main()
