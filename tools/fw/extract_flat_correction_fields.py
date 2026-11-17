"""Recover directly serialized fields from actual flat NEFs, without pixel claims."""
from pathlib import Path
import argparse,binascii,json,struct
from audit_nef import file_sha
from bridge_real_nef_contract import nefinfo

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--audit',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    report=dict(scope=__doc__,audit_sha256=file_sha(a.audit),script_sha256=file_sha(__file__),files=[])
    for row in json.loads(a.audit.read_text(encoding='utf8'))['files']:
        path=Path(row['path']);assert file_sha(path)==row['sha256']
        ni=nefinfo(path,row['tiff']);v=bytes.fromhex(ni['entries']['0x6']['bytes']);s=bytes.fromhex(ni['entries']['0x7']['bytes'])
        assert len(v)==116 and len(s)==104
        assert binascii.crc_hqx(v[:-2],0xffff)==struct.unpack_from('<H',v,114)[0]
        assert binascii.crc_hqx(s[:-2],0xffff)==struct.unpack_from('<H',s,102)[0]
        report['files'].append(dict(name=path.name,path=str(path),sha256=row['sha256'],nefinfo=ni,
            vignette=dict(coefficients=[struct.unpack_from('<i',v,k)[0] for k in [0x44,0x34,0x24,0x14]],
                strength_L=struct.unpack_from('<I',v,0x60)[0],status=v[4]),
            two_table_spatial=dict(coefficients=[struct.unpack_from('<i',s,k)[0] for k in [0x2c,0x1c,0x14,0x50,0x40,0x38]],
                flag_at_4=s[4],flag_at_5a=s[0x5a]),source_unchanged=file_sha(path)==row['sha256']))
    report['ok']=all(r['source_unchanged'] for r in report['files'])
    (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    (a.output/Path(__file__).name).write_bytes(Path(__file__).read_bytes())
    print(json.dumps([dict(name=r['name'],vignette=r['vignette'],two_table_spatial=r['two_table_spatial']) for r in report['files']],indent=2))
if __name__=='__main__':main()
