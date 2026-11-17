"""Exact modified3 native update/rollback checks with private-memory flash adapters."""
from pathlib import Path
import argparse,gc,json,shutil,traceback
import probe_eg_update_route as eg
from probe_preflash_review import AuditRig,schedule
from review_spatial_preflash import ROOT,SOURCES
from verify_spatial_preflash_kit import DIGESTS,need,read_module

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    a.output.mkdir(parents=True,exist_ok=False)
    blobs={k:read_module(p,k) for k,p in SOURCES.items()}
    report=dict(ok=False,scope=__doc__,file_checks=[],scheduler=[],physical_flash=False,
        adapters='Native discovery/CRC/descriptor/RAM scheduler, host OS/file adapters, erase/program in private memory.',
        limits='No physical flash timing, power loss, rescue or real camera boot is tested.')
    try:
        for rom,target in (('modified2','test'),('modified1','test'),('stock','test'),
                           ('test','modified2'),('test','modified1'),('test','stock')):
            rig=AuditRig(blobs[rom]);label=rom+'_accepts_'+target
            row=eg.run(rig,label,blobs[target])
            need(row['discovery_return']==row['integrity_return']==row['component_precheck_return']==0,label)
            need(row['file_kind']==2 and row['component']==3 and row['component_count']==1,'Wrong component')
            need(row['displayed_version']=='03.80','Wrong displayed version')
            need(row['loaded_buffer_sha256']==DIGESTS[target],'Loaded bytes differ')
            need(row['update_length']==len(blobs[target])-2,'Update extent')
            report['file_checks'].append(dict(running_rom=rom,target=target,**row))
            print(json.dumps(dict(stage='file',label=label,ok=True)),flush=True);del rig;gc.collect()
        broken=bytearray(blobs['test']);broken[0x177868]^=1
        for label,data,name,size in (('damaged_crc',bytes(broken),'EG162080.BIN',None),
            ('wrong_model_filename',blobs['test'],'EG172080.BIN',None),
            ('oversize_directory_entry',blobs['test'],'EG162080.BIN',0x2940001)):
            rig=AuditRig(blobs['modified2']);row=eg.run(rig,label,data,name,reported_size=size)
            if label=='damaged_crc':need(row['discovery_return']==0 and row['integrity_return']==3,'CRC failure accepted')
            else:need(row['discovery_return']!=0,'Wrong file accepted')
            report['file_checks'].append(dict(running_rom='modified2',expected_rejection=True,**row))
            print(json.dumps(dict(stage='negative',label=label,rejected=True)),flush=True);del rig;gc.collect()
        for rom,target,failure in (('modified2','test',None),('test','modified2',None),
            ('test','modified1',None),('test','stock',None),('modified2','test','erase'),('test','stock','readback')):
            rig=AuditRig(blobs[rom]);label=rom+'_to_'+target+('_'+failure if failure else '')
            row=schedule(rig,label,blobs[target],failure);report['scheduler'].append(row)
            print(json.dumps({k:v for k,v in row.items() if k not in ('events','calls')}),flush=True);del rig;gc.collect()
        report['ok']=True
    except Exception:
        report['error']=traceback.format_exc()
        if 'rig' in locals():report['failed_calls']=rig.calls;report['failed_events']=rig.flash_events
        raise
    finally:
        (a.output/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
        for name in (Path(__file__).name,'probe_eg_update_route.py','probe_preflash_review.py','review_spatial_preflash.py','verify_spatial_preflash_kit.py'):
            shutil.copyfile(ROOT/'tools/fw'/name,a.output/name)
        print(json.dumps(dict(ok=report['ok'],file_checks=len(report['file_checks']),scheduler=len(report['scheduler']))))
if __name__=='__main__':main()
