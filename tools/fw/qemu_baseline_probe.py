"""Use the pinned upstream Python controller for a finite, audited QEMU run.

No HTTP server and no firmware code edits. The original controller's synthetic
startup calls/fixtures remain in use and are recorded, not physical evidence.
"""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import sys
import time
import traceback

p=argparse.ArgumentParser()
p.add_argument('--repo',type=Path,required=True)
p.add_argument('--firmware',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
p.add_argument('--profile',choices=['menu','shooting'],default='shooting')
p.add_argument('--trace-consumers',action='store_true',help='Observe selected native PCs during upstream diagnostic-call windows')
p.add_argument('--observe-list-path',action='store_true',help='Read-only resource, full-list and MMIO breakpoint observations')
p.add_argument('--capture-probe',action='store_true',help='Submit the upstream bounded half/full release input probe; does not assert a saved photograph')
a=p.parse_args()
repo=a.repo.resolve(); output=a.output.resolve()
output.mkdir(parents=True,exist_ok=False)
sys.path.insert(0,str(repo/'tools'))
import interactive as ui
import probe
table_observations=[]
if a.trace_consumers:
    probe.TRACE_CALL.extend([0x100bc150,0x100bc18e,0x100bc204,0x100bc5b0,0x100bc5d6])
    original_call=ui.call_fixture
    def observe_empty_table(remote,registers):
        address=int(registers['r6'],16)
        row={'pc':registers['r15'],'address':hex(address),'requested_bytes':0x39000}
        try:
            blob=remote.memory(address,0x39000)
            filename=f'table-{len(table_observations)}.bin'
            (output/filename).write_bytes(blob)
            row.update(file=filename,sha256=hashlib.sha256(blob).hexdigest(),
                       bytes_zero=blob.count(0),bytes_ff=blob.count(255),
                       first_32_bytes=blob[:32].hex(),
                       sentinel_count=sum(blob[i:i+4]==b'\xff'*4 for i in range(0,len(blob),0x200)))
        except Exception as exc:
            row['error']=str(exc)
        table_observations.append(row)
    def observed_call(*args,**kwargs):
        if args[2]==0x10525a70:
            observers=dict(kwargs.get('observers') or {})
            observers[0x100bc204]=observe_empty_table
            kwargs['observers']=observers
        return original_call(*args,**kwargs)
    ui.call_fixture=observed_call
path_observations=[]
if a.observe_list_path:
    from qemu_path_observer import install
    path_observations=install(ui,probe,output)
ui.FIRMWARE=a.firmware.resolve(strict=True)
ui.BUILD_MANIFEST=repo/'.local/build-manifest.json'
digest=ui.checked_firmware(ui.FIRMWARE)

class ObservedCamera(ui.Camera):
    def config_snapshot(self):
        areas={'config_29e':(0xc20aaa66,1), 'config_3dc_3dd':(0xc20aaba4,2),
               'state':(0xc18fa954,64), 'state_1c':(0xc18fa970,4),
               'notification_callbacks':(0xc2086b40,16)}
        result={}
        for label,(address,size) in areas.items():
            try:result[label]={'address':hex(address),'bytes':self.remote.memory(address,size).hex()}
            except Exception as exc:result[label]={'error':str(exc)}
        return result
    def call(self,packet,name,function,payload,arguments):
        selected=function in (0x101cb734,0x101cb766,0x10122852)
        before=self.config_snapshot() if selected else None
        returned=super().call(packet,name,function,payload,arguments)
        if selected:
            record={'kind':'local_config_observation','function':hex(function),'name':name,
                    'arguments':arguments,'before':before,'after':self.config_snapshot()}
            self.audit(record)
            observations.append(record)
        return returned

observations=[]
shooting=a.profile=='shooting'
camera=ObservedCamera(8787,profile=a.profile,capture_control_test=shooting,
                      raw_source=ui.active_manifest('native0') if shooting else None,
                      exmcu_no_lens=shooting,tg_periodic_test=shooting,tg_paired_test=shooting,
                      raw_ingress_test=ui.active_ingress() if shooting else None,
                      isp_boundary_test=shooting,orientation_fixture=0 if shooting else None,
                      keep_awake=shooting,photo_liveview=shooting,firmware_sha256=digest)
camera.exposure_probe=a.capture_probe
camera.isp_disable_cache=False
camera.tg_period_ms=None
report={'profile':a.profile,'firmware_sha256':digest,'upstream_commit':'419a1f2a91a1f2d3a0209027c29606475f7fe26f',
        'consumer_breakpoints':a.trace_consumers,'trace_scope':'only during upstream diagnostic call_fixture windows, not an exhaustive execution trace',
        'scope':'original controller synthetic boot, not real sensor or complete still-photo capture',
        'started_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'ok':False}
try:
    print('BOOT',a.profile,flush=True)
    if shooting:camera.boot_shooting()
    else:camera.boot()
    for _ in range(3):
        time.sleep(1)
        camera.refresh()
    (output/'baseline.png').write_bytes(camera.png)
    camera.pause()
    report['config_after_boot']=camera.config_snapshot()
    report['baseline_state']=camera.snapshot()
    packet=camera.run_to(0x100531bc)
    clear=probe.call_fixture(camera.remote,packet,0x10170f2c,b'Z'*80,[('scratch',0),64])
    report['native_clear_check']=clear
    if bytes.fromhex(clear['output'])!=bytes(64)+b'Z'*16:
        raise RuntimeError('QEMU native clear failed its 64-byte boundary check')
    packet='T05thread:'+clear['return_cpu']+';'
    if shooting:
        packet,before=camera.exposure_observation(packet)
        turns=[]
        for name in ['main_ccw','main_ccw','main_cw','main_cw']:
            packet=camera.dial_or_mode(packet,name)
            packet,state=camera.exposure_observation(packet)
            turns.append({'action':name,'exposure':state})
        report['exposure_before']=before
        report['dial_sequence']=turns
        if turns[-1]['exposure']['tv']!=before['tv']:
            raise RuntimeError('Main dial did not return to baseline')
        if a.capture_probe:
            report['capture_probe_path_event_start']=len(path_observations)
            packet=camera.capture_probe(packet)
            report['capture_probe']=camera.snapshot().get('capture_probe')
            report['capture_probe_path_event_end']=len(path_observations)
        camera.continue_guest()
        time.sleep(1);camera.refresh();camera.pause()
    else:
        camera.key(packet,'down')
        camera.continue_guest();time.sleep(1);camera.refresh();camera.pause()
    (output/'after_input.png').write_bytes(camera.png)
    report['final_state']=camera.snapshot()
    report['observations']=observations
    report['ok']=True
    print('BASELINE_OK',a.profile,flush=True)
except Exception as exc:
    report['error']=str(exc)
    report['traceback']=traceback.format_exc()
    print(report['traceback'],flush=True)
finally:
    report['upstream_session']=str(camera.directory)
    report['table_observations']=table_observations
    if a.observe_list_path:
        (output/'path-observations.json').write_text(json.dumps(path_observations,indent=2),encoding='utf-8')
        report['path_observation_count']=len(path_observations)
    camera.close_guest()
    report['firmware_unchanged']=hashlib.sha256(ui.FIRMWARE.read_bytes()).hexdigest()==digest
    (output/'result.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    shutil.copytree(camera.directory,output/'session')
sys.exit(0 if report['ok'] else 1)
