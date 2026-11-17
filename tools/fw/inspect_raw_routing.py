"""Mine existing native first-hit captures; do not start another emulation."""
from pathlib import Path
import argparse
import hashlib
import json
import struct

ROOT=Path(__file__).resolve().parents[2]
BASE=0x10020000
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args()
assert not a.output.exists()
source=ROOT/'analysis/raw-nef-influence-2026-11-03/native-front-register/events.json'
events=json.loads(source.read_text(encoding='utf-8'))
blob=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
digest=hashlib.sha256(blob).hexdigest()
assert digest=='1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'

def area(record,name):
    item=record['memory'][name]
    if 'bytes' not in item:
        return None
    value=bytes.fromhex(item['bytes'])
    assert len(value)==item['size']
    assert hashlib.sha256(value).hexdigest()==item['sha256']
    return value

def half(data,offset):
    return struct.unpack_from('<H',data,offset)[0]

def word(data,offset):
    return struct.unpack_from('<I',data,offset)[0]

rows=[]
for index,event in enumerate(events):
    if event['event'] not in ('four_slot_parameter_generator','processing_driver','parameter_pointer_builder'):
        continue
    row=dict(source_index=index,event=event['event'],phase=event['phase'],outer_call=event['outer_call'],
             caller=event['registers']['r14'])
    if event['event']=='processing_driver':
        block=area(event,'packet_block_34')
        packet=area(event,'processing_packet')
        driver=area(event,'driver')
        assert block is not None
        core=area(event,'packet_block_0')
        row.update(bank=driver[4],packet_mode=word(packet,0xcc),raw_output_pointer=hex(word(packet,0x20)),
                   control_bytes=list(block[:5]),gains=[half(block,6+6*i) for i in range(4)],
                   negative_halfwords=[half(block,8+6*i) for i in range(4)],
                   third_halfwords=[half(block,10+6*i) for i in range(4)],
                   capped_parameter=half(block,0x1e),adjacent_pair=[half(block,0x20),half(block,0x22)],
                   core_mask=None if core is None else core[0x3e])
    elif event['event']=='four_slot_parameter_generator':
        context=area(event,'parameter_context')
        props=area(event,'generator_input')
        row.update(scope='Function entry; output capture is BEFORE this generator.',
                   scalar=half(props,0x86),gain=half(context,0x26),
                   third_halfwords=[half(context,0x4e+2*i) for i in range(4)],
                   capped_parameter=half(context,0x56),spatial_flags=list(context[0x74:0x76]),
                   spatial_coefficients=list(struct.unpack_from('<6i',context,0x5c)),
                   spatial_table_1=list(struct.unpack_from('<17h',context,0x7e)),
                   spatial_table_2=list(struct.unpack_from('<17h',context,0xa0)),
                   cached_parameter_selector=props[0x7e],cached_source_selector=props[0x96])
    else:
        request=area(event,'processing_request')
        row.update(raw_replacement_handle=hex(word(request,0x1a8)),mode=word(request,0x374))
    rows.append(row)

report=dict(scope=__doc__,source=str(source.relative_to(ROOT)),source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
            firmware_sha256=digest,events_total=len(events),rows=rows,
            excluded_mode_table=dict(address='0x115cd67d',values=list(blob[0x115cd67d-BASE:0x115cd67d-BASE+19])),
            limitations=['Existing observations capture only first hit per call_fixture window.',
                         'No new QEMU execution or complete still capture.',
                         'Null replacement pointers do not prove that the unit cannot affect a different output.',
                         'Previously missed still processing/encoding/package entries remain unobserved.'])
a.output.write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps(dict(source_event_count=len(events),selected=len(rows),output=str(a.output))))
