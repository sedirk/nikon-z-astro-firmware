"""Read-only breakpoint observers for list/resource/MMIO routing in pinned QEMU.

Only installed during upstream diagnostic call_fixture windows. These windows
include synthetic boot inputs; their observations do not describe a stock boot.
"""
import hashlib
import struct

POINTS = {
    0x10077164: 'resource_c_before_get', 0x10077168: 'resource_c_after_get',
    0x100771c6: 'resource_c_sync_after_get', 0x100bfafe: 'list_source_set',
    0x100bc118: 'list_builder_entry', 0x100bc14e: 'list_cpu_address',
    0x100bc204: 'list_builder_exit', 0x100bc4a6: 'list_group_select',
    0x100bc4b8: 'selected_list_bus_address',
    0x1010b9fe: 'list_mmio_write_before', 0x1010ba02: 'list_mmio_write_after',
    0x1011c2ce: 'resource_b_load', 0x1011c31c: 'resource_b_null_fallback',
    0x1011d562: 'resource_b_mode_load', 0x1011d57e: 'resource_b_mode_null_fallback',
    0x100cda36: 'resource_b_upload_pointer', 0x100cda3a: 'resource_b_upload_length',
    0x10250e28: 'list_generator_entry',
}

def install(ui, probe, output):
    events=[]
    original=ui.call_fixture
    def observed_call(*args, **kwargs):
        function=args[2]
        def observe(remote, regs):
            pc=int(regs['r15'],16)
            row={'event':POINTS[pc], 'outer_diagnostic_call':hex(function), 'registers':regs, 'memory':{}}
            def read(label, address, size, save=False):
                try:
                    blob=remote.memory(address,size)
                    info={'address':hex(address),'bytes':size,'sha256':hashlib.sha256(blob).hexdigest(),
                          'zero_bytes':blob.count(0),'ff_bytes':blob.count(255),'head':blob[:128].hex()}
                    if save:
                        name=f'{len(events):03d}-{label}.bin'
                        (output/name).write_bytes(blob); info['file']=name
                    row['memory'][label]=info
                    return blob
                except Exception as exc:
                    row['memory'][label]={'address':hex(address),'error':str(exc)}
            if pc in (0x100bfafe,0x100bc118):
                address=int(regs['r0'],16)
                read('source',address,0xdfff8)
                read('resource_b_c_directory',0xc1880dac,56)
            if pc==0x100bc204:
                blob=read('all_list_groups',int(regs['r6'],16),0x18f000,True)
                if blob is not None:
                    row['groups']=[{'index':i,'zero_bytes':blob[i*0x39000:(i+1)*0x39000].count(0),
                                    'sentinels_at_512':sum(blob[j:j+4]==b'\xff'*4 for j in range(i*0x39000,(i+1)*0x39000,512))}
                                   for i in range(7)]
            if pc==0x100bc4b8:
                read('selected_bus_head',int(regs['r5'],16),128)
                read('address_translation',0xc29a8e58,192)
            if pc==0x100bc4a6:
                read('capture_request',int(regs['r8'],16),48)
            if pc==0x1010b9fe:
                row['mmio_address']=hex(int(regs['r0'],16)+0x3e0)
                row['value_to_write']=regs['r2']
                read('programming_structure',int(regs['r1'],16),0x38)
            if pc in (0x1011c2ce,0x1011c31c,0x1011d562,0x1011d57e):
                read('resource_b_pointer',0xc18fa970,4)
            events.append(row)
        observers=dict(kwargs.get('observers') or {})
        for point in POINTS:
            previous=observers.get(point)
            if previous:
                def combined(remote, regs, previous=previous):
                    previous(remote,regs);observe(remote,regs)
                observers[point]=combined
            else:
                observers[point]=observe
        kwargs['observers']=observers
        return original(*args, **kwargs)
    ui.call_fixture=observed_call
    return events
