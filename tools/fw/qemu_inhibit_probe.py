"""Controlled AF-status/capture diagnostics in a disposable pinned QEMU guest.

Artificial status messages test control flow, not autofocus or exposure success.
No firmware code edits, service stubs, direct inhibit writes or physical camera.
"""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import struct
import sys
import time
import traceback

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--repo', type=Path, required=True)
p.add_argument('--firmware', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--mask-check', action='store_true', help='Read effective mask and native summary getters, without artificial AF messages')
p.add_argument('--initiate-capture', action='store_true', help='Call the native capture API with its statically recovered wrapper input, trace rejection/acceptance')
p.add_argument('--without-card', action='store_true', help='Use the original CaptureWithoutCard wrapper branch (requires --initiate-capture)')
p.add_argument('--state-trace', action='store_true', help='Observe native state transitions and release completion paths (requires --without-card)')
p.add_argument('--completion-trace', action='store_true', help='Observe image completion state and producer conditions (requires --state-trace)')
p.add_argument('--source-trace', action='store_true', help='Observe upstream work flags and finish producers (requires --completion-trace)')
p.add_argument('--process-trace', action='store_true', help='Observe queued-frame consumption and image processing completion (requires --source-trace)')
p.add_argument('--readout-trace', action='store_true', help='Observe source readout waits and low-level command submission (requires --process-trace)')
p.add_argument('--timer-trace', action='store_true', help='Observe the native sensor finish timer and completion callback (requires --readout-trace)')
p.add_argument('--settle-ticks', type=int, default=1000, help='Argument to the final native wait call; default 1000')
p.add_argument('--rsp-timeout', type=int, default=45, help='Host socket timeout during the final wait, in seconds (does not alter guest time)')
a = p.parse_args()
assert not (a.mask_check and a.initiate_capture)
assert not a.without_card or a.initiate_capture
assert not a.state_trace or a.without_card
assert not a.completion_trace or a.state_trace
assert not a.source_trace or a.completion_trace
assert not a.process_trace or a.source_trace
assert not a.readout_trace or a.process_trace
assert not a.timer_trace or a.readout_trace
assert 1 <= a.settle_ticks <= 30000
assert 5 <= a.rsp_timeout <= 300
a.output.mkdir(parents=True, exist_ok=False)
probe_source = Path(__file__).read_bytes()
(a.output / 'probe-source.py').write_bytes(probe_source)
sys.path.insert(0, str(a.repo / 'tools'))
import interactive as ui
import probe
from capture_diagnostics import capture_health

ui.FIRMWARE = a.firmware.resolve(strict=True)
ui.BUILD_MANIFEST = a.repo / '.local/build-manifest.json'
digest = ui.checked_firmware(ui.FIRMWARE)
camera = ui.Camera(8787, profile='shooting', capture_control_test=True,
                   raw_source=ui.active_manifest('native0'), exmcu_no_lens=True,
                   tg_periodic_test=True, tg_paired_test=True,
                   raw_ingress_test=ui.active_ingress(), isp_boundary_test=True,
                   orientation_fixture=0, keep_awake=True, photo_liveview=True,
                   firmware_sha256=digest)
camera.exposure_probe = True
camera.isp_disable_cache = False
camera.tg_period_ms = None
events = []
phase = 'boot'
points = {
    0x10061672: 'af_status_callback', 0x1006157e: 'queued_af_status',
    0x10060122: 'clear_inhibit', 0x1006017c: 'set_inhibit',
    0x100621c0: 'release_request', 0x10061810: 'release_request_mode',
    0x1016585e: 'release_related_call', 0x1005fc3e: 'set_bit_store',
    0x1005fc60: 'clear_bit_store', 0x100bc4a6: 'list_group_select',
    0x10326632: 'gui_request_return', 0x103fd45e: 'gui_request_callback',
    0x101eedb4: 'initiate_capture_entry', 0x101eedf8: 'initiate_capture_exit',
    0x101eee14: 'capture_busy_result', 0x101eee1c: 'release_state_result',
    0x101eee24: 'release_context_result', 0x101eee2a: 'release_stage_result',
    0x101eee30: 'capture_flag17_result', 0x101eeed2: 'capture_mask_result',
    0x101eefc4: 'destination_check_entry', 0x101eefca: 'destination_check_result',
    0x101ef04a: 'prepare_result', 0x101ef12e: 'capture_late_path',
    0x102050dc: 'release_enqueue', 0x10202c72: 'release_worker',
    0x101ede2e: 'destination_validator_entry', 0x101ede68: 'storage_query_result',
    0x101ede7e: 'storage_query_maps_error3', 0x101edefe: 'storage_flag_maps_error3',
    0x10254516: 'storage_record_initialized', 0x10254526: 'storage_record_type',
    0x10320ede: 'storage_object_query_result',
}
original_call = ui.call_fixture


def snapshot():
    remote = camera.remote
    state = capture_health(remote, camera.device_evidence or None)
    state['release_context'] = remote.memory(0xc2376e04, 0x48).hex()
    state['af_source_state'] = remote.memory(0xc1882d08, 0x60).hex()
    state['af_report'] = remote.memory(0xc2152268, 0xbc).hex()
    state['gui_state'] = remote.memory(0xc1820a6c, 8).hex()
    sets = []
    for address in (0xc18b8ac0, 0xc18b8ac8, 0xc18b8ad0):
        bits, pointer = struct.unpack('<2I', remote.memory(address, 8))
        assert bits == 97
        data = remote.memory(pointer, 16)
        sets.append(dict(descriptor=hex(address), bit_count=bits, pointer=hex(pointer),
                         bytes=data.hex(), value=int.from_bytes(data, 'little')))
    active, enabled, special = [s['value'] for s in sets]
    state['inhibit_bitsets'] = sets
    state['effective_inhibit_ids'] = [hex(i) for i in range(97) if active & enabled & (1 << i)]
    state['special_inhibit_ids'] = [hex(i) for i in range(97) if active & special & (1 << i)]
    state['inhibit_summary_words'] = list(struct.unpack('<5I', remote.memory(0xc18b8aac, 20)))
    state['capture_service_context'] = remote.memory(0xc18b84e0, 0xa0).hex()
    state['release_service_context'] = remote.memory(0xc2376dac, 0xa0).hex()
    if a.state_trace:
        state['capture_sequence_context'] = remote.memory(0xc2376050, 0x100).hex()
        state['capture_sequence_aux'] = remote.memory(0xc2376550, 0x100).hex()
        state['image_request_context'] = remote.memory(0xc236f5e0, 0x48).hex()
        state['image_service_context'] = remote.memory(0xc18b7dc0, 0x100).hex()
        state['image_start_sync_object'] = remote.memory(0xc236f084, 0x20).hex()
        state['image_callback_slot_d'] = remote.memory(0xc2375ba8, 4).hex()
    if a.completion_trace:
        state['image_control_context'] = remote.memory(0xc18b7cc0, 0x100).hex()
        state['lower_controller_context'] = remote.memory(0xc18d1d30, 0x300).hex()
        state['source_event_context'] = remote.memory(0xc18b7228, 0x80).hex()
        frame = int.from_bytes(remote.memory(0xc18b7de4, 4), 'little')
        state['active_frame_pointer'] = hex(frame)
        if frame:
            state['active_frame'] = remote.memory(frame, 0x400).hex()
            config = int.from_bytes(bytes.fromhex(state['active_frame'])[0x3a4:0x3a8], 'little')
            state['frame_config_pointer'] = hex(config)
            if config:
                state['frame_config_head'] = remote.memory(config, 0xb0).hex()
    if a.source_trace:
        state['source_control_context'] = remote.memory(0xc18b71a8, 0x180).hex()
        state['source_request_context'] = remote.memory(0xc236d378, 0x80).hex()
        state['source_work_object'] = remote.memory(0xc236d250, 0x50).hex()
        state['source_timing_request'] = remote.memory(0xc236db04, 0x20).hex()
        state['image_callback_slots'] = remote.memory(0xc2375b74, 0x90).hex()
    if a.process_trace:
        state['lower_frame_queue'] = remote.memory(0xc2528d30, 0x50).hex()
        state['lower_work_object'] = remote.memory(0xc25287a4, 0x40).hex()
        state['image_finish_context'] = remote.memory(0xc236fcf0, 0x1c8).hex()
        config = int(state.get('frame_config_pointer', '0'), 16)
        if config:
            state['frame_config_processing'] = remote.memory(config, 0x300).hex()
    if a.readout_trace:
        state['source_extended_request'] = remote.memory(0xc236d378, 0x300).hex()
        state['source_sync_objects'] = remote.memory(0xc236d284, 0x34).hex()
        state['sensor_control_context'] = remote.memory(0xc18b7750, 0x100).hex()
        state['sensor_work_object'] = remote.memory(0xc236db94, 0x40).hex()
    if a.timer_trace:
        state['sensor_timing_context'] = remote.memory(0xc18b7808, 0x300).hex()
    storage = int.from_bytes(remote.memory(0xc18e8ed8, 4), 'little')
    state['storage_object_pointer'] = hex(storage)
    if storage:
        state['storage_record'] = remote.memory(storage + 0x186a60, 0x60).hex()
    return state


def observed_call(*args, **kwargs):
    function = args[2]
    def observe(remote, regs):
        pc = int(regs['r15'], 16)
        # Skip unrelated bit-set operations to keep the evidence focused.
        if pc in (0x1005fc3e, 0x1005fc60) and int(regs['r1'], 16) != 0xc2376d64:
            return
        row = dict(phase=phase, event=points[pc], outer_function=hex(function), registers=regs)
        row['inhibit_bits'] = remote.memory(0xc2376d60, 16).hex()
        row['release_context'] = remote.memory(0xc2376e04, 0x24).hex()
        if a.state_trace:
            row['capture_service_context'] = remote.memory(0xc18b84e0, 0xa0).hex()
            row['capture_sequence_context'] = remote.memory(0xc2376050, 0x100).hex()
            row['image_start_sync_object'] = remote.memory(0xc236f084, 0x20).hex()
        if a.completion_trace:
            row['image_control_context'] = remote.memory(0xc18b7cc0, 0x100).hex()
            row['image_service_context'] = remote.memory(0xc18b7dc0, 0x100).hex()
            row['lower_controller_context'] = remote.memory(0xc18d1d30, 0x100).hex()
            if pc in (0x10072172, 0x10076d0c):
                address = int(regs['r0'], 16)
                if address:
                    row['frame_input'] = remote.memory(address, 0x140).hex()
        if a.source_trace:
            row['source_control_context'] = remote.memory(0xc18b71a8, 0x180).hex()
            row['source_request_context'] = remote.memory(0xc236d378, 0x80).hex()
            row['source_work_object'] = remote.memory(0xc236d250, 0x50).hex()
            if pc in (0x101484d0, 0x10144b42, 0x10076a08):
                row['next_payload'] = remote.memory(int(regs['r0'], 16),
                    {0x101484d0: 8, 0x10144b42: 16, 0x10076a08: 40}[pc]).hex()
            if pc == 0x101fdaca:
                row['next_completion_payload'] = remote.memory(int(regs['r0'], 16), 12).hex()
        if a.process_trace:
            row['lower_frame_queue'] = remote.memory(0xc2528d30, 0x50).hex()
            row['lower_work_object'] = remote.memory(0xc25287a4, 0x40).hex()
            if pc in (0x10146e60, 0x1014a566):
                row['process_payload'] = remote.memory(int(regs['r0'], 16),
                    48 if pc == 0x10146e60 else 16).hex()
        if a.readout_trace:
            row['source_sync_objects'] = remote.memory(0xc236d284, 0x34).hex()
            row['sensor_control_context'] = remote.memory(0xc18b7750, 0x100).hex()
            row['sensor_work_object'] = remote.memory(0xc236db94, 0x40).hex()
            if pc in (0x101e167a, 0x101e1884, 0x101e1590, 0x101e1990):
                row['source_extended_request'] = remote.memory(0xc236d378, 0x300).hex()
        if a.timer_trace:
            row['sensor_timing_context'] = remote.memory(0xc18b7808, 0x300).hex()
            if pc == 0x10190ebc:
                row['timer_object_pointer'] = regs['r0']
                row['timer_object'] = remote.memory(int(regs['r0'], 16), 0x50).hex()
        if pc in (0x10061672, 0x1006157e, 0x100621c0):
            address = int(regs['r1' if pc == 0x10061672 else 'r0'], 16)
            row['input'] = remote.memory(address, 0xbc if pc == 0x10061672 else 8).hex()
        if pc == 0x101ede2e:
            row['input'] = remote.memory(int(regs['r0'], 16), 20).hex()
        if pc == 0x10320ede:
            row['storage_record'] = remote.memory(int(regs['r5'], 16), 0x60).hex()
        if pc == 0x101ede68:
            row['storage_record'] = remote.memory(int(regs['r13'], 16), 0x60).hex()
        if pc == 0x100bc4a6:
            row['list_request'] = remote.memory(int(regs['r8'], 16), 48).hex()
        if pc in (0x101484ac, 0x10144b1e):
            row['sequence_payload'] = remote.memory(int(regs['r0'], 16), 72 if pc == 0x10144b1e else 64).hex()
        if pc == 0x101fdb1a:
            row['completion_payload'] = remote.memory(int(regs['r0'], 16), 1).hex()
        events.append(row)
    observers = dict(kwargs.get('observers') or {})
    observers.update({pc: observe for pc in points})
    kwargs['observers'] = observers
    return original_call(*args, **kwargs)


ui.call_fixture = observed_call
experiment = 'native-without-card' if a.without_card else 'native-capture-api' if a.initiate_capture else 'effective-mask' if a.mask_check else 'artificial-af-status'
scopes = {
    'native-without-card': 'Native capture API using the statically recovered CaptureWithoutCard parameters and preparation call.',
    'native-capture-api': 'Native capture API using the statically recovered default destination request.',
    'effective-mask': 'Read effective inhibit masks and native summary getters, then submit original physical-input diagnostics.',
    'artificial-af-status': 'Artificial AF-status delivery through the original callback, then physical-input diagnostics.',
}
report = dict(ok=False, firmware_sha256=digest,
              upstream_commit='419a1f2a91a1f2d3a0209027c29606475f7fe26f',
              scope=scopes[experiment] + ' Synthetic boot with upstream RAM/device fixtures; no real autofocus, exposure or RAW-quality validation.',
              phases=[], calls=[])
report['experiment'] = experiment
report['probe_sha256'] = hashlib.sha256(probe_source).hexdigest()
report['arguments'] = vars(a) | {'repo': str(a.repo), 'firmware': str(a.firmware), 'output': str(a.output)}


def invoke(function, payload, arguments):
    global packet
    result = ui.call_fixture(camera.remote, packet, function, payload, arguments)
    packet = 'T05thread:' + result['return_cpu'] + ';'
    report['calls'].append(dict(phase=phase, result=result))
    return result


try:
    print('BOOT', flush=True)
    camera.boot_shooting()
    camera.pause()
    packet = camera.run_to(0x100531bc)
    report['baseline'] = snapshot()
    report['baseline_af_report'] = report['baseline']['af_report']
    baseline = bytes.fromhex(report['baseline_af_report'])
    assert len(baseline) == 0xbc
    print('BASELINE', report['baseline']['active_inhibit_ids'], flush=True)
    phases = [('status-1', 1, False), ('status-2', 2, True), ('restore-status', baseline[0], False)]
    if a.initiate_capture:
        phase = 'native-capture-api'
        if a.state_trace:
            points.update({
                0x101efbf8: 'capture_state_set', 0x101efc04: 'capture_state_store',
                0x101edf7c: 'enter_state3', 0x101ee6c2: 'count_update',
                0x101ee7ec: 'completion_dispatch', 0x101efe92: 'state3_cleanup',
                0x101eff16: 'state3_cleanup_exit', 0x101ee1be: 'start_sequence',
                0x101ee2de: 'start_sequence_result', 0x101ee7f2: 'completion_current_state',
                0x101ee800: 'completion_mode_result', 0x102024b6: 'sequence_completion_call',
                0x10200cfa: 'sequence_begin', 0x101efc3e: 'capture_substate_set',
                0x101efc56: 'capture_substate_get',
                0x101484ac: 'frame_submit', 0x101484c8: 'frame_submit_result',
                0x10144b1e: 'frame_worker', 0x101fe4c0: 'frame_callback',
                0x101fdb1a: 'frame_completion_consumer',
                0x102009de: 'pending_stage_entry', 0x10200a18: 'pending_stage_mask_result',
                0x101fc2a2: 'sequence_resume', 0x101fc29a: 'sequence_pending_store',
                0x101413ee: 'image_start_gate', 0x10141406: 'image_start_gate_result',
                0x10141374: 'image_start', 0x1013f546: 'image_start_inner',
                0x101430d4: 'image_controller_callback', 0x1014318c: 'image_ready_40',
                0x1013fd52: 'image_notify_d_normal', 0x101433b8: 'image_notify_d_alternate',
            })
            probe.TRACE_REPEAT = set(probe.TRACE_REPEAT) | {0x101efbf8, 0x101efc04, 0x101edf7c, 0x101efc3e,
                0x101fc2a2, 0x101fc29a, 0x101fe4c0, 0x102009de, 0x10200a18,
                0x101413ee, 0x10141406, 0x101430d4}
            report['state_trace'] = True
        if a.completion_trace:
            points.update({
                0x1013e18a: 'image_state_event', 0x1013e1a6: 'image_state_store',
                0x1013fcb6: 'image_state_worker', 0x1013fd6c: 'image_state_work_branch',
                0x1013fd94: 'image_state_allocate', 0x1013fda4: 'image_frame_allocated',
                0x10143398: 'controller_notify_d_gate', 0x10143c12: 'image_state_worker_queue',
                0x100719fe: 'source_41f0004_received', 0x10071a10: 'lower_notify_d_primary',
                0x10072172: 'lower_frame_work', 0x100721ae: 'lower_frame_check_result',
                0x100721d8: 'lower_notify_d_secondary',
                0x101e2012: 'source_finish_entry', 0x101e20c8: 'source_41f0004_emit',
                0x10076d0c: 'frame_resource_init', 0x10076d14: 'frame_resource_init_result',
                0x100c0372: 'resource_first_result', 0x100c0416: 'frame_resource_ready',
            })
            probe.TRACE_REPEAT = set(probe.TRACE_REPEAT) | {0x1013e18a, 0x1013e1a6}
            # High-rate SMP callbacks can race the upstream single-step/rearm
            # mechanism. Observe one callback per call in this focused mode.
            probe.TRACE_REPEAT.discard(0x101430d4)
            report['completion_trace'] = True
        if a.source_trace:
            points.update({
                0x101e26f0: 'source_worker_flags', 0x101e279c: 'source_finish_selected',
                0x101e289c: 'source_phase_dispatch', 0x101e414c: 'source_phase0',
                0x101e40ca: 'source_phase1', 0x101e4074: 'source_phase2',
                0x101e40aa: 'source_phase2_signal', 0x101e4126: 'source_phase1_signal',
                0x101e4142: 'source_phase1_short_signal',
                0x101e212e: 'source_start_worker', 0x101e4378: 'source_start_alternate',
                0x101e2170: 'source_start_parameters_ready',
                0x101dfd06: 'source_device_request', 0x101dfd42: 'source_device_request_result',
                0x101dfd54: 'source_device_wait', 0x101dfd58: 'source_device_wait_result',
                0x101e2236: 'source_device_request_returned',
                0x101e226e: 'source_start_delay_wait', 0x101e2272: 'source_start_delay_returned',
                0x101e2226: 'source_start_schedule', 0x101e222a: 'source_start_return',
                0x101e0e92: 'source_phase_timer_callback',
                0x101484d0: 'next_frame_submit', 0x10200aee: 'next_frame_submit_result',
                0x10144b42: 'next_frame_worker', 0x10144c56: 'next_frame_ready_check',
                0x101424d2: 'next_frame_process', 0x10076a08: 'next_frame_lower_submit',
                0x101426de: 'next_frame_lower_return', 0x101fdaca: 'next_frame_completion_consumer',
                0x1020072e: 'next_pending_stage', 0x10200742: 'next_pending_mask_result',
                0x10141f78: 'next_notify_producer', 0x10141fa8: 'next_notify_wait',
                0x10141fac: 'next_notify_wait_result', 0x10141ffa: 'next_notify_emit',
            })
            probe.TRACE_REPEAT = set(probe.TRACE_REPEAT) | {0x101e26f0, 0x101e289c}
            report['source_trace'] = True
        if a.process_trace:
            points.update({
                0x10076cec: 'frame_queue_append', 0x10076cf0: 'frame_queue_appended',
                0x1007240a: 'frame_mode_query',
                0x100710ee: 'frame_dependency_clear', 0x1007110c: 'frame_queue_empty_result',
                0x1007110e: 'frame_dependency_remaining', 0x10071148: 'frame_dependency_return',
                0x1007410c: 'lower_worker_flags', 0x10072430: 'lower_source_callback',
                0x10072552: 'lower_source_frame_result', 0x10071a18: 'lower_process_result',
                0x10072c66: 'lower_process_stage', 0x10073ef0: 'lower_input_stage',
                0x101474ae: 'image_data_callback', 0x10146e60: 'image_finish_worker',
                0x1014a36a: 'image_finish_select', 0x1014a566: 'image_finish_policy',
                0x1014a39c: 'image_finish_policy_result',
            })
            probe.TRACE_REPEAT = set(probe.TRACE_REPEAT) | {0x100710ee, 0x1007110c,
                0x1007110e, 0x10071148, 0x10072430}
            report['process_trace'] = True
        if a.readout_trace:
            points.update({
                0x101e42d2: 'source_readout_schedule', 0x101e430e: 'source_sensor_stop_submit',
                0x100f6786: 'sensor_stop_queue', 0x1007299a: 'lower_cleanup_work',
                0x10072a3c: 'lower_cleanup_return',
                0x101e2834: 'source_readout_policy_result',
                0x101e167a: 'readout_normal_entry', 0x101e1590: 'readout_mode2_entry',
                0x101e1884: 'readout_special_entry', 0x101e1990: 'readout_command_entry',
                0x101e16b0: 'readout_timing_check',
                0x101e16c2: 'readout_wait8', 0x101e16c6: 'readout_wait8_return',
                0x101e16d0: 'readout_wait1', 0x101e16d4: 'readout_wait1_return',
                0x101e16de: 'readout_sync_wait1', 0x101e16e2: 'readout_sync_wait1_return',
                0x101e1776: 'readout_delay_compare', 0x101e184c: 'readout_timer_wait',
                0x101e1854: 'readout_timer_return', 0x101e185a: 'readout_result_branch',
                0x101e1874: 'readout_finish_submit', 0x101e1880: 'readout_normal_return',
                0x101e18aa: 'special_readout_wait', 0x101e18ae: 'special_readout_wait_return',
                0x101e194e: 'special_readout_finish_submit',
                0x101e19a4: 'readout_command_policy_result',
                0x104294ae: 'readout_command_submit', 0x104294dc: 'readout_command_short_submit',
                0x100f6804: 'sensor_finish_submit',
                0x100f4cc2: 'sensor_worker_flags', 0x100f4fbc: 'sensor_phase100_check',
                0x100f5078: 'sensor_phase200', 0x100f5080: 'sensor_phase200_return',
                0x100f508c: 'sensor_phase400',
                0x101e10a6: 'source_event2_producer', 0x101e0fbc: 'source_event5_producer',
                0x101e109c: 'source_event5_emit', 0x101e10e0: 'source_event2_emit',
                0x100f6850: 'sensor_finish_mode2_queue', 0x100f6854: 'sensor_finish_return',
                0x100f68d8: 'sensor_finish_device_call', 0x100f68dc: 'sensor_finish_device_return',
            })
            report['readout_trace'] = True
        if a.timer_trace:
            points.update({
                0x101931da: 'sensor_finish_op0_return', 0x101931e2: 'sensor_finish_op1_return',
                0x101931ea: 'sensor_finish_timer_gate', 0x101931fe: 'sensor_finish_timer_return',
                0x10190ebc: 'sensor_timer_submit', 0x10190f82: 'sensor_timer_configure',
                0x10190f86: 'sensor_timer_configured', 0x10190f98: 'sensor_timer_started',
                0x10193180: 'sensor_finish_timer_callback', 0x1019318a: 'sensor_finish_callback_mask',
                0x10110a9c: 'sensor_finish_hw_request',
            })
            probe.TRACE_REPEAT = set(probe.TRACE_REPEAT) | {0x10190ebc, 0x10190f82, 0x10190f86, 0x10190f98}
            report['timer_trace'] = True
        payload = bytearray(32)
        # 10524bc0 constructs bytes 0..3 and words +4,+8,+c as zero,
        # then passes a positive shot count at +0x10 to 101eedb4.
        struct.pack_into('<I', payload, 0x10, 1)
        report['api_input_basis'] = '10524bc0 wrapper: zero-valued type/mode/option fields, destination 0, one requested frame. Does not assert card availability.'
        if a.without_card:
            invoke(0x101efaa8, bytes(8), [1])
            payload[2] = 1
            report['api_input_basis'] = '10524bc0 input+8==1 branch: calls 101efaa8(1), sets native request byte+2=1; 10524ae0 labels this branch CaptureWithoutCard. No direct flag writes.'
        report['native_capture_api'] = invoke(0x101eedb4, payload, [('scratch', 0), 0x10524b7f])
        print('API_RETURN', report['native_capture_api']['return_r0'], flush=True)
        invoke(0x10170cca, bytes(8), [100])
        report['after_api'] = snapshot()
        if a.without_card and int(report['native_capture_api']['return_r0'], 16) == 0:
            # RSP's original 5-second socket timeout is shorter than some
            # intentionally longer observation windows, even with no guest fault.
            timeout = camera.remote.sock.gettimeout()
            try:
                camera.remote.sock.settimeout(a.rsp_timeout)
                invoke(0x10170cca, bytes(8), [a.settle_ticks])
            finally:
                camera.remote.sock.settimeout(timeout)
            report['after_settle'] = snapshot()
        phases = []
    elif a.mask_check:
        phase = 'mask-check'
        report['native_summary_getters'] = {}
        for name, function in [('overall', 0x100601d8), ('special', 0x100600bc)]:
            result = invoke(function, bytes(8), [])
            report['native_summary_getters'][name] = int(result['return_r0'], 16)
        print('EFFECTIVE', report['baseline']['effective_inhibit_ids'], report['native_summary_getters'], flush=True)
        phase = 'unmodified-status-capture'
        packet = camera.capture_probe(packet)
        report['unmodified_status_capture'] = camera.snapshot()['capture_probe']
        phases = []
    for label, status, capture in phases:
        phase = label
        before = snapshot()
        payload = bytearray(baseline)
        payload[0] = status
        # Deliver only the original registered callback's message. The producer
        # cache is intentionally not overwritten: this is a consumer experiment.
        invoke(0x10061672, payload, [0x04260011, ('scratch', 0)])
        invoke(0x10170cca, bytes(8), [100])
        after = snapshot()
        item = dict(phase=phase, synthetic_status=status, before=before, after=after)
        print('STATUS', status, after['active_inhibit_ids'], after['release_context'][:16], flush=True)
        if capture:
            phase = 'capture-after-status-2'
            packet = camera.capture_probe(packet)
            item['capture_probe'] = camera.snapshot()['capture_probe']
            item['after_capture'] = snapshot()
            print('CAPTURE', item['capture_probe']['exposure_completed'], item['after_capture']['application'], flush=True)
        report['phases'].append(item)
    report['final'] = snapshot()
    report['ok'] = True
except Exception as exc:
    report.update(error=str(exc), traceback=traceback.format_exc())
    print(report['traceback'], flush=True)
finally:
    camera.close_guest()
    report['firmware_unchanged'] = hashlib.sha256(ui.FIRMWARE.read_bytes()).hexdigest() == digest
    report['event_count'] = len(events)
    (a.output / 'events.json').write_text(json.dumps(events, indent=2), encoding='utf-8')
    (a.output / 'result.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    shutil.copytree(camera.directory, a.output / 'session')
sys.exit(0 if report['ok'] else 1)
