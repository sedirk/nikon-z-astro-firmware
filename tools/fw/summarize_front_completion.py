"""Persist new facts and bounded next steps without altering firmware or prior evidence."""
from pathlib import Path
import hashlib,json,struct
ROOT=Path(__file__).resolve().parents[2];OUT=ROOT/'analysis/raw-front-completion-2026-11-10'
def sha(b):return hashlib.sha256(b).hexdigest()
def read(p):return json.loads(p.read_text(encoding='utf8'))
def write(p,obj):
    assert not p.exists(),p
    p.write_text(json.dumps(obj,ensure_ascii=False,indent=2),encoding='utf8')

def main():
    mapping=read(OUT/'usb-opcode-map.json');native=read(OUT/'native-irq-dispatch/result.json')
    assert native['ok'] and len(native['cases'])==36
    blob=(ROOT/'firmware/decoded/eg1620_038000.bi').read_bytes()
    assert sha(blob)=='1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'
    start=0x11f7a49c;table=list(struct.unpack_from('<65H',blob,start-0x10020000))
    observed=[int(x['opcode'],16) for x in mapping['opcodes']]
    assert table==sorted(observed) and len(set(table))==65
    write(OUT/'usb-rom-table-match.json',dict(ok=True,firmware_sha256=sha(blob),address=hex(start),
        byte_count=130,bytes=blob[start-0x10020000:start-0x10020000+130].hex(),
        opcodes=[hex(x) for x in table],matches_current_camera_set=True,observed_order_differs=True,
        table_end_exclusive=hex(start+130),following_halfword=hex(struct.unpack_from('<H',blob,start-0x10020000+130)[0]),
        classification='Exact data match, not proof of an executable dispatch table; direct literal references were not found.',
        calibration_data_read=False,body_firmware_hash_measured=False))
    qemu=OUT/'primary-sources/nikon-z6.c';lines=qemu.read_text(encoding='utf8').splitlines()
    uses=[dict(line=i,text=x) for i,x in enumerate(lines,1) if 'capture_sync[' in x]
    assert len(uses)==3
    excerpts=[]
    for lo,hi,label in ((1307,1317,'diagnostic completion pulse'),(1509,1558,'periodic completion and running condition'),
        (1560,1586,'status read and write-to-ack model'),(1622,1684,'SDES configuration storage')):
        excerpts.append(dict(first_line=lo,last_line=hi,label=label,text='\n'.join(lines[lo-1:hi])))
    write(OUT/'model-completion-audit.json',dict(ok=True,working_source_sha256=sha(qemu.read_bytes()),
        storage_uses=uses,excerpts=excerpts,
        finding='2006103c, 20061264 and 20061268 are stored as capture_sync fields. The model has no consumer that makes IRQ87 bit0x10 depend on those fields. Test pulses/periodic frame phases create that bit independently.',
        significance='An ID35-disable experiment can pass synthetic completion even if real hardware requires its transfer/configuration.',
        physical_failure_cause='Still a hypothesis; no internal status trace was captured on the failing body.',
        model_modified=False,firmware_modified=False))
    write(OUT/'candidate-status.json',dict(status='RESEARCH_CONTINUES_NO_NEW_FLASH_IMAGE',local_date='2026-11-10',
        target='Preserve dark current; disable static pre-NEF RAW corrections; eliminate rings.',
        recovery_user_confirmed=True,recalled_modified5_stays_recalled=True,
        current_recovery_baseline='modified4 expected from preceding recovery instructions; USB reports V3.80 and does not fingerprint the patch.',
        menu_change_record='user-settings-change.json',usb_identity_read=True,usb_advertised_vendor_count=65,
        usb_primary_source_mapped=51,usb_unknown_symbol_count=14,usb_calibration_dump_obtained=False,
        exact_rom_vendor_set_match='0x11f7a49c, 65 u16 entries',
        native_irq_dispatch_cases=36,native_variants=['stock','modified4','recalled_modified5'],
        completion_path=['0x10179024/0x1017902e -> 0x10110a1a -> 0x1010ce94 callback registration',
          '0x20060044 raw status -> 0x1010c850 IRQ87 -> callback at c1806d84+34',
          '0x10178de8 bit0x10 -> RTOS event bit8 -> 0x10179da4 wait',
          'Absent event8 -> local status0x20; prior round traced upper event041f0181 subtype8'],
        verified=['User reports camera recovered.',
          'Read-only WPD identity and public vendor command list succeeded.',
          'Native registration, ISR, callback and wait route execute identically in the 36 injected-status cases.',
          'Working QEMU SDES config storage does not enforce the proposed ID35-to-completion dependency.'],
        hypotheses=['The withdrawn ID35 gate/descriptor suppression may violate real frontend transfer dependencies.',
          'Other dispatcher/timing interactions among the four reverted ranges remain possible.',
          'Actual ID35 fixed data and CAL38 33x4 values may identify a safe correction control or neutral transform; units and pixel operation remain open.'],
        next_required=['Inspect real PTP dispatch using the camera-matched ROM command set; validate any calibration reader before device execution.',
          'Prioritize obtaining authentic CAL38/ID35 records or identifying their hardware consumers; preserve mandatory transfer/completion.',
          'Derive one still-only correction change with known zero/identity semantics; retain all dark-patch bytes and error handling.',
          'Before next firmware A/B, collect new recovered-modified4 samples with all three menus OFF and fixed geometry.'],
        last_physical_dark_regression='modified3; modified4 fresh 5-second dark still pending',
        new_nef=False,physical_ring_improvement_claimed=False,original_firmware_preserved=True,
        camera_settings_changed_by_assistant=False,usb_vendor_opcodes_executed=[],new_flash_candidate=False))
    print(json.dumps(dict(ok=True,rom_usb_set_matches=True,commands=65,native_cases=36,new_flash=False)))

if __name__=='__main__':main()
