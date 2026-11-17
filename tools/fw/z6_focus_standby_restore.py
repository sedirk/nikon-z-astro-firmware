"""Z6 C3.80 Modified17: Standby Focus Position Restoration & Default-ON Toggle.

Addresses the Viltrox (e.g. AF 16mm F1.8 Z) and other wire-by-wire lenses
standby sleep focus loss / reset-to-infinity bug.
"""
from __future__ import annotations
import struct
from keystone import Ks, KS_ARCH_ARM, KS_MODE_THUMB

BASE = 0x10020000

ADDR_M17_MENU_DEF = 0x113A63A0
ADDR_M17_FOCUS_CAVE_T1 = 0x1002DF00
ADDR_M17_CONNECT_HOOK = 0x1029A930
ADDR_M17_FOCUS_CAVE_T2 = 0x1002DF30
ADDR_M17_RESUME_HOOK = 0x1025E8C2

# Backward-compatibility alias
ADDR_M17_FOCUS_CAVE = ADDR_M17_FOCUS_CAVE_T1

ADDR_GET_PROPERTY = 0x10409234
ADDR_LENS_RESTORE = 0x104ABC4E

ASM_CAVE_T1 = f"""
.thumb
.syntax unified
    str.w   r3, [sl, #0x58]
    push.w  {{r0, r1, r2, r3, r4, r5, r6, lr}}
    movw    r0, #0x1ba2
    bl      #0x{ADDR_GET_PROPERTY:08x}
    cmp     r0, #1
    bne     .Lskip_t1
    movw    r1, #0xb0f4
    movt    r1, #0xc18f
    ldr     r0, [r1]
    cbz     r0, .Lskip_t1
    bl      #0x{ADDR_LENS_RESTORE:08x}
.Lskip_t1:
    pop.w   {{r0, r1, r2, r3, r4, r5, r6, lr}}
    b.w     #0x1029ad14
"""

ASM_CONNECT_HOOK = f"""
.thumb
.syntax unified
    b.w  #0x{ADDR_M17_FOCUS_CAVE_T1:08x}
"""

ASM_CAVE_T2 = f"""
.thumb
.syntax unified
    push    {{r0, r1}}
    movw    r0, #0x0ab8
    movt    r0, #0xc18d
    movs    r1, #1
    str     r1, [r0]
    pop     {{r0, r1}}
    mov     r0, r4
    pop     {{r3, r4, r5, r6, r7, pc}}
"""

ASM_RESUME_HOOK = f"""
.thumb
.syntax unified
    b.w  #0x{ADDR_M17_FOCUS_CAVE_T2:08x}
"""


def build_focus_standby_restore_spans(stock: bytes) -> list[tuple[int, str, bytes, str]]:
    """Return all spans for Modified17 focus restoration and default-ON toggle."""
    ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
    t1_bytes = bytes(ks.asm(ASM_CAVE_T1, ADDR_M17_FOCUS_CAVE_T1)[0])
    hook_connect_bytes = bytes(ks.asm(ASM_CONNECT_HOOK, ADDR_M17_CONNECT_HOOK)[0])
    t2_bytes = bytes(ks.asm(ASM_CAVE_T2, ADDR_M17_FOCUS_CAVE_T2)[0])
    hook_resume_bytes = bytes(ks.asm(ASM_RESUME_HOOK, ADDR_M17_RESUME_HOOK)[0])

    assert len(t1_bytes) == 44, f"Unexpected T1 size: {len(t1_bytes)}"
    assert len(hook_connect_bytes) == 4, f"Unexpected hook_connect size: {len(hook_connect_bytes)}"
    assert len(t2_bytes) == 20, f"Unexpected T2 size: {len(t2_bytes)}"
    assert len(hook_resume_bytes) == 4, f"Unexpected hook_resume size: {len(hook_resume_bytes)}"

    # Menu default value: 0x00000000 -> 0x00000001
    menu_def_bytes = struct.pack("<I", 1)

    spans = [
        (
            ADDR_M17_FOCUS_CAVE_T1,
            "focus_standby_restore_t1",
            t1_bytes,
            "Modified17: Standby wakeup focus restoration trampoline 1 (MlLensConnectComplete)",
        ),
        (
            ADDR_M17_CONNECT_HOOK,
            "focus_standby_connect_hook",
            hook_connect_bytes,
            "Modified17: eSyscCommandId_MlLensConnectComplete hook branching to T1",
        ),
        (
            ADDR_M17_FOCUS_CAVE_T2,
            "focus_standby_restore_t2",
            t2_bytes,
            "Modified17: Standby wakeup focus restoration trampoline 2 (Resume Flag)",
        ),
        (
            ADDR_M17_RESUME_HOOK,
            "focus_standby_resume_hook",
            hook_resume_bytes,
            "Modified17: Power management Resume exit hook branching to T2",
        ),
        (
            ADDR_M17_MENU_DEF,
            "focus_save_position_default_on",
            menu_def_bytes,
            "Modified17: Save focus position (0x1ba2) menu default value set to 1 (ON)",
        ),
    ]
    return spans


if __name__ == "__main__":
    spans = build_focus_standby_restore_spans(b"")
    print(f"Generated {len(spans)} spans for Modified17 focus fix.")
    for addr, grp, b, desc in spans:
        print(f"  0x{addr:08x} [{grp}] ({len(b)} bytes): {desc}")