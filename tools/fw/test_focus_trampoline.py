import sys
from pathlib import Path
from keystone import Ks, KS_ARCH_ARM, KS_MODE_THUMB
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

ADDR_CAVE = 0x1002DF00
ADDR_HOOK = 0x10525AD6

ASM_CAVE = f"""
.thumb
.syntax unified

    push {{r4, r5, r6, lr}}
    mov  r4, r5

    movw r0, #0x3e8
    bl   #0x10170cca

    movw r0, #0x1ba2
    bl   #0x10409234
    cmp  r0, #1
    bne  .Lskip

    bl   #0x10408e7c
    cbz  r0, .Lskip

    bl   #0x104c4ca8

.Lskip:
    mov  r5, r4
    pop  {{r4, r5, r6, lr}}
    mov  r0, r5
    pop  {{r3, r4, r5, r6, r7, pc}}
"""

ASM_HOOK = f"""
.thumb
.syntax unified
    bl   #0x{ADDR_CAVE:08x}
    nop
    nop
    nop
    nop
"""

def main():
    ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

    blob_cave, _ = ks.asm(ASM_CAVE, ADDR_CAVE)
    blob_hook, _ = ks.asm(ASM_HOOK, ADDR_HOOK)

    bytes_cave = bytes(blob_cave)
    bytes_hook = bytes(blob_hook)

    print(f"Cave blob: {len(bytes_cave)} bytes")
    for i in cs.disasm(bytes_cave, ADDR_CAVE):
        print(f"  0x{i.address:08x}: {i.mnemonic:8s} {i.op_str}")

    print(f"\nHook blob: {len(bytes_hook)} bytes (expected 12 bytes)")
    for i in cs.disasm(bytes_hook, ADDR_HOOK):
        print(f"  0x{i.address:08x}: {i.mnemonic:8s} {i.op_str}")

if __name__ == "__main__":
    main()
