from keystone import Ks, KS_ARCH_ARM, KS_MODE_THUMB
import binascii

ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)

asm_code = """
    push.w  {r0, r1, r2, r3, r4, r5, r6, lr}
    movw    r0, #0x1ba2
    bl      #0x10409234
    cmp     r0, #1
    bne     .Lskip
    movw    r0, #0x1133
    bl      #0x10409234
    adds    r2, r0, #1
    sub     sp, sp, #0x18
    mov     r0, sp
    movw    r1, #0x4f00
    movt    r1, #0x104c
    bl      #0x10170e54
    movs    r0, #0
    strb    r0, [sp, #6]
    movs    r2, #0x14
    movs    r1, #9
    mov     r0, sp
    bl      #0x103fe810
    movs    r1, #9
    movs    r0, #0
    bl      #0x103fdff8
    add     sp, sp, #0x18
.Lskip:
    pop.w   {r0, r1, r2, r3, r4, r5, r6, lr}
    mov     r0, r4
    pop.w   {r3, r4, r5, r6, r7, pc}
"""

code, count = ks.asm(asm_code, 0x1002df00)
code_bytes = bytes(code)
print(f"Assembled {count} instructions ({len(code_bytes)} bytes):")
print(binascii.hexlify(code_bytes).decode("ascii"))

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
print("\nDisassembly of assembled bytes:")
for ins in md.disasm(code_bytes, 0x1002df00):
    print(f"  0x{ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}")

hook_code, _ = ks.asm("b.w #0x1002df00", 0x1025e8c2)
print("\nHook at 0x1025e8c2:", binascii.hexlify(bytes(hook_code)).decode("ascii"))

