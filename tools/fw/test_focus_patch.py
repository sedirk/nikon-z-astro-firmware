import json
from pathlib import Path
import binascii
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import *
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = 0x10020000
stock_path = Path("Z6_firmware/firmware/decoded/eg1620_038000.bi")
patch_path = Path("Z6_firmware/patches/z6-c380-modified17-focus-astro-600s.json")

patch_data = json.load(open(patch_path, encoding="utf-8"))

# Replace the focus edits in patch_data
new_edits = []
for e in patch_data["edits"]:
    # Skip old focus edits
    if e["group"] in ["focus_standby_restore_cave", "focus_standby_restore_hook", "focus_save_position_default_on"]:
        continue
    new_edits.append(e)

# 1. Cave at 0x1002df00
cave_after = "2de97f4041f6a230dbf394f9012819d141f23310dbf38ef9421c86b0684644f60071c1f24c0142f195ff00208df80600142209216846d0f36bfc09210020d0f35bf806b0bde87f402046bde8f880"
cave_len = len(cave_after) // 2
cave_before = "00" * cave_len

new_edits.append({
    "group": "focus_standby_restore_cave",
    "address": "0x1002df00",
    "before": cave_before,
    "after": cave_after,
    "description": "Modified17: Standby wakeup focus restoration trampoline in ROM cave"
})

# 2. Hook at 0x1025e8c2
new_edits.append({
    "group": "focus_standby_restore_hook",
    "address": "0x1025e8c2",
    "before": "2046f8bd",
    "after": "cff51dbb",
    "description": "Modified17: Power management Resume dispatcher exit hook branching to focus restoration"
})

# 3. Default ON at 0x113a63a0
new_edits.append({
    "group": "focus_save_position_default_on",
    "address": "0x113a63a0",
    "before": "00000000",
    "after": "01000000",
    "description": "Modified17: Save focus position (0x1ba2) menu default value set to 1 (ON)"
})

patch_data["edits"] = new_edits

# Validate application on stock ROM
stock_bytes = bytearray(stock_path.read_bytes())
for e in patch_data["edits"]:
    addr = int(e["address"], 16)
    off = addr - BASE
    before = binascii.unhexlify(e["before"])
    after = binascii.unhexlify(e["after"])
    actual = stock_bytes[off : off + len(before)]
    if actual != before:
        raise ValueError(f"Mismatch at {e['address']} ({e['group']}): expected {e['before'][:16]}..., got {actual[:8].hex()}...")
    stock_bytes[off : off + len(after)] = after

print(f"All {len(patch_data['edits'])} edits applied successfully to stock ROM in memory!")

# Save updated patch json
with open(patch_path, "w", encoding="utf-8") as f:
    json.dump(patch_data, f, indent=2, ensure_ascii=False)
print("Updated patch JSON saved!")

# Now test with Unicorn Emulator
print("\n--- Unicorn Emulation Test ---")
STACK_ADDR = 0x20000000
STACK_SIZE = 0x10000

# Test Case 1: 0x1ba2 == 0 (Disabled)
print("\nTesting Case 1: Save focus position DISABLED (0x1ba2 returns 0)...")
uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
# Map single continuous region 0x10000000..0x10600000
uc.mem_map(0x10000000, 0x600000)
uc.mem_map(STACK_ADDR, STACK_SIZE)


# Write code into emulator
uc.mem_write(0x1002df00, binascii.unhexlify(cave_after))
uc.mem_write(0x1025e8c2, binascii.unhexlify("cff51dbb")) # hook
# "No.%d" string at 0x104c4f00
uc.mem_write(0x104c4f00, b"No.%d\x00")

# Mock functions:
# 1. 0x10409234 (GetProperty): returns r0 = mock_prop_val
# 2. 0x10170e54 (sprintf): mock sprintf
# 3. 0x103fe810 (SendRPC): mock record call
# 4. 0x103fdff8: mock return

# Helper hook for mocks
mock_state = {
    "prop_1ba2": 0,
    "prop_1133": 0,
    "rpc_called": False,
    "rpc_opcode": None,
    "rpc_data": None
}

def hook_code_cb(uc, address, size, user_data):
    if address == 0x10409234: # GetProperty
        prop = uc.reg_read(UC_ARM_REG_R0)
        if prop == 0x1ba2:
            uc.reg_write(UC_ARM_REG_R0, mock_state["prop_1ba2"])
        elif prop == 0x1133:
            uc.reg_write(UC_ARM_REG_R0, mock_state["prop_1133"])
        else:
            uc.reg_write(UC_ARM_REG_R0, 0)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR) | 1)
    elif address == 0x10170e54: # snprintf(sp, "No.%d", group)
        buf_ptr = uc.reg_read(UC_ARM_REG_R0)
        group = uc.reg_read(UC_ARM_REG_R2)
        s = f"No.{group}\x00".encode()
        uc.mem_write(buf_ptr, s)
        uc.reg_write(UC_ARM_REG_R0, len(s))
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR) | 1)
    elif address == 0x103fe810: # SendRPC
        mock_state["rpc_called"] = True
        mock_state["rpc_opcode"] = uc.reg_read(UC_ARM_REG_R1)
        len_arg = uc.reg_read(UC_ARM_REG_R2)
        buf_ptr = uc.reg_read(UC_ARM_REG_R0)
        mock_state["rpc_data"] = bytes(uc.mem_read(buf_ptr, len_arg))
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR) | 1)
    elif address == 0x103fdff8:
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR) | 1)

uc.hook_add(UC_HOOK_CODE, hook_code_cb)

# Set initial registers at 0x1025e8c2
# sp has {r3, r4, r5, r6, r7, pc} saved on stack
stack_top = STACK_ADDR + 0x8000
RETURN_PC = 0x1024bc4e # caller of Resume
uc.reg_write(UC_ARM_REG_SP, stack_top)
# push {r3=0x33, r4=0x44, r5=0x55, r6=0x66, r7=0x77, pc=RETURN_PC}
import struct
saved_regs = struct.pack("<6I", 0x33, 0x44, 0x55, 0x66, 0x77, RETURN_PC)
uc.mem_write(stack_top, saved_regs)

# r4 = return value 0x1234
uc.reg_write(UC_ARM_REG_R4, 0x1234)

# Run from hook at 0x1025e8c2 until RETURN_PC
uc.emu_start(0x1025e8c2 | 1, RETURN_PC, timeout=1000000)

print(f"Emulation finished!")
print(f"Final PC: 0x{uc.reg_read(UC_ARM_REG_PC):08x} (expected 0x{RETURN_PC:08x})")
print(f"Final R0: 0x{uc.reg_read(UC_ARM_REG_R0):08x} (expected 0x00001234)")
print(f"RPC called: {mock_state['rpc_called']} (expected False)")
assert uc.reg_read(UC_ARM_REG_PC) == RETURN_PC
assert uc.reg_read(UC_ARM_REG_R0) == 0x1234
assert mock_state["rpc_called"] == False

# Test Case 2: 0x1ba2 == 1 (Enabled)
print("\nTesting Case 2: Save focus position ENABLED (0x1ba2 returns 1)...")
mock_state["prop_1ba2"] = 1
mock_state["prop_1133"] = 0
mock_state["rpc_called"] = False
mock_state["rpc_opcode"] = None
mock_state["rpc_data"] = None

uc.reg_write(UC_ARM_REG_SP, stack_top)
uc.mem_write(stack_top, saved_regs)
uc.reg_write(UC_ARM_REG_R4, 0x5678)

uc.emu_start(0x1025e8c2 | 1, RETURN_PC, timeout=1000000)

print(f"Emulation finished!")
print(f"Final PC: 0x{uc.reg_read(UC_ARM_REG_PC):08x} (expected 0x{RETURN_PC:08x})")
print(f"Final R0: 0x{uc.reg_read(UC_ARM_REG_R0):08x} (expected 0x00005678)")
print(f"RPC called: {mock_state['rpc_called']} (expected True)")
print(f"RPC opcode: {mock_state['rpc_opcode']} (expected 9)")
print(f"RPC data: {mock_state['rpc_data'][:10]} (expected b'No.1\\x00...')")

assert uc.reg_read(UC_ARM_REG_PC) == RETURN_PC
assert uc.reg_read(UC_ARM_REG_R0) == 0x5678
assert mock_state["rpc_called"] == True
assert mock_state["rpc_opcode"] == 9
assert mock_state["rpc_data"].startswith(b"No.1\x00")

print("\nALL UNICORN EMULATION TESTS PASSED PERFECTLY!")
