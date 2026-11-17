"""Data table builders and address layout for Nikon Z6 C3.80 30-600s exposure extension."""
from __future__ import annotations
import struct

BASE = 0x10020000
SIZE = 33502842

# 8 extended M-mode still shutter steps: (tv_s24, ui_id, seconds, label)
EXT_STEPS: tuple[tuple[int, int, int, str], ...] = (
    (-144, 67, 60, '60"'),
    (-156, 68, 90, '90"'),
    (-168, 69, 120, '120"'),
    (-180, 70, 180, '180"'),
    (-192, 71, 240, '240"'),
    (-200, 72, 300, '300"'),
    (-216, 73, 480, '480"'),
    (-224, 74, 600, '600"'),
)
EXT_SLOW_TO_FAST: tuple[tuple[int, int, int, str], ...] = tuple(reversed(EXT_STEPS))

N_EXT = len(EXT_STEPS)          # 8
STOCK_M_COUNT = 112             # 0x70
M_COUNT = STOCK_M_COUNT + N_EXT # 120 (0x78)
STOCK_TV_COUNT = 109            # 0x6D
TV_COUNT = STOCK_TV_COUNT + N_EXT  # 117 (0x75)
STOCK_UI_COUNT = 67             # 0x43
UI_COUNT = STOCK_UI_COUNT + N_EXT  # 75 (0x4B)
UI_FIRST = 67                   # 0x43
UI_LAST = 74                    # 0x4A

IDX_600S = 3
IDX_60S = 10   # 0x0A
IDX_30S = 11   # 0x0B

# Boot pool allocation layout
STOCK_POOL_REQ = 0x754E0
EXT_BLOCK_OFF = 0x75500
EXT_TOTAL_ALLOC = 0x75D80
POOL_START = 0xC9700000
POOL_MAX_BASE = 0xCC400000 - EXT_TOTAL_ALLOC  # 0xCC38A280
BLOCK_TAG = 0x5549584C

# Alignment hole 1 placements (0x1002EF14 .. 0x1002FFFC)
ADDR_PTP_HDR = 0x1002EF14
ADDR_PTP_TBL = 0x1002EF80
ADDR_PROP_DESC = 0x1002F5F4

ADDR_POOL_RESET = 0x1002F700
ADDR_DIAL_PREREF = 0x1002F760
ADDR_MTBL_REF = 0x1002F790
ADDR_ALLOWED_TV = 0x1002F7C0
ADDR_GET_MTBL = 0x1002F820
ADDR_GET_BLOCK = 0x1002F860
ADDR_ACTIVE_UI = 0x1002F900
ADDR_DIAL_STEP = 0x1002F970
ADDR_DIAL_BURST = 0x1002F9E0
ADDR_UI_R8 = 0x1002FA80
ADDR_UI_R7 = 0x1002FAD0
ADDR_UI_SP8 = 0x1002FB10
ADDR_UI_RAT = 0x1002FB50
ADDR_MIN_TV8 = 0x1002FBC0
ADDR_BOOT_ALLOC = 0x1002FC20
ADDR_RANGE_1 = 0x1002FD00
ADDR_RANGE_2 = 0x1002FD30
ADDR_RANGE_3 = 0x1002FD60
ADDR_RANGE_4 = 0x1002FD90

# Alignment hole 2 placements (0x10D30840 .. 0x10D32C00)
ADDR_ROM_MTBL = 0x10D30840
ADDR_TV_FLAG_TBL = 0x10D31000
ADDR_TV_FLAG_DESC = 0x10D313B8
ADDR_TV_UI_TBL = 0x10D31400
ADDR_STR_PTR_TBL = 0x10D31800
ADDR_UI_CLS_TBL1 = 0x10D31940
ADDR_UI_CLS_TBL2 = 0x10D31BC0
ADDR_EXT_STRS = 0x10D31E40
ADDR_EXT_LOOKUP = 0x10D31F00

ADDR_LOOKUP_TV = 0x10D32000
ADDR_LOOKUP_RAT = 0x10D32080
ADDR_US_TIMER = 0x10D32100
ADDR_NS_TIMER = 0x10D32180
ADDR_EXIF_RAT = 0x10D32200
ADDR_M_FALLBACK = 0x10D32280
ADDR_TOP_OLED = 0x10D32A00
ADDR_PTP_GATE = 0x10D32B00


def build_rom_tables(stock: bytes) -> list[tuple[int, str, bytes, str]]:
    """Construct all extended shutter ROM tables from verified Stock C3.80 tables."""
    out: list[tuple[int, str, bytes, str]] = []

    # 1. PTP 0x500D / 0xD100 16-byte prefix ({3, 2, 0x20D, 0x204}) + header (108 bytes) + 117-entry Tv table
    ptp_prefix_addr = ADDR_PTP_HDR - 0x10  # 0x1002EF04; [ADDR_PTP_HDR - 8] @ 0x1002EF0C holds {0x20D, 0x204}
    ptp_hdr = stock[0x115520DC - BASE : 0x11552158 - BASE]
    assert len(ptp_hdr) == 0x7C and ptp_prefix_addr + len(ptp_hdr) == ADDR_PTP_TBL
    assert struct.unpack_from("<4I", ptp_hdr, 0) == (3, 2, 0x20D, 0x204)
    out.append((ptp_prefix_addr, "m600_rom_tables", ptp_hdr, "PTP 0x500D/0xD100 property prefix {0x20D,0x204} + descriptor header"))

    ptp_tbl = bytearray(stock[0x11552158 - BASE : 0x11552158 - BASE + STOCK_TV_COUNT * 12])
    for tv, _, sec, _ in EXT_STEPS:
        ptp_tbl += struct.pack("<hhII", tv, 0, sec * 10000, (sec << 16) | 1)
    assert len(ptp_tbl) == TV_COUNT * 12
    out.append((ADDR_PTP_TBL, "m600_rom_tables", bytes(ptp_tbl), "117-entry PTP ExposureTime table (up to 600s)"))

    # 2. Property dependency list (46 -> 47 entries, inserting 0x204 at index 1)
    cnt46, ptr46 = struct.unpack_from("<II", stock, 0x114CBA14 - BASE)
    assert cnt46 == 46 and ptr46 == 0x114CB95C
    words46 = list(struct.unpack_from("<46I", stock, ptr46 - BASE))
    words47 = [words46[0], 0x204] + words46[1:]
    prop_desc = struct.pack("<II47I", 47, ADDR_PROP_DESC + 8, *words47)
    out.append((ADDR_PROP_DESC, "m600_rom_tables", prop_desc, "47-entry property refresh descriptor including 0x204"))

    # 3. 120-entry M-mode step table template in ROM
    rom_mtbl_off = 0x11E94DD4 + 0x16920 - BASE  # 0x11EAB6F4
    first4 = [struct.unpack_from("<4i", stock, rom_mtbl_off + k * 16) for k in range(4)]
    assert first4[0][0] == 3 and first4[1][0] == 2 and first4[2][0] == 1 and first4[3][:2] == (0, -120)
    mtbl = bytearray(stock[rom_mtbl_off : rom_mtbl_off + 3 * 16])
    for tv, _, _, _ in EXT_SLOW_TO_FAST:
        mtbl += struct.pack("<4i", 0, tv, 0x7FFFFFFF, 0)
    mtbl += stock[rom_mtbl_off + 3 * 16 : rom_mtbl_off + STOCK_M_COUNT * 16]
    assert len(mtbl) == M_COUNT * 16
    out.append((ADDR_ROM_MTBL, "m600_rom_tables", bytes(mtbl), "120-entry M-mode step table ROM template (600s..1/8000s)"))

    # 4. 117-entry (tv, step_flag) table + descriptor
    cnt109, ptr109 = struct.unpack_from("<II", stock, 0x114CF290 - BASE)
    assert cnt109 == STOCK_TV_COUNT and ptr109 == 0x114CEF28
    tv_flag = bytearray()
    for tv, _, _, _ in EXT_SLOW_TO_FAST:
        tv_flag += struct.pack("<ii", tv, 2)
    tv_flag += stock[ptr109 - BASE : ptr109 - BASE + STOCK_TV_COUNT * 8]
    assert len(tv_flag) == TV_COUNT * 8
    out.append((ADDR_TV_FLAG_TBL, "m600_rom_tables", bytes(tv_flag), "117-entry Tv step-grid table"))
    out.append((ADDR_TV_FLAG_DESC, "m600_rom_tables", struct.pack("<II", TV_COUNT, ADDR_TV_FLAG_TBL), "117-entry Tv step-grid descriptor"))

    # 5. 117-entry (tv, ui_id) mapping table
    tv_ui = bytearray(stock[0x11471A0C - BASE : 0x11471A0C - BASE + STOCK_TV_COUNT * 8])
    for tv, ui_id, _, _ in EXT_STEPS:
        tv_ui += struct.pack("<ii", tv, ui_id)
    assert len(tv_ui) == TV_COUNT * 8
    out.append((ADDR_TV_UI_TBL, "m600_rom_tables", bytes(tv_ui), "117-entry Tv-to-UI-ID table (IDs 67..74)"))

    # 6. Extended strings + 76-entry UI string pointer table
    str_buf = bytearray()
    str_ptrs = list(struct.unpack_from("<67I", stock, 0x10657B80 - BASE))
    for _, _, _, label in EXT_STEPS:
        str_ptrs.append(ADDR_EXT_STRS + len(str_buf))
        str_buf += label.encode("ascii") + b"\x00"
    str_ptrs.append(0)
    out.append((ADDR_EXT_STRS, "m600_rom_tables", bytes(str_buf), "Null-terminated shutter labels 60\"..600\""))
    out.append((ADDR_STR_PTR_TBL, "m600_rom_tables", struct.pack("<76I", *str_ptrs), "76-entry UI shutter string pointer table"))

    # 7. UI formatting class tables 1 & 2 (67 stock + 8 class-21 whole-second + sentinel)
    ext_cls = b"".join(struct.pack("<ii", ui_id, 21) for _, ui_id, _, _ in EXT_STEPS) + struct.pack("<ii", 0, 0)
    cls1 = stock[0x10653810 - BASE : 0x10653810 - BASE + STOCK_UI_COUNT * 8] + ext_cls
    cls2 = stock[0x10656F68 - BASE : 0x10656F68 - BASE + STOCK_UI_COUNT * 8] + ext_cls
    out.append((ADDR_UI_CLS_TBL1, "m600_rom_tables", cls1, "76-entry UI display class table 1"))
    out.append((ADDR_UI_CLS_TBL2, "m600_rom_tables", cls2, "76-entry UI display class table 2"))

    # 8. 8-entry lookup table (tv_s24, ui_id, seconds)
    ext_lu = b"".join(struct.pack("<iII", tv, ui_id, sec) for tv, ui_id, sec, _ in EXT_STEPS)
    out.append((ADDR_EXT_LOOKUP, "m600_rom_tables", ext_lu, "8-entry (tv_s24, ui_id, seconds) lookup table"))

    return out
