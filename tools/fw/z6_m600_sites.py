"""In-place branch, pointer, and bound patches for Nikon Z6 C3.80 30-600s extension."""
from __future__ import annotations
import struct

from z6_m600_tables import (
    ADDR_ALLOWED_TV,
    ADDR_BOOT_ALLOC,
    ADDR_DIAL_BURST,
    ADDR_DIAL_PREREF,
    ADDR_DIAL_STEP,
    ADDR_EXIF_RAT,
    ADDR_GET_MTBL,
    ADDR_MIN_TV8,
    ADDR_MTBL_REF,
    ADDR_M_FALLBACK,
    ADDR_NS_TIMER,
    ADDR_POOL_RESET,
    ADDR_PROP_DESC,
    ADDR_PTP_GATE,
    ADDR_PTP_HDR,
    ADDR_PTP_TBL,
    ADDR_RANGE_1,
    ADDR_RANGE_2,
    ADDR_RANGE_3,
    ADDR_RANGE_4,
    ADDR_STR_PTR_TBL,
    ADDR_TOP_OLED,
    ADDR_TV_FLAG_DESC,
    ADDR_TV_UI_TBL,
    ADDR_UI_CLS_TBL1,
    ADDR_UI_CLS_TBL2,
    ADDR_UI_R7,
    ADDR_UI_R8,
    ADDR_UI_RAT,
    ADDR_UI_SP8,
    ADDR_US_TIMER,
    TV_COUNT,
    UI_COUNT,
)
from z6_thumb_emit import encode_branch32


def _jmp4(src: int, dst: int) -> bytes:
    return encode_branch32(src, dst, link=False)


def _call4(src: int, dst: int) -> bytes:
    return encode_branch32(src, dst, link=True)


def _jmp6(src: int, dst: int) -> bytes:
    return encode_branch32(src, dst, link=False) + b"\x00\xbf"


def _jmp8(src: int, dst: int) -> bytes:
    return encode_branch32(src, dst, link=False) + b"\x00\xbf\x00\xbf"


def _u32(val: int) -> bytes:
    return struct.pack("<I", val)


def build_site_patches() -> list[tuple[int, str, bytes, str]]:
    return [
        # Pool allocation, reset, and dynamic M-table lookup
        (0x101120E2, "m600_pool_runtime", _call4(0x101120E2, ADDR_BOOT_ALLOC), "Redirect boot pool allocation to allocate extended M-table"),
        (0x101E5BA8, "m600_pool_runtime", _jmp6(0x101E5BA8, ADDR_POOL_RESET), "Invalidate extended M-table block when pool resets"),
        (0x10090102, "m600_pool_runtime", _jmp6(0x10090102, ADDR_GET_MTBL), "Route M-mode shutter table getter to 120-entry table"),
        (0x1012ED8E, "m600_pool_runtime", _jmp6(0x1012ED8E, ADDR_M_FALLBACK), "Clamp M-table sentinel index fallback for 112/120 entries"),
        # Exposure timing and EXIF ExposureTime rational
        (0x1011C14A, "m600_exposure_timing", _jmp6(0x1011C14A, ADDR_NS_TIMER), "Compute exact 64-bit nanosecond exposure duration for 60s-600s"),
        (0x101C486E, "m600_exposure_timing", _jmp6(0x101C486E, ADDR_US_TIMER), "Compute exact microsecond exposure duration for 60s-600s"),
        (0x101C4790, "m600_exposure_timing", _jmp6(0x101C4790, ADDR_EXIF_RAT), "Write exact EXIF ExposureTime rational (seconds*10 / 10) for 60s-600s"),
        # Dial stepping, allowed-Tv list, and min-Tv*8 clamp
        (0x100DAD66, "m600_dial_control", _jmp4(0x100DAD66, ADDR_MIN_TV8), "Extend M-still minimum Tv*8 lower bound to -224*8 (-1792 / -960 floor)"),
        (0x1012A696, "m600_dial_control", _jmp4(0x1012A696, ADDR_DIAL_PREREF), "Refresh M-table entry flags before dial evaluation"),
        (0x1012A6CC, "m600_dial_control", _jmp4(0x1012A6CC, ADDR_DIAL_STEP), "Map 60s-600s dial steps across 1/3, 1/2, and 1 EV grids"),
        (0x1012A786, "m600_dial_control", _jmp4(0x1012A786, ADDR_MTBL_REF), "Recompute 120-entry M-table flags on active table"),
        (0x1012A874, "m600_dial_control", _jmp4(0x1012A874, ADDR_DIAL_BURST), "Stop multi-click dial burst cleanly at 30s/60s boundary"),
        (0x101508FD, "m600_dial_control", bytes([0xE0]), "Unconditional branch into allowed-Tv loop body"),
        (0x1015093E, "m600_dial_control", _jmp4(0x1015093E, ADDR_ALLOWED_TV), "Filter -144..-224 Tv entries out of non-M-still allowed lists"),
        # UI adapters, range checks, top OLED, and PTP gate
        (0x102F9E94, "m600_ui_display", _jmp4(0x102F9E94, ADDR_RANGE_1), "Include UI IDs 67..74 in seconds display group 1"),
        (0x102F9EBC, "m600_ui_display", _jmp4(0x102F9EBC, ADDR_RANGE_2), "Include UI IDs 67..74 in seconds display group 2"),
        (0x10331640, "m600_ptp_tables", _jmp4(0x10331640, ADDR_PTP_GATE), "Gate PTP 0x500D 60s-600s writes to M still mode"),
        (0x1036A7CC, "m600_ui_display", _jmp8(0x1036A7CC, ADDR_UI_R8), "Resolve extended UI ID 67..74 at 0x1036a7cc"),
        (0x1037A8BC, "m600_ui_display", _jmp4(0x1037A8BC, ADDR_UI_R7), "Resolve extended UI ID 67..74 at 0x1037a8bc"),
        (0x1041E546, "m600_ui_display", _jmp4(0x1041E546, ADDR_RANGE_3), "Include UI IDs 67..74 in LV/EVF shutter formatter 1"),
        (0x1041E71A, "m600_ui_display", _jmp4(0x1041E71A, ADDR_UI_SP8), "Resolve extended UI ID 67..74 at 0x1041e71a"),
        (0x1041E730, "m600_ui_display", _jmp4(0x1041E730, ADDR_RANGE_4), "Include UI IDs 67..74 in LV/EVF shutter formatter 2"),
        (0x10473810, "m600_ui_display", _jmp4(0x10473810, ADDR_UI_RAT), "Resolve extended shutter rational to UI ID 67..74"),
        (0x1053B16E, "m600_top_oled", _jmp4(0x1053B16E, ADDR_TOP_OLED), "Format 3-digit 60s-600s shutter label on top OLED"),
        # Table count scalars (67 -> 75 UI IDs, 109 -> 117 Tv entries)
        (0x102F5A36, "m600_table_bounds", bytes([UI_COUNT]), "Extend UI shutter ID count 67 -> 75 at 0x102f5a36"),
        (0x102FE7E6, "m600_table_bounds", bytes([TV_COUNT]), "Extend Tv lookup count 109 -> 117 at 0x102fe7e6"),
        (0x102FE7F8, "m600_table_bounds", bytes([TV_COUNT]), "Extend Tv lookup count 109 -> 117 at 0x102fe7f8"),
        (0x102FE8AE, "m600_table_bounds", bytes([UI_COUNT]), "Extend UI shutter ID count 67 -> 75 at 0x102fe8ae"),
        (0x103316A6, "m600_table_bounds", bytes([TV_COUNT, 0x2E, 0xE4, 0xD3, TV_COUNT]), "Extend PTP Tv table loop bound 109 -> 117 at 0x103316a6"),
        (0x1033192E, "m600_table_bounds", bytes([TV_COUNT]), "Extend PTP 0x500D enumeration count 109 -> 117"),
        (0x10331CCA, "m600_table_bounds", bytes([TV_COUNT]), "Extend PTP 0xD100 enumeration count 109 -> 117"),
        (0x1036A89C, "m600_table_bounds", bytes([UI_COUNT]), "Extend UI shutter ID bound 67 -> 75 at 0x1036a89c"),
        (0x1037A8F6, "m600_table_bounds", bytes([UI_COUNT]), "Extend UI shutter ID bound 67 -> 75 at 0x1037a8f6"),
        (0x1037B238, "m600_table_bounds", bytes([TV_COUNT]), "Extend Tv lookup count 109 -> 117 at 0x1037b238"),
        # Relocated table literal pointers
        (0x102FA09C, "m600_table_ptrs", _u32(ADDR_STR_PTR_TBL), "Point shutter string table literal 1 to 75-entry table"),
        (0x102FEA48, "m600_table_ptrs", _u32(ADDR_TV_UI_TBL), "Point Tv->UI map literal 1 to 117-entry table"),
        (0x102FEA50, "m600_table_ptrs", _u32(ADDR_UI_CLS_TBL1), "Point UI class table 1 literal to 75-entry table"),
        (0x102FEA5C, "m600_table_ptrs", _u32(ADDR_STR_PTR_TBL), "Point shutter string table literal 2 to 75-entry table"),
        (0x1033173C, "m600_table_ptrs", _u32(ADDR_PTP_HDR), "Point PTP shutter descriptor header to relocated copy"),
        (0x10331BAC, "m600_table_ptrs", _u32(ADDR_PTP_TBL), "Point PTP shutter table literal 1 to 117-entry table"),
        (0x10331E74, "m600_table_ptrs", _u32(ADDR_PTP_TBL), "Point PTP shutter table literal 2 to 117-entry table"),
        (0x1037AB30, "m600_table_ptrs", struct.pack("<II", ADDR_UI_CLS_TBL2, ADDR_STR_PTR_TBL), "Point UI class table 2 and string table literals"),
        (0x1037B3BC, "m600_table_ptrs", _u32(ADDR_TV_UI_TBL), "Point Tv->UI map literal 2 to 117-entry table"),
        (0x1041E6D4, "m600_table_ptrs", _u32(ADDR_STR_PTR_TBL), "Point LV/EVF shutter string table literal to 75-entry table"),
        (0x114D3518, "m600_table_ptrs", struct.pack("<II", ADDR_PROP_DESC, ADDR_TV_FLAG_DESC), "Point property refresh descriptor and Tv step-flag descriptor"),
    ]
