"""Pure-Python numeric ARMv7 Thumb-2 instruction emitter with two-pass label resolution."""
from __future__ import annotations
import struct
from typing import Callable

R0, R1, R2, R3, R4, R5, R6, R7 = 0, 1, 2, 3, 4, 5, 6, 7
R8, R9, R10, R11, IP, SP, LR, PC = 8, 9, 10, 11, 12, 13, 14, 15

COND_EQ = 0x0
COND_NE = 0x1
COND_CS = 0x2  # HS / unsigned >=
COND_CC = 0x3  # LO / unsigned <
COND_MI = 0x4
COND_PL = 0x5
COND_LS = 0x9  # unsigned <=
COND_GE = 0xA  # signed >=
COND_LT = 0xB  # signed <
COND_GT = 0xC  # signed >
COND_LE = 0xD  # signed <=


def reg_mask(*regs: int) -> int:
    m = 0
    for r in regs:
        m |= 1 << r
    return m


def encode_branch32(pc: int, target: int, link: bool = False) -> bytes:
    off = target - (pc + 4)
    assert (off & 1) == 0 and -0x1000000 <= off <= 0xFFFFFE, f"Branch out of range: {pc:#x} -> {target:#x}"
    s = (off >> 24) & 1
    i1 = (off >> 23) & 1
    i2 = (off >> 22) & 1
    j1 = (~i1 ^ s) & 1
    j2 = (~i2 ^ s) & 1
    imm10 = (off >> 12) & 0x3FF
    imm11 = (off >> 1) & 0x7FF
    hw1 = 0xF000 | (s << 10) | imm10
    hw2 = (0xD000 if link else 0x9000) | (j1 << 13) | (j2 << 11) | imm11
    return struct.pack("<HH", hw1, hw2)


class ThumbEmitter:
    def __init__(self, base_addr: int) -> None:
        self.base = base_addr
        self.buf = bytearray()
        self.labels: dict[str, int] = {}
        self.fixups: list[tuple[int, str, int | None]] = []

    @property
    def pc(self) -> int:
        return self.base + len(self.buf)

    def h16(self, hw: int) -> None:
        self.buf += struct.pack("<H", hw & 0xFFFF)

    def h32(self, hw1: int, hw2: int) -> None:
        self.buf += struct.pack("<HH", hw1 & 0xFFFF, hw2 & 0xFFFF)

    def label(self, name: str) -> None:
        assert name not in self.labels, f"Duplicate label {name}"
        self.labels[name] = self.pc

    def nop(self) -> None:
        self.h16(0xBF00)

    def ret_lr(self) -> None:
        self.h16(0x4770)

    def barrier_sy(self) -> None:
        self.h32(0xF3BF, 0x8F5F)

    def save_flags(self, rd: int) -> None:
        self.h32(0xF3EF, 0x8000 | (rd << 8))

    def restore_flags(self, rn: int) -> None:
        self.h32(0xF380 | rn, 0x8C00)

    def push(self, *regs: int) -> None:
        m = reg_mask(*regs)
        if (m & ~0x40FF) == 0 and (m & 0xFF) != 0:
            self.h16(0xB400 | (((m >> 14) & 1) << 8) | (m & 0xFF))
        else:
            assert (m & ~0x5FFF) == 0 and len(regs) >= 2
            self.h32(0xE92D, m)

    def pop(self, *regs: int) -> None:
        m = reg_mask(*regs)
        if (m & ~0x80FF) == 0 and (m & 0xFF) != 0:
            self.h16(0xBC00 | (((m >> 15) & 1) << 8) | (m & 0xFF))
        else:
            assert (m & ~0xDFFF) == 0 and len(regs) >= 2
            self.h32(0xE8BD, m)

    def sp_add(self, imm: int) -> None:
        assert imm >= 0 and (imm & 3) == 0 and (imm >> 2) <= 0x7F
        self.h16(0xB000 | (imm >> 2))

    def sp_sub(self, imm: int) -> None:
        assert imm >= 0 and (imm & 3) == 0 and (imm >> 2) <= 0x7F
        self.h16(0xB080 | (imm >> 2))

    def mov_u16(self, rd: int, imm16: int) -> None:
        assert 0 <= imm16 <= 0xFFFF
        if rd < 8 and imm16 <= 0xFF:
            self.h16(0x2000 | (rd << 8) | imm16)
            return
        i = (imm16 >> 11) & 1
        imm4 = (imm16 >> 12) & 0xF
        imm3 = (imm16 >> 8) & 0x7
        imm8 = imm16 & 0xFF
        self.h32(0xF240 | (i << 10) | imm4, (imm3 << 12) | (rd << 8) | imm8)

    def movt_u16(self, rd: int, imm16: int) -> None:
        assert 0 <= imm16 <= 0xFFFF
        i = (imm16 >> 11) & 1
        imm4 = (imm16 >> 12) & 0xF
        imm3 = (imm16 >> 8) & 0x7
        imm8 = imm16 & 0xFF
        self.h32(0xF2C0 | (i << 10) | imm4, (imm3 << 12) | (rd << 8) | imm8)

    def set_u32(self, rd: int, val: int) -> None:
        val &= 0xFFFFFFFF
        self.mov_u16(rd, val & 0xFFFF)
        hi = (val >> 16) & 0xFFFF
        if hi != 0:
            self.movt_u16(rd, hi)

    def set_max_i32(self, rd: int) -> None:
        self.h32(0xF06F, 0x4000 | (rd << 8))

    def mov_reg(self, rd: int, rm: int) -> None:
        self.h16(0x4600 | (((rd >> 3) & 1) << 7) | ((rm & 0xF) << 3) | (rd & 7))

    def add_u12(self, rd: int, rn: int, imm12: int) -> None:
        assert 0 <= imm12 <= 0xFFF
        i = (imm12 >> 11) & 1
        imm3 = (imm12 >> 8) & 7
        imm8 = imm12 & 0xFF
        self.h32(0xF200 | (i << 10) | rn, (imm3 << 12) | (rd << 8) | imm8)

    def sub_u12(self, rd: int, rn: int, imm12: int) -> None:
        assert 0 <= imm12 <= 0xFFF
        i = (imm12 >> 11) & 1
        imm3 = (imm12 >> 8) & 7
        imm8 = imm12 & 0xFF
        self.h32(0xF2A0 | (i << 10) | rn, (imm3 << 12) | (rd << 8) | imm8)

    def adds_u3(self, rd: int, rn: int, imm3: int) -> None:
        assert rd < 8 and rn < 8 and 0 <= imm3 <= 7
        self.h16(0x1C00 | (imm3 << 6) | (rn << 3) | rd)

    def subs_u8(self, rdn: int, imm8: int) -> None:
        assert rdn < 8 and 0 <= imm8 <= 255
        self.h16(0x3800 | (rdn << 8) | imm8)

    def add_lsl(self, rd: int, rn: int, rm: int, shift: int = 0) -> None:
        assert 0 <= shift <= 31
        imm3 = (shift >> 2) & 7
        imm2 = shift & 3
        self.h32(0xEB00 | rn, (imm3 << 12) | (rd << 8) | (imm2 << 6) | rm)

    def lsl_imm(self, rd: int, rm: int, shift: int) -> None:
        imm3 = (shift >> 2) & 7
        imm2 = shift & 3
        self.h32(0xEA4F, (imm3 << 12) | (rd << 8) | (imm2 << 6) | rm)

    def neg_reg(self, rd: int, rn: int) -> None:
        self.h32(0xF1C0 | rn, (rd << 8) | 0)

    def sxtb(self, rd: int, rm: int) -> None:
        self.h32(0xFA4F, 0xF080 | (rd << 8) | rm)

    def sxth(self, rd: int, rm: int) -> None:
        self.h32(0xFA0F, 0xF080 | (rd << 8) | rm)

    def mul32(self, rd: int, rn: int, rm: int) -> None:
        self.h32(0xFB00 | rn, 0xF000 | (rd << 8) | rm)

    def umull64(self, rdlo: int, rdhi: int, rn: int, rm: int) -> None:
        self.h32(0xFBA0 | rn, (rdlo << 12) | (rdhi << 8) | rm)

    def cmp_u8(self, rn: int, imm8: int) -> None:
        assert 0 <= imm8 <= 255
        if rn < 8:
            self.h16(0x2800 | (rn << 8) | imm8)
        else:
            self.h32(0xF1B0 | rn, 0x0F00 | imm8)

    def cmp_reg(self, rn: int, rm: int) -> None:
        if rn < 8 and rm < 8:
            self.h16(0x4280 | (rm << 3) | rn)
        else:
            self.h16(0x4500 | (((rn >> 3) & 1) << 7) | ((rm & 0xF) << 3) | (rn & 7))

    def tst_u8(self, rn: int, imm8: int) -> None:
        assert 0 <= imm8 <= 255
        self.h32(0xF010 | rn, 0x0F00 | imm8)

    def ldr_u32(self, rt: int, rn: int, imm: int = 0) -> None:
        assert 0 <= imm <= 4095
        self.h32(0xF8D0 | rn, (rt << 12) | imm)

    def ldr_u8(self, rt: int, rn: int, imm: int = 0) -> None:
        assert 0 <= imm <= 4095
        self.h32(0xF890 | rn, (rt << 12) | imm)

    def ldr_s8(self, rt: int, rn: int, imm: int = 0) -> None:
        assert 0 <= imm <= 4095
        self.h32(0xF990 | rn, (rt << 12) | imm)

    def ldr_s16(self, rt: int, rn: int, imm: int = 0) -> None:
        assert 0 <= imm <= 4095
        self.h32(0xF9B0 | rn, (rt << 12) | imm)

    def ldr_u32_idx(self, rt: int, rn: int, rm: int, shift: int = 0) -> None:
        self.h32(0xF850 | rn, (rt << 12) | (shift << 4) | rm)

    def ldr_post4(self, rt: int, rn: int) -> None:
        self.h32(0xF850 | rn, (rt << 12) | 0x0B04)

    def str_u32(self, rt: int, rn: int, imm: int = 0) -> None:
        assert 0 <= imm <= 4095
        self.h32(0xF8C0 | rn, (rt << 12) | imm)

    def str_u8(self, rt: int, rn: int, imm: int = 0) -> None:
        assert 0 <= imm <= 4095
        self.h32(0xF880 | rn, (rt << 12) | imm)

    def str_u32_idx(self, rt: int, rn: int, rm: int, shift: int = 0) -> None:
        self.h32(0xF840 | rn, (rt << 12) | (shift << 4) | rm)

    def str_post4(self, rt: int, rn: int) -> None:
        self.h32(0xF840 | rn, (rt << 12) | 0x0B04)

    def ldrd_u32(self, rt: int, rt2: int, rn: int, imm: int = 0) -> None:
        assert (imm & 3) == 0 and 0 <= (imm >> 2) <= 255
        self.h32(0xE9D0 | rn, (rt << 12) | (rt2 << 8) | (imm >> 2))

    def strd_u32(self, rt: int, rt2: int, rn: int, imm: int = 0) -> None:
        assert (imm & 3) == 0 and 0 <= (imm >> 2) <= 255
        self.h32(0xE9C0 | rn, (rt << 12) | (rt2 << 8) | (imm >> 2))

    def j_cond(self, cond: int, label_name: str) -> None:
        self.fixups.append((len(self.buf), label_name, cond))
        self.h16(0)

    def j_local(self, label_name: str) -> None:
        self.fixups.append((len(self.buf), label_name, None))
        self.h16(0)

    def jump_abs(self, target: int) -> None:
        self.buf += encode_branch32(self.pc, target, link=False)

    def call_abs(self, target: int) -> None:
        self.buf += encode_branch32(self.pc, target, link=True)

    def finish(self) -> bytes:
        if len(self.buf) % 4 != 0:
            self.nop()
        for pos, name, cond in self.fixups:
            assert name in self.labels, f"Missing label {name}"
            ins_pc = self.base + pos
            off = self.labels[name] - (ins_pc + 4)
            assert (off & 1) == 0
            if cond is None:
                assert -2048 <= off <= 2046, f"Short jump out of range for {name}: {off}"
                hw = 0xE000 | ((off >> 1) & 0x7FF)
            else:
                assert -256 <= off <= 254, f"Cond jump out of range for {name}: {off}"
                hw = 0xD000 | (cond << 8) | ((off >> 1) & 0xFF)
            self.buf[pos : pos + 2] = struct.pack("<H", hw)
        return bytes(self.buf)
