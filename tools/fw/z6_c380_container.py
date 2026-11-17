"""Decode official Nikon Z6 C3.80 container using input-derived zero-span XOR masks.

Adapted from the MIT-licensed spanning-tree zero-offset mask recovery method in
RealCaCl2/z30-firmware-extensions (Copyright (c) 2026 Z30 Firmware Extensions
contributors; see THIRD_PARTY_NOTICES.md).

Known-zero offsets in z6_c380_zero_samples.json are version-specific structural
observations of C3.80 padding, containing neither Nikon firmware code/resources
nor third-party precomputed XOR tables. Full SHA-256 identity of the user's
legally obtained Z_6_0380.bin (or decoded eg1620_038000.bi) is verified first.
"""
from __future__ import annotations

import binascii
import hashlib
import json
from pathlib import Path
import struct

THIS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = THIS_DIR.parents[1]

CONTAINER_SIZE = 34_923_366
CONTAINER_SHA256 = "ff978ffdf77c58c0b861a06e16d432d5886969f3cdd05d62f6c8e82e8a4cea54"

STOCK_EG_NAME = "eg1620_038000.bi"
STOCK_EG_SIZE = 33_502_842
STOCK_EG_SHA256 = "1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def recover_c380_mask(encoded_body: bytes) -> tuple[bytes, bytes, bytes]:
    """Recover (columns, rows, blocks) 256-byte XOR masks from encoded Z_6_0380.bin[32:]."""
    spec_path = THIS_DIR / "z6_c380_zero_samples.json"
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    zero_anchor = int(spec["zero_anchor"])
    samples: list[int] = spec["samples"]

    if len(encoded_body) <= max(samples + [zero_anchor + 255]):
        raise ValueError("Encoded body is too short for Nikon Z6 C3.80 mask recovery")

    columns = bytes(
        val ^ encoded_body[zero_anchor]
        for val in encoded_body[zero_anchor : zero_anchor + 256]
    )
    values: list[int | None] = [None] * 512
    values[0] = 0
    for off in samples:
        row = (off >> 8) & 255
        block = 256 + ((off >> 16) & 255)
        val = encoded_body[off] ^ columns[off & 255]
        if values[row] is not None:
            recovered = values[row] ^ val
            if values[block] is not None and values[block] != recovered:
                raise ValueError("Inconsistent known-zero mask samples")
            values[block] = recovered
        elif values[block] is not None:
            values[row] = values[block] ^ val
        else:
            raise ValueError("Disconnected mask sample ordering")

    if any(v is None for v in values):
        raise ValueError("Incomplete C3.80 mask recovery")

    return columns, bytes(values[:256]), bytes(values[256:])


def apply_mask(body_or_encoded: bytes, masks: tuple[bytes, bytes, bytes]) -> bytes:
    """Symmetric XOR transform preserving the 32-byte unmasked inner header."""
    columns, rows, blocks = masks
    pattern = b"".join(bytes(c_v ^ r_v for c_v in columns) for r_v in rows)
    out = bytearray(body_or_encoded)
    for start in range(0, len(out), 65536):
        high = blocks[(start >> 16) & 255]
        stop = min(start + 65536, len(out))
        low = max(start, 32)
        out[low:stop] = bytes(
            val ^ pattern[i - start] ^ high
            for i, val in enumerate(body_or_encoded[low:stop], low)
        )
    return bytes(out)


def decode_c380_container(raw_container: bytes) -> tuple[bytes, list[dict], tuple[bytes, bytes, bytes]]:
    """Verify official Z_6_0380.bin and decode its body + 4 firmware modules."""
    raw = bytes(raw_container)
    if len(raw) != CONTAINER_SIZE or sha256_hex(raw) != CONTAINER_SHA256:
        raise ValueError(
            f"Official Z_6_0380.bin verification failed: expected {CONTAINER_SIZE} bytes "
            f"with SHA-256 {CONTAINER_SHA256}, got {len(raw)} bytes ({sha256_hex(raw)})"
        )

    encoded_body = raw[32:]
    masks = recover_c380_mask(encoded_body)
    body = apply_mask(encoded_body, masks)

    n_mods, header_size, r0, r1 = struct.unpack_from(">4I", body, 32)
    if (n_mods, header_size, r0, r1) != (4, 176, 0, 0):
        raise ValueError(f"Unexpected Z6 C3.80 decoded container header: {(n_mods, header_size, r0, r1)}")

    calc_crc = binascii.crc_hqx(body[:-16], 0)
    stored_crc = int.from_bytes(body[-16:-14], "big")
    if calc_crc != stored_crc or body[-14:] != bytes(14):
        raise ValueError("Decoded Z6 C3.80 container CRC-16/XMODEM or trailer check failed")

    modules: list[dict] = []
    cursor = header_size
    for idx in range(n_mods):
        raw_name, start, size, mr0, mr1 = struct.unpack_from(">16s4I", body, 48 + 32 * idx)
        name = raw_name.rstrip(b"\x00").decode("ascii")
        if start != cursor or size < 2 or start + size > len(body) - 16 or mr0 != 0 or mr1 != 0:
            raise ValueError(f"Invalid module bounds in Z6 C3.80 container for {name!r}")
        mod_bytes = body[start : start + size]
        if binascii.crc_hqx(mod_bytes, 0) != 0:
            raise ValueError(f"CRC-16/XMODEM remainder check failed for module {name!r}")
        modules.append(
            {
                "name": name,
                "body_offset": start,
                "size": size,
                "sha256": sha256_hex(mod_bytes),
                "data": mod_bytes,
            }
        )
        cursor = start + size

    if cursor != len(body) - 16:
        raise ValueError("Decoded Z6 C3.80 modules do not span container body")

    return body, modules, masks


def load_stock_eg_module(input_path: Path | None = None, root: Path | None = None) -> bytes:
    """Load verified Stock C3.80 EG module from either Z_6_0380.bin or eg1620_038000.bi."""
    base_root = (root or PROJECT_ROOT).resolve()
    candidates: list[Path] = []
    if input_path is not None:
        p = input_path.resolve()
        if not p.is_file():
            raise FileNotFoundError(f"Specified stock firmware input does not exist: {p}")
        candidates.append(p)
    else:
        for rel in ("firmware/decoded/eg1620_038000.bi", "firmware/original/Z_6_0380.bin"):
            cand = base_root / rel
            if cand.is_file():
                candidates.append(cand)
        if not candidates:
            raise FileNotFoundError(
                "Stock Nikon Z6 C3.80 firmware input not found. Place official 'Z_6_0380.bin' "
                f"(SHA-256 {CONTAINER_SHA256}) at '{base_root / 'firmware/original/Z_6_0380.bin'}' "
                "or pass '--stock <path-to-Z_6_0380.bin>'."
            )

    raw = candidates[0].read_bytes()
    digest = sha256_hex(raw)
    if len(raw) == STOCK_EG_SIZE and digest == STOCK_EG_SHA256:
        if binascii.crc_hqx(raw, 0) != 0:
            raise ValueError("Decoded eg1620_038000.bi failed CRC-16/XMODEM check")
        return raw

    if len(raw) == CONTAINER_SIZE and digest == CONTAINER_SHA256:
        _, modules, _ = decode_c380_container(raw)
        for m in modules:
            if m["name"] == STOCK_EG_NAME:
                if len(m["data"]) != STOCK_EG_SIZE or m["sha256"] != STOCK_EG_SHA256:
                    raise ValueError("Decoded EG module from Z_6_0380.bin failed digest check")
                return m["data"]
        raise ValueError(f"Module {STOCK_EG_NAME} missing from Z_6_0380.bin")

    raise ValueError(
        f"Unsupported input firmware '{candidates[0]}' ({len(raw):,} bytes, SHA-256 {digest}). "
        f"Expected official Nikon Z6 C3.80 Z_6_0380.bin ({CONTAINER_SHA256}) "
        f"or decoded eg1620_038000.bi ({STOCK_EG_SHA256})."
    )
