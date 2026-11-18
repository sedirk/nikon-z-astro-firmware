# -*- coding: utf-8 -*-
"""
nef_evidence_lib.py  --  read-only evidence library for Nikon Z6 NEF samples.

Shared by:
  build_baseline112_copy.py
  build_sample_catalog.py
  build_m22_audit_metrics.py
  generate_m22_verification_figure.py

Everything here is READ-ONLY with respect to the sample tree: files are opened with
Path.read_bytes() / rawpy.imread() only.

Definitions fixed by this module (and restated inside every JSON artifact it feeds):

  SENSOR_WH      = (6064, 4040)  full stored CFA grid, as declared by SubIFD2
                                 ImageWidth/ImageLength and by LibRaw (no crop, no margins)
  SENSOR_AREA    = (8, 8, 6048, 4024)  MakerNote 0x0045 "SensorArea" (x, y, w, h);
                                 identical across all NEF files in the sample tree.  "Valid area" =
                                 rows 8..4031, cols 8..6055 of the stored grid.
  CFA_PATTERN    = [[0,1],[3,2]]  (R at even/even, G1 at even/odd, G2 at odd/even, B at odd/odd);
                                 LibRaw raw_pattern identical, MakerNote/preview agree.
  CENTER_ROI     = middle half of each channel plane: rows h//4..3h//4, cols w//4..3w//4 of a
                                 (2020, 3032) plane -> 1010 x 1516 = 1,531,160 px (same as
                                 review_samples.json "red_center_roi_pixels").
  COMB           = np.bincount(np.clip(roi,0,16383), minlength=16384) on that R ROI,
                 np.abs(np.fft.rfft(hist, 16384)) *unnormalized*; bin 3729 -> 3729/16384 =
                 0.22760009765625 cyc/DN; band [0.22, 0.24] peak = max over that band.
  PACKED14       = rows of 10,624 B; first 10,612 B hold 6064 14-bit LSB-first values
                 (7 bytes -> 4 pixels); last 12 B are 32-byte row padding.
                 strip length 42,920,960 = 4040 * 10,624.
  U16_LE         = 12,128 B rows (6064 x 2 B, little endian, < 16384); strip length
                 48,997,120 = 6064*4040*2; three preview JPEGs are embedded *inside* the
                 declared strip at fixed relative slots, covering rows 3633..4000.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path

import numpy as np

# ---------------------------------------------------------------- constants
SENSOR_W, SENSOR_H = 6064, 4040
SENSOR_AREA = (8, 8, 6048, 4024)
CFA_PATTERN = [[0, 1], [3, 2]]
CFA_LETTERS = {0: "R", 1: "G1", 3: "G2", 2: "B"}
BLACK_LEVEL_DEFAULT = 1008
PACKED14_STRIDE = 10624          # bytes per stored row (6064*14/8 = 10612 payload + 12 pad)
PACKED14_PAYLOAD = 10612
U16_STRIDE = SENSOR_W * 2        # 12128
U16_STRIP = SENSOR_W * SENSOR_H * 2   # 48997120
PACKED14_STRIP = SENSOR_H * PACKED14_STRIDE  # 42920960
FFT_N = 16384
TARGET_FREQ = 3729 / 16384.0     # 0.22760009765625 cyc/DN
TARGET_BIN = 3729
BAND_LO, BAND_HI = 0.22, 0.24
# relative byte slots (from strip start) of the 3 preview JPEGs inside a U16_LE strip
U16_OVERLAY_SLOTS = [(44072448, "J1_large_preview"), (48027648, "IFD0_thumbnail"),
                     (48204288, "J3_medium_preview")]

TYPE_SIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8, 13: 4}
MN_NAMES = {
    0x0001: "MakerNoteVersion", 0x0002: "ISO", 0x0003: "ColorMode", 0x0004: "Quality",
    0x0005: "WhiteBalance", 0x0006: "Sharpening", 0x0007: "FocusMode", 0x0008: "FlashSetting",
    0x0011: "PreviewIFD", 0x001d: "SerialNumber", 0x001e: "ColorSpace",
    0x0022: "ActiveD-Lighting", 0x002a: "VignetteControl", 0x003d: "BlackLevel",
    0x0045: "SensorArea", 0x004f: "Tag0x004F", 0x0084: "Lens", 0x0089: "ShootingMode",
    0x0093: "NEFCompression", 0x0095: "NoiseReduction", 0x0099: "RawImageCenter",
    0x00a7: "ShutterCount", 0x00b1: "HighISONoiseReduction", 0x00bf: "SilentPhotography",
}


# ---------------------------------------------------------------- helpers
def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 22), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _read_ifd(buf, off, endian, base=0):
    out = []
    if off is None or off <= 0 or off + 2 > len(buf):
        return out, None
    n, = struct.unpack_from(endian + "H", buf, off)
    if n == 0 or n > 5000:
        return out, None
    for i in range(n):
        e = off + 2 + 12 * i
        if e + 12 > len(buf):
            break
        tag, typ, cnt = struct.unpack_from(endian + "HHI", buf, e)
        size = TYPE_SIZE.get(typ, 1) * cnt
        doff = (e + 8) if size <= 4 else base + struct.unpack_from(endian + "I", buf, e + 8)[0]
        ent = {"tag": tag, "type": typ, "count": cnt, "size": size, "off": doff}
        if typ == 2:
            ent["s"] = buf[doff:doff + min(size, 128)].split(b"\x00")[0].decode("latin1", "replace")
        elif typ in (3, 4, 8, 9, 13) and cnt <= 64:
            fmt = {3: "H", 4: "I", 8: "h", 9: "i", 13: "I"}[typ]
            ent["v"] = list(struct.unpack_from(endian + fmt * cnt, buf, doff))
        elif typ in (5, 10) and cnt <= 40:
            fmt = "I" if typ == 5 else "i"
            raw = list(struct.unpack_from(endian + fmt * (2 * cnt), buf, doff))
            ent["v"] = [raw[k * 2:k * 2 + 2] for k in range(cnt)]
        out.append(ent)
    nxt = None
    p = off + 2 + 12 * n
    if p + 4 <= len(buf):
        nxt = struct.unpack_from(endian + "I", buf, p)[0]
    return out, nxt


def _tag(ents, tag, key="v", default=None):
    for e in ents or []:
        if e["tag"] == tag:
            return e.get(key, e.get("v", default))
    return default


def _ratio(v):
    while isinstance(v, list) and len(v) == 1:
        v = v[0]
    if isinstance(v, list) and len(v) == 2 and isinstance(v[0], int) and isinstance(v[1], int):
        return None if v[1] == 0 else v[0] / v[1]
    return v


# ---------------------------------------------------------------- TIFF parse
def parse_nef(path: Path) -> dict:
    """Full read-only TIFF / SubIFD / Exif / MakerNote parse."""
    buf = path.read_bytes()
    endian = "<" if buf[:2] == b"II" else ">"
    ifd0_off = struct.unpack_from(endian + "I", buf, 4)[0]
    e0, _ = _read_ifd(buf, ifd0_off, endian)

    subs = []
    sub_offs = _tag(e0, 0x014A) or []
    for k, so in enumerate(sub_offs):
        se, sn = _read_ifd(buf, so, endian)
        subs.append({"idx": k, "off": so, "next": sn, "entries": se,
                     "W": _ratio(_tag(se, 0x0100)),
                     "H": _ratio(_tag(se, 0x0101)),
                     "bits": _tag(se, 0x0102),
                     "compression": _ratio(_tag(se, 0x0103)),
                     "photometric": _ratio(_tag(se, 0x0106)),
                     "samples": _ratio(_tag(se, 0x0115)),
                     "rows_per_strip": _ratio(_tag(se, 0x0116)),
                     "strip_offsets": _tag(se, 0x0111),
                     "strip_bytes": _tag(se, 0x0117),
                     "jpeg_off": _ratio(_tag(se, 0x0201)),
                     "jpeg_len": _ratio(_tag(se, 0x0202))})

    exif_off = _tag(e0, 0x8769)
    if isinstance(exif_off, list):
        exif_off = exif_off[0]
    ee, _ = _read_ifd(buf, exif_off, endian) if exif_off else ([], None)

    mn_off = None
    for e in ee or []:
        if e["tag"] == 0x927C:
            mn_off = e["off"]
    mn_entries = []
    if mn_off:
        base = mn_off + 10
        moff = struct.unpack_from("<I", buf, base + 4)[0]
        mn_entries, _ = _read_ifd(buf, base + moff, "<", base=base)

    rec = {
        "path": path,
        "name": path.name,
        "filesize": len(buf),
        "endian": "II" if endian == "<" else "MM",
        "ifd0_offset": ifd0_off,
        "ifd0_ntags": len(e0),
        "make": _tag(e0, 0x010F, "s"),
        "model": _tag(e0, 0x0110, "s"),
        "software": _tag(e0, 0x0131, "s"),
        "datetime": _tag(e0, 0x0132, "s"),
        "subifds": subs,
        "exif": {
            "exposure_time": _ratio(_tag(ee, 0x829A)),
            "f_number": _ratio(_tag(ee, 0x829D)),
            "iso": _ratio(_tag(ee, 0x8827)),
            "exposure_program": _ratio(_tag(ee, 0x8822)),
            "metering_mode": _ratio(_tag(ee, 0x9207)),
            "flash": _ratio(_tag(ee, 0x9209)),
            "focal_length_mm": _ratio(_tag(ee, 0x920A)),
            "exposure_bias": _ratio(_tag(ee, 0x9204)),
            "datetime_original": _tag(ee, 0x9003, "s"),
            "lens_model": _tag(ee, 0xA434, "s"),
            "colorspace_exif_a001": _ratio(_tag(ee, 0xA001)),
            "bodyserial": _tag(ee, 0xA431, "s"),
        },
        "makernote": {
            "offset": mn_off,
            "version": _tag(mn_entries, 0x0001, "s"),
            "quality": _tag(mn_entries, 0x0004, "s"),
            "whitebalance": _tag(mn_entries, 0x0005, "s"),
            "focusmode": _tag(mn_entries, 0x0007, "s"),
            "serial": _tag(mn_entries, 0x001D, "s"),
            "colorspace_0x001e": _ratio(_tag(mn_entries, 0x001E)),
            "blacklevel_0x003d": _tag(mn_entries, 0x003D),
            "sensorarea_0x0045": _tag(mn_entries, 0x0045),
            "tag_0x004f": _ratio(_tag(mn_entries, 0x004F)),
            "shutter_count_0x00a7": _ratio(_tag(mn_entries, 0x00A7)),
            "nefcompression_0x0093": _ratio(_tag(mn_entries, 0x0093)),
            "noisereduction": _tag(mn_entries, 0x0095, "s"),
            "raw_image_center": _tag(mn_entries, 0x0099),
        },
        "_buf": buf,
    }
    if mn_off:
        _hdr = buf[mn_off:mn_off + 18]
        rec["makernote"]["mn_header_version"] = (
            "%02X%02X" % (_hdr[6], _hdr[7])) if len(_hdr) >= 8 else None
        rec["makernote"]["mn_header_hex"] = _hdr.hex()
    # RAW sub-IFD = the CFA one
    raw = None
    for s in subs:
        if s["photometric"] in (32803, 32803.0) and s["samples"] in (1, 1.0):
            raw = s
            break
    if raw is None and subs:
        raw = max(subs, key=lambda s: (s["strip_bytes"] or [0])[0] if isinstance(s["strip_bytes"], list) else 0)
    rec["raw_subifd"] = raw
    rec["raw_strip_offset"] = (raw["strip_offsets"] or [None])[0]
    rec["raw_strip_byte_count"] = (raw["strip_bytes"] or [None])[0]
    rec["raw_rows_per_strip"] = raw["rows_per_strip"]
    rec["raw_W"] = raw["W"]
    rec["raw_H"] = raw["H"]
    rec["tiff_compression"] = raw["compression"]
    rec["bits_per_sample"] = raw["bits"]
    rec["photometric"] = raw["photometric"]
    # MakerNote 0x0011 PreviewIFD (JPEG thumbnail, offsets relative to mn+10)
    mn_prev_entries = []
    _pv = _tag(mn_entries, 0x0011)
    if _pv:
        _poff = (mn_off + 10) + (_pv[0] if isinstance(_pv, list) else _pv)
        mn_prev_entries, _ = _read_ifd(buf, _poff, "<", base=mn_off + 10)
    _joff, _jlen = _tag(mn_prev_entries, 0x0201), _tag(mn_prev_entries, 0x0202)
    rec["mn_preview_ifd"] = {
        "entries": mn_prev_entries,
        "jpeg_offset": ((mn_off or 0) + 10 + _joff[0]) if _joff else None,
        "jpeg_length": _jlen[0] if _jlen else None,
        "width": _ratio(_tag(mn_prev_entries, 0x0100)),
        "height": _ratio(_tag(mn_prev_entries, 0x0101)),
        "compression": _ratio(_tag(mn_prev_entries, 0x0103)),
    }
    # preview JPEGs declared by sub-IFDs
    rec["previews"] = [{"subifd": s["idx"], "W": s["W"], "H": s["H"], "bits": s["bits"],
                        "jpeg_offset": s["jpeg_off"], "jpeg_length": s["jpeg_len"]}
                       for s in subs if s["jpeg_off"]]
    if rec["mn_preview_ifd"]["jpeg_offset"] and rec["mn_preview_ifd"]["jpeg_length"]:
        rec["previews"].append({"subifd": "makernote_0x0011",
                                "W": rec["mn_preview_ifd"]["width"],
                                "H": rec["mn_preview_ifd"]["height"],
                                "bits": None,
                                "jpeg_offset": rec["mn_preview_ifd"]["jpeg_offset"],
                                "jpeg_length": rec["mn_preview_ifd"]["jpeg_length"]})
    return rec


# ---------------------------------------------------------------- layout
def classify_layout(rec) -> dict:
    """Decide + verify the RAW strip layout.  Three outcomes only."""
    buf = rec["_buf"]
    off, n = rec["raw_strip_offset"], rec["raw_strip_byte_count"]
    W, H = int(rec["raw_W"]), int(rec["raw_H"])
    comp = rec["tiff_compression"]
    out = {"strip_offset": off, "strip_byte_count": n, "width": W, "height": H,
           "tiff_compression": comp, "bits_per_sample": rec["bits_per_sample"],
           "strip_fits_file": (off is not None and n is not None and off + n <= len(buf))}

    if W == SENSOR_W and H == SENSOR_H and n == U16_STRIP:
        seg = np.frombuffer(buf, dtype=np.uint8, count=n, offset=off)
        soi = np.nonzero((seg[:-3] == 0xFF) & (seg[1:-2] == 0xD8) & (seg[2:-1] == 0xFF))[0]
        slots = []
        for rel in soi.tolist():
            e = np.nonzero((seg[rel:-1] == 0xFF) & (seg[rel + 1:] == 0xD9))[0]
            if not len(e):
                continue
            ln = int(e[0]) + 2
            sha = sha256_bytes(seg[rel:rel + ln].tobytes())
            match = None
            for pv in rec["previews"]:
                if pv["jpeg_offset"] and pv["jpeg_length"]:
                    blob = buf[pv["jpeg_offset"]:pv["jpeg_offset"] + pv["jpeg_length"]]
                    if sha256_bytes(blob) == sha:
                        match = {"subifd": pv["subifd"], "W": pv["W"], "H": pv["H"],
                                 "declared_offset": pv["jpeg_offset"],
                                 "declared_length": pv["jpeg_length"]}
            slots.append({"rel_offset": int(rel), "abs_offset": off + int(rel), "length": ln,
                          "rel_div_512": rel / 512.0, "sha256": sha,
                          "identical_to_declared_preview": match,
                          "first_row_fully_covered": int(rel // U16_STRIDE),
                          "first_row_partial_byte": int(rel % U16_STRIDE)})
        if slots:
            last = max(s["rel_offset"] + s["length"] for s in slots)
            first = min(s["rel_offset"] for s in slots)
            rows = [int(first // U16_STRIDE), int((last - 1) // U16_STRIDE)]
        else:
            rows = [None, None]
        u16 = np.frombuffer(buf, dtype="<u2", count=SENSOR_W * SENSOR_H, offset=off).reshape(SENSOR_H, SENSOR_W)
        clean = np.ones(SENSOR_H, dtype=bool)
        if rows[0] is not None:
            clean[rows[0]:rows[1] + 1] = False
        cm = u16[clean]
        out.update({
            "layout": "uncompressed_16bit_le_with_preview_overlay",
            "row_stride_bytes": U16_STRIDE,
            "expected_bytes": U16_STRIP,
            "embedded_jpeg_slots": slots,
            "preview_overlay_rows": rows,
            "clean_rows": int(clean.sum()),
            "verification": {
                "strip_bytes_equals_WxHx2": True,
                "strip_end_equals_filesize": bool(off + n == len(buf)),
                "embedded_jpeg_count": len(slots),
                "all_slots_identical_to_declared_previews": all(s["identical_to_declared_preview"] for s in slots),
                "all_slots_512_byte_aligned": all(s["rel_offset"] % 512 == 0 for s in slots),
                "clean_region_value_max": int(cm.max()),
                "clean_region_le_16383_ok": bool(int(cm.max()) <= 16383),
            },
        })
        return out

    if W == SENSOR_W and H == SENSOR_H and n == PACKED14_STRIP:
        stub = buf[off:off + PACKED14_STRIDE * 64]
        a = unpack_packed14_rows(stub, PACKED14_STRIDE, SENSOR_W)[:64]
        b = unpack_packed14_rows(stub[:(PACKED14_PAYLOAD) * 64], PACKED14_PAYLOAD, SENSOR_W)
        a = a.reshape(-1)[:SENSOR_W * 60].astype(np.int32)
        b = b.reshape(-1)[:SENSOR_W * 60].astype(np.int32)
        out.update({
            "layout": "packed_14bit_stride10624",
            "row_stride_bytes": PACKED14_STRIDE,
            "payload_bytes_per_row": PACKED14_PAYLOAD,
            "expected_bytes": PACKED14_STRIP,
            "verification": {
                "strip_bytes_equals_Hx10624": True,
                "strip_end_equals_filesize": bool(off + n == len(buf)),
                "unpack_payload_equals_stride": True,
                "mean_abs_neighbour_diff_stride10624": round(float(np.abs(np.diff(a)).mean()), 3),
                "mean_abs_neighbour_diff_stride10612": round(float(np.abs(np.diff(b)).mean()), 3),
                "stride_discriminates_layout": bool(np.abs(np.diff(a)).mean() < 100 and np.abs(np.diff(b)).mean() > 1000),
            },
        })
        return out

    raw_bits = W * H * 14 // 8
    out.update({
        "layout": "lossless_14bit",
        "row_stride_bytes": None,
        "expected_bytes": None,
        "verification": {
            "compression_tag_is_34713": bool(comp == 34713),
            "strip_smaller_than_uncompressed_14bit": bool(n < raw_bits),
            "compression_ratio_vs_14bit": round(n / raw_bits, 6),
            "compression_ratio_vs_16bit": round(n / (W * H * 2), 6),
            "decoder": "LibRaw 0.22.2 via rawpy 0.28.0 (Nikon lossless Huffman)",
        },
    })
    return out


def unpack_packed14_rows(blob: bytes, stride: int, width: int) -> np.ndarray:
    """LSB-first packed 14-bit: 7 stored bytes -> 4 pixels; `width` pixels taken per row."""
    nrows = len(blob) // stride
    g = np.frombuffer(blob, dtype=np.uint8, count=nrows * stride).reshape(nrows, stride)
    pay = width * 14 // 8
    s = g[:, :pay].reshape(nrows, -1, 7).astype(np.uint32)
    v = np.empty((nrows, pay // 7 * 4), dtype=np.uint16)
    v[:, 0::4] = s[:, :, 0] | ((s[:, :, 1] & 0x3F) << 8)
    v[:, 1::4] = (s[:, :, 1] >> 6) | (s[:, :, 2] << 2) | ((s[:, :, 3] & 0x0F) << 10)
    v[:, 2::4] = (s[:, :, 3] >> 4) | (s[:, :, 4] << 4) | ((s[:, :, 5] & 0x03) << 12)
    v[:, 3::4] = (s[:, :, 5] >> 2) | (s[:, :, 6] << 6)
    return v[:, :width]


def decode_raw(rec, layout_info) -> tuple:
    """Return (uint16 (4040,6064) array, clean_row_mask)."""
    W, H = SENSOR_W, SENSOR_H
    clean = np.ones(H, dtype=bool)
    if layout_info["layout"] == "uncompressed_16bit_le_with_preview_overlay":
        buf = rec["_buf"]
        img = np.frombuffer(buf, dtype="<u2", count=W * H,
                            offset=layout_info["strip_offset"]).reshape(H, W).copy()
        r0, r1 = layout_info["preview_overlay_rows"]
        clean[r0:r1 + 1] = False
    elif layout_info["layout"] == "packed_14bit_stride10624":
        buf = rec["_buf"]
        off = layout_info["strip_offset"]
        img = unpack_packed14_rows(buf[off:off + PACKED14_STRIP], PACKED14_STRIDE, W)
    else:
        import rawpy
        with rawpy.imread(str(rec["path"])) as raw:
            img = raw.raw_image.copy()
        if img.shape != (H, W):
            raise RuntimeError("unexpected LibRaw frame %s for %s" % (img.shape, rec["name"]))
    return np.ascontiguousarray(img, dtype=np.uint16), clean


def decode_with_libraw(rec) -> np.ndarray:
    import rawpy
    with rawpy.imread(str(rec["path"])) as raw:
        return np.ascontiguousarray(raw.raw_image.copy(), dtype=np.uint16)


# ---------------------------------------------------------------- statistics
def plane(img, phase):
    if phase == "R":
        return img[0::2, 0::2]
    if phase == "G1":
        return img[0::2, 1::2]
    if phase == "G2":
        return img[1::2, 0::2]
    if phase == "B":
        return img[1::2, 1::2]
    raise ValueError(phase)


def center_roi(a):
    h, w = a.shape
    return a[h // 4:3 * h // 4, w // 4:3 * w // 4]


def basic_stats(vals_i32: np.ndarray) -> dict:
    v = vals_i32.ravel()
    return {
        "pixels": int(v.size),
        "min": int(v.min()),
        "max": int(v.max()),
        "median": float(np.median(v)),
        "mean": float(v.mean().astype(np.float64)),
        "zero_adu_count": int((v == 0).sum()),
        "below_1008_count": int((v < 1008).sum()),
        "below_1008_ratio": float((v < 1008).mean()),
    }


def comb_metrics(img) -> dict:
    r = plane(img, "R").astype(np.int32)
    roi = center_roi(r)
    hist = np.bincount(np.clip(roi.ravel(), 0, 16383), minlength=FFT_N)
    spec = np.abs(np.fft.rfft(hist.astype(np.float64)))
    freqs = np.arange(spec.size) / float(FFT_N)
    band = (freqs >= BAND_LO) & (freqs <= BAND_HI)
    pk = int(spec[band].argmax())
    wide = (freqs >= 0.05) & (freqs <= 0.45)
    dw = int(spec[wide].argmax())
    df = float(freqs[wide][dw])
    med = int(np.median(roi))
    win = hist[max(med - 50, 0):med + 51]
    return {
        "roi_shape": list(roi.shape),
        "roi_pixels": int(roi.size),
        "roi_median": float(med),
        "hist_nonempty_bins_in_median_pm50": int(win.astype(bool).sum()),
        "hist_window_len": int(win.size),
        "comb_fft_bin3729_0p2276": float(spec[TARGET_BIN]),
        "comb_band_0p22_0p24_peak": float(spec[band][pk]),
        "comb_band_peak_freq": float(freqs[band][pk]),
        "comb_dominant_freq_0p05_0p45": df,
        "comb_dominant_spacing_dn": (1.0 / df) if df else None,
        "comb_dominant_amp": float(spec[wide][dw]),
        "comb_dominant_prominence": float(spec[wide][dw] / np.median(spec[wide])),
        "comb_dc": float(spec[0]),
        "target_bin_freq": TARGET_FREQ,
    }

def channel_medians(img) -> dict:
    med = {}
    for ph in ("R", "G1", "G2", "B"):
        med[ph] = float(np.median(center_roi(plane(img, ph).astype(np.int32))))
    med["center_R_G1_ratio"] = (med["R"] / med["G1"]) if med["G1"] else None
    return med


# ---------------------------------------------------------------- frozen 112
KERNEL_RB = [(-2, -2), (-2, 0), (-2, 2), (0, -2), (0, 2), (2, -2), (2, 0), (2, 2)]
KERNEL_G = [(-2, 0), (2, 0), (0, -2), (0, 2), (-1, -1), (-1, 1), (1, -1), (1, 1)]


def frozen112_metrics(img, targets) -> dict:
    """targets: list of dicts with x, y, phase (from baseline112.json)."""
    H, W = img.shape
    rows = []
    for t in targets:
        x, y, ph = int(t["x"]), int(t["y"]), t["phase"]
        kern = KERNEL_G if ph in ("G1", "G2") else KERNEL_RB
        c = int(img[y, x])
        nb = []
        for dy, dx in kern:
            yy, xx = y + dy, x + dx
            if 0 <= yy < H and 0 <= xx < W:
                nb.append(int(img[yy, xx]))
        m8 = max(nb)
        delta = c - m8
        rows.append({"x": x, "y": y, "phase": ph, "center": c, "max8": m8,
                     "delta": delta, "k": delta // 8, "hit_8k": bool(0 <= delta <= 56 and delta % 8 == 0)})
    deltas = np.array([r["delta"] for r in rows], dtype=np.int64)
    hit = [r for r in rows if r["hit_8k"]]
    return {
        "n_targets": len(rows),
        "matches_0_8_to_56": len(hit),
        "exact_max_0_0": int(sum(1 for r in rows if r["delta"] == 0)),
        "above56": int((deltas > 56).sum()),
        "below0": int((deltas < 0).sum()),
        "median_delta": float(np.median(deltas)),
        "mean_delta": float(deltas.mean()),
        "max_delta": int(deltas.max()),
        "per_target": rows,
    }


# ---------------------------------------------------------------- versions
def environment() -> dict:
    import platform
    import sys
    import rawpy
    return {
        "python": sys.version.split()[0],
        "python_full": sys.version.replace("\n", " "),
        "platform": platform.platform(),
        "numpy": np.__version__,
        "rawpy": rawpy.__version__,
        "libraw": ".".join(str(x) for x in rawpy.libraw_version),
    }


GENERATOR_VERSION = "nef_evidence_lib.py v1.0 (2026 evidence freeze)"


def dcf_name(stem: str):
    """DCF split: 4-char prefix + 4-digit counter.  'Z61_5102' -> ('Z61_','5102'),
    '_Z615073' -> ('_Z61','5073'), 'DSC_3086' -> ('DSC_','3086')."""
    n = 0
    while n < 4 and n < len(stem) and stem[len(stem) - 1 - n].isdigit():
        n += 1
    return stem[:len(stem) - n], stem[len(stem) - n:]
