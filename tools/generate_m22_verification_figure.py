# -*- coding: utf-8 -*-
"""
generate_m22_verification_figure.py

Builds modified22_real_camera_verification.png: the same-condition Modified22 flat pair

    left column  Z61_5119.NEF  Standard sRGB flat, 1/8000 s, ISO 1600, packed-14
    right column Z61_5110.NEF  Astro RAW sRGB flat,  1/8000 s, ISO 1600, packed-14

Top row : local R-channel histogram around its median +- 50 DN
Bottom  : 16384-bin unnormalised |rfft| of that histogram, 0.15-0.35 cyc/DN
          (vertical guides at bin 3729 = 0.22760009765625 cyc/DN and at the [0.22,0.24] band peak)

Defaults are resolved relative to this file (Path(__file__).resolve()), so the script carries no
absolute path of its own:

    --samples-root   default <repo root>/samples         (directory that contains 11.17_modified22/)
    --out            default <repo root>/docs/images/modified22_real_camera_verification.png

Example:
    python generate_m22_verification_figure.py --samples-root D:\\...\\samples

Both frames are decoded by the script itself (Nikon packed-14, 10,624-byte rows, LSB-first), and the
printed numbers are the ones drawn on the figure; they are also written to <out>.numbers.json.
"""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import ScalarFormatter

SENSOR_W, SENSOR_H = 6064, 4040
PACKED14_STRIDE = 10624
PACKED14_PAYLOAD = 10612
U16_STRIP = SENSOR_W * SENSOR_H * 2
PACKED14_STRIP = SENSOR_H * PACKED14_STRIDE
FFT_N = 16384
TARGET_BIN = 3729
TARGET_FREQ = TARGET_BIN / float(FFT_N)      # 0.22760009765625
BAND = (0.22, 0.24)
TYPE_SIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8, 13: 4}


# --------------------------------------------------------------------------- minimal NEF reading
def read_ifd(buf, off, endian):
    n, = struct.unpack_from(endian + "H", buf, off)
    out = {}
    for i in range(n):
        e = off + 2 + 12 * i
        tag, typ, cnt = struct.unpack_from(endian + "HHI", buf, e)
        size = TYPE_SIZE.get(typ, 1) * cnt
        doff = (e + 8) if size <= 4 else struct.unpack_from(endian + "I", buf, e + 8)[0]
        if typ in (3, 4, 13) and cnt <= 8:
            out[tag] = list(struct.unpack_from(endian + {3: "H", 4: "I", 13: "I"}[typ] * cnt, buf, doff))
        elif typ in (5, 10) and cnt <= 8:
            f = "I" if typ == 5 else "i"
            v = list(struct.unpack_from(endian + f * (2 * cnt), buf, doff))
            out[tag] = [v[k * 2] / v[k * 2 + 1] for k in range(cnt) if v[k * 2 + 1]]
    return out


def raw_strip(path: Path):
    buf = path.read_bytes()
    endian = "<" if buf[:2] == b"II" else ">"
    ifd0 = read_ifd(buf, struct.unpack_from(endian + "I", buf, 4)[0], endian)
    for so in ifd0.get(0x014A, []):
        sub = read_ifd(buf, so, endian)
        if sub.get(0x0106) == [32803] and sub.get(0x0115) == [1]:
            return buf, sub.get(0x0111)[0], sub.get(0x0117)[0]
    raise RuntimeError("no CFA sub-IFD in %s" % path)


def unpack_packed14_rows(blob, stride, width):
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


def decode(path: Path):
    buf, off, n = raw_strip(path)
    if n == PACKED14_STRIP:
        layout = "packed_14bit_stride10624"
        img = unpack_packed14_rows(buf[off:off + PACKED14_STRIP], PACKED14_STRIDE, SENSOR_W)
    elif n == U16_STRIP:
        layout = "uncompressed_16bit_le_with_preview_overlay"
        img = np.frombuffer(buf, dtype="<u2", count=SENSOR_W * SENSOR_H, offset=off).reshape(SENSOR_H, SENSOR_W)
    else:
        raise RuntimeError("unexpected strip length %d in %s -- this figure script only handles the "
                           "two layouts of the Modified22 batch" % (n, path.name))
    return img, layout, off, n


def comb(img):
    r = img[0::2, 0::2].astype(np.int32)
    h, w = r.shape
    roi = r[h // 4:3 * h // 4, w // 4:3 * w // 4]           # middle half of each axis
    hist = np.bincount(np.clip(roi.ravel(), 0, 16383), minlength=FFT_N)
    spec = np.abs(np.fft.rfft(hist.astype(np.float64)))
    freqs = np.arange(spec.size) / float(FFT_N)
    band = (freqs >= BAND[0]) & (freqs <= BAND[1])
    pk = int(spec[band].argmax())
    wide = (freqs >= 0.05) & (freqs <= 0.45)
    dw = int(spec[wide].argmax())
    return {
        "roi_median": float(np.median(roi)),
        "roi_pixels": int(roi.size),
        "hist": hist,
        "spec": spec,
        "freqs": freqs,
        "bin3729": float(spec[TARGET_BIN]),
        "band_peak": float(spec[band][pk]),
        "band_peak_freq": float(freqs[band][pk]),
        "dominant_freq": float(freqs[wide][dw]),
        "dominant_spacing_dn": float(1.0 / freqs[wide][dw]),
        "dc": float(spec[0]),
    }


def main():
    repo_root = Path(__file__).resolve().parents[1]
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--samples-root", default=str(repo_root / "samples"),
                    help="directory containing 11.17_modified22/ (default: <repo>/samples)")
    ap.add_argument("--batch", default="11.17_modified22")
    ap.add_argument("--left", default="Z61_5119.NEF", help="Standard frame (left column)")
    ap.add_argument("--right", default="Z61_5110.NEF", help="Astro frame (right column)")
    ap.add_argument("--out", default=str(repo_root / "docs" / "images" / "modified22_real_camera_verification.png"))
    ap.add_argument("--dpi", type=int, default=200)
    args = ap.parse_args()

    root = Path(args.samples_root).resolve() / args.batch
    panels = []
    for name, tag in ((args.left, "Standard"), (args.right, "Astro")):
        p = root / name
        if not p.exists():
            raise SystemExit("missing input: %s" % p)
        img, layout, off, n = decode(p)
        d = comb(img)
        d.update({"name": name, "tag": tag, "layout": layout, "strip_offset": off,
                  "strip_byte_count": n, "path": str(p)})
        d["exptime"] = "1/8000 s"
        d["iso"] = 1600
        panels.append(d)
        print("%-14s %-38s centerR=%7.0f  bin[%d]=%10.1f  band[%.2f,%.2f]=%10.1f @%.6f" % (
            name, layout, d["roi_median"], TARGET_BIN, d["bin3729"], BAND[0], BAND[1],
            d["band_peak"], d["band_peak_freq"]))

    spec_lo, spec_hi = int(round(0.15 * FFT_N)), int(round(0.35 * FFT_N))
    y_top = max(np.max(p["hist"][max(int(p["roi_median"]) - 50, 0):int(p["roi_median"]) + 51])
                for p in panels) * 1.10
    y_bot = max(np.max(p["spec"][spec_lo:spec_hi + 1]) for p in panels) * 1.10

    fig, axes = plt.subplots(2, 2, figsize=(13.6, 9.2), constrained_layout=False)
    fig.subplots_adjust(left=0.065, right=0.985, top=0.865, bottom=0.075, hspace=0.34, wspace=0.16)

    for col, p in enumerate(panels):
        med = int(p["roi_median"])
        ax = axes[0, col]
        idx = np.arange(med - 50, med + 51)
        ax.bar(idx, p["hist"][med - 50:med + 51], width=1.0, color="#1f77b4" if col == 0 else "#d62728")
        ax.set_xlim(med - 50, med + 50)
        ax.set_ylim(0, y_top)
        ax.set_xlabel("RAW value inside the centre-R ROI (ADU)")
        ax.set_ylabel("pixels per 1-DN bin")
        ax.set_title("%s  --  %s\n%s, %s, ISO %d, %s" % (
            p["name"], "Standard sRGB flat" if col == 0 else "Astro RAW sRGB flat",
            p["tag"], p["exptime"], p["iso"], p["layout"].replace("_", " ")), fontsize=10.5)
        ax.text(0.02, 0.96,
                "centre R median = %.0f ADU\nhistogram comb spacing = %.2f DN\noccupied bins in median$\\pm$50 = %d of %d"
                % (p["roi_median"], p["dominant_spacing_dn"],
                   int(p["hist"][med - 50:med + 51].astype(bool).sum()), p["hist"][med - 50:med + 51].size),
                transform=ax.transAxes, va="top", ha="left", fontsize=8.6,
                bbox=dict(boxstyle="round,pad=0.35", fc="white", ec="0.6", alpha=0.92))
        ax.grid(alpha=0.25, lw=0.5)

        ax = axes[1, col]
        f = p["freqs"][spec_lo:spec_hi + 1]
        s = p["spec"][spec_lo:spec_hi + 1]
        ax.plot(f, s, lw=0.9, color="#1f77b4" if col == 0 else "#d62728")
        ax.axvline(TARGET_FREQ, color="0.15", ls="--", lw=0.9, label="exact bin %d = 0.227600 cyc/DN" % TARGET_BIN)
        ax.axvline(p["band_peak_freq"], color="black", ls=":", lw=1.0,
                   label="[0.22,0.24] band peak = %.6f" % p["band_peak_freq"])
        ax.set_xlim(0.15, 0.35)
        ax.set_ylim(0, y_bot)
        ax.set_xlabel("frequency (cyc/DN)  --  16384-bin histogram, unnormalised |rfft|")
        ax.set_ylabel("$|\\mathrm{rfft}(h)|$  (counts)")
        ax.ticklabel_format(axis="y", style="plain")
        ax.grid(alpha=0.25, lw=0.5)
        ax.legend(loc="upper left", fontsize=7.8, framealpha=0.92, handlelength=1.6)
        ax.text(0.98, 0.95,
                "bin %d @ 0.227600 cyc/DN = %.1f\n[0.22, 0.24] band peak = %.1f"
                % (TARGET_BIN, p["bin3729"], p["band_peak"]),
                transform=ax.transAxes, va="top", ha="right", fontsize=8.6,
                bbox=dict(boxstyle="round,pad=0.35", fc="white", ec="0.6", alpha=0.92))

    # right column: fixed Y limits identical to the left column + inset zoom
    axes[1, 1].set_ylim(0, axes[1, 0].get_ylim()[1])
    axes[0, 1].set_ylim(0, axes[0, 0].get_ylim()[1])
    ins = axes[1, 1].inset_axes([0.50, 0.12, 0.46, 0.40])
    p = panels[1]
    ins.plot(p["freqs"][spec_lo:spec_hi + 1], p["spec"][spec_lo:spec_hi + 1], lw=0.8, color="#d62728")
    ins.axvline(TARGET_FREQ, color="0.15", ls="--", lw=0.8)
    ins.axvline(p["band_peak_freq"], color="black", ls=":", lw=0.9)
    ins.set_xlim(0.15, 0.35)
    ins.set_ylim(0, np.max(p["spec"][spec_lo:spec_hi + 1]) * 1.12)
    ins.tick_params(labelsize=6.5)
    ins.set_title("Astro curve, own Y scale (detail)", fontsize=7.2)
    ins.grid(alpha=0.25, lw=0.4)
    ins.set_yticks([0, 25000, 50000, 75000])

    ratio_pk = panels[0]["band_peak"] / panels[1]["band_peak"]
    ratio_bin = panels[0]["bin3729"] / panels[1]["bin3729"]
    fig.suptitle(
        "Modified22 real-camera flat pair, same exposure (1/8000 s, ISO 1600, f/1.8, 16 mm) -- both frames "
        "packed-14, verified pixel-identical to LibRaw\n"
        "Standard (left) keeps the 4.385-DN comb, Astro (right) does not: band peak x%.2f, exact bin 3729 x%.2f"
        % (ratio_pk, ratio_bin), fontsize=11, y=0.975)

    out = Path(args.out)
    fig.savefig(out, dpi=args.dpi)
    print("wrote", out)

    numbers = {"samples_root": str(root), "out": str(out),
               "columns": [{k: v for k, v in p.items() if k not in ("hist", "spec", "freqs")} for p in panels],
               "ratio_standard_over_astro": {"bin3729": ratio_bin, "band_peak": ratio_pk},
               "y_limits": {"top": y_top, "bottom": y_bot}}
    Path(str(out) + ".numbers.json").write_text(json.dumps(numbers, indent=1), encoding="utf-8")
    print("wrote", str(out) + ".numbers.json")


if __name__ == "__main__":
    main()
