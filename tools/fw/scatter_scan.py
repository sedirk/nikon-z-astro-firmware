"""Heuristic scan of the Z6 MAIN (EG) image for ARM scatter-load style region tables.

Read-only, stdlib only. An RVCT/armlink region table is a run of 16-byte records
(load_address, execution_address, length, handler) whose handler is one of a few
copy/zero/decompress routines inside the image. This script reports every run of
at least --min-run such records where the handler repeats, so a human can confirm
the real table by disassembling its user. Output is evidence for review, not a
confirmed memory map.

Usage: python3 -I scatter_scan.py <eg1620_038000.bi> [--base 0x10020000]
"""
import argparse
import hashlib
import json
import struct
import sys

EXPECTED_SHA256 = '1e6348d58750e67372d0a8e363932c57ee9c04d0eb8f62803bcd19812df0d25c'


def main():
    p = argparse.ArgumentParser()
    p.add_argument('image')
    p.add_argument('--base', type=lambda v: int(v, 0), default=0x10020000)
    p.add_argument('--min-run', type=int, default=3)
    a = p.parse_args()
    data = open(a.image, 'rb').read()
    sha = hashlib.sha256(data).hexdigest()
    if sha != EXPECTED_SHA256:
        sys.exit(f'unexpected input hash {sha}')
    base, end = a.base, a.base + len(data)
    words = struct.unpack_from('<%dI' % (len(data) // 4), data)

    def in_image(v):
        return base <= v < end

    def record_ok(i):
        load, exe, size, handler = words[i:i + 4]
        return (in_image(handler & ~1) and size < 0x20000000 and
                (in_image(load) or load == 0) and exe >= 0x10000000)

    runs = []
    i = 0
    n = len(words) - 4
    while i < n:
        if record_ok(i):
            j = i
            handlers = set()
            while j < n and record_ok(j):
                handlers.add(words[j + 3])
                j += 4
            count = (j - i) // 4
            if count >= a.min_run and len(handlers) <= 4:
                recs = []
                for k in range(i, j, 4):
                    load, exe, size, handler = words[k:k + 4]
                    recs.append(dict(load=f'{load:#010x}', load_off=f'{load - base:#x}' if load else None,
                                     exec=f'{exe:#010x}', size=f'{size:#x}', handler=f'{handler:#010x}'))
                runs.append(dict(table_va=f'{base + i * 4:#010x}', table_off=f'{i * 4:#x}',
                                 records=count, handlers=sorted(f'{h:#010x}' for h in handlers),
                                 entries=recs))
            i = j if j > i else i + 1
        else:
            i += 1
    print(json.dumps(dict(image=a.image, sha256=sha, base=f'{base:#x}', length=len(data),
                          candidate_tables=runs), indent=1))


if __name__ == '__main__':
    main()
