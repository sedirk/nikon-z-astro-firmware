"""Record the local model's pixel dependencies, without running or modifying it."""
from pathlib import Path
import argparse
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT/'work/src/z6-qemu-419a1f2a91a1f2d3a0209027c29606475f7fe26f/qemu'
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
assert not a.output.exists()
names = ('nikon-z6.c', 'nikon-functional-isp.h', 'nikon-isp-pixels.h', 'nikon-z6-profile.h')
sources = {name: (SRC/name).read_text(encoding='utf-8') for name in names}
hashes = {str((SRC/name).relative_to(ROOT)): hashlib.sha256((SRC/name).read_bytes()).hexdigest()
          for name in names}
assert hashes[str((SRC/'nikon-z6.c').relative_to(ROOT))] == '9a92f19510f6730312158079cea39717826648da0d245d766ed39ce412e9091c'
references = []
for path in sorted(SRC.iterdir()):
    if path.suffix not in ('.c', '.h'):
        continue
    for number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
        if 'image_processor_config' in line:
            references.append(dict(file=path.name, line=number, text=line))

def excerpt(name, lo, hi):
    return dict(file=name, first_line=lo, last_line=hi,
                lines=sources[name].splitlines()[lo-1:hi])

candidate_pattern = re.compile(r'\b0x(?:710|714|720|1200|1224)\b', re.I)
hits = {name: [dict(line=n, text=line)
               for n, line in enumerate(sources[name].splitlines(), 1)
               if candidate_pattern.search(line)]
        for name in ('nikon-functional-isp.h', 'nikon-isp-pixels.h')}
assert not any(hits.values())
report = dict(scope=__doc__, source_hashes=hashes, array_references=references,
              candidate_literal_hits_in_pixel_implementation=hits,
              excerpts=[excerpt('nikon-z6.c', 1721, 1765),
                        excerpt('nikon-functional-isp.h', 1, 146),
                        excerpt('nikon-isp-pixels.h', 1, 110)],
              source_review=[
                  'MMIO handler stores the configuration words; it is not a correction algorithm.',
                  'The opt-in regular transaction reads bank0 RAW input and writes NV12 hypotheses via transfer channels 3..5.',
                  'The bank+3ec write in this implementation belongs to a 448-byte in-place dummy/drain copy, not a still NEF raster.',
                  'nikon_isp_images_input receives geometry/raw bytes; the candidate parameter words or tables are not passed to it.',
                  'Tone conversion uses geometry black_level/white_level and synthetic RGB/NV12 assumptions, not the recovered candidate registers.',
                  'No inference about camera pixel invariance follows from a model that lacks these dependencies.'
              ],
              limitations=['Local pinned source audit, not an upstream survey or hardware specification.',
                           'Literal search alone does not establish absence; the accompanying dependency and write-path source review is required.',
                           'No QEMU run, no model change, no newly implemented pixel algorithm.'])
a.output.write_text(json.dumps(report, indent=2), encoding='utf-8')
print(json.dumps(dict(sources=len(hashes), array_references=len(references), candidate_hits=hits)))
