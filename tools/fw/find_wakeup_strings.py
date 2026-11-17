from pathlib import Path
import re

BASE = 0x10020000
buf = Path("firmware/decoded/eg1620_038000.bi").read_bytes()

# Search for strings related to S1, half-press, meter, standby, wakeup
patterns = [
    r's1', r'shutter', r'meter', r'standby', r'wakeup', r'resume', r'wake'
]

matches = []
for m in re.finditer(b'[\\x20-\\x7e]{4,}', buf):
    s = m.group().decode('latin1')
    low = s.lower()
    if any(p in low for p in ['standby', 'wakeup', 'resume', 'meteron', 'meter_on', 'halfpress', 's1on', 's1_on']):
        matches.append((BASE + m.start(), s))

print(f"Found {len(matches)} matches:")
for addr, s in matches[:40]:
    print(f"0x{addr:08x}: {s}")
