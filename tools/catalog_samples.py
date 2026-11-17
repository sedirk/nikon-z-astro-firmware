import pathlib
import json

root = pathlib.Path(__file__).resolve().parents[1]
samples_dir = root / 'samples'

catalog = {}
total_files = 0
total_bytes = 0

for d in sorted(samples_dir.iterdir()):
    if d.is_dir():
        files = sorted(d.glob('*'))
        f_list = []
        d_bytes = 0
        for f in files:
            if f.is_file():
                sz = f.stat().st_size
                d_bytes += sz
                total_bytes += sz
                total_files += 1
                f_list.append({
                    "name": f.name,
                    "size_bytes": sz,
                })
        catalog[d.name] = {
            "file_count": len(f_list),
            "total_bytes": d_bytes,
            "total_mb": round(d_bytes / (1024 * 1024), 2),
            "files": f_list
        }

out_json = root / 'docs/SAMPLE_EVIDENCE_CATALOG.json'
out_json.write_text(json.dumps({
    "description": "Historical audit sample catalog and hardware verification evidence across all Modified versions (M1~M22)",
    "summary": {
        "total_folders": len(catalog),
        "total_files": total_files,
        "total_megabytes": round(total_bytes / (1024 * 1024), 2),
    },
    "folders": catalog
}, indent=2), encoding='utf-8')

print(f"Catalog created: {out_json} | {total_files} files across {len(catalog)} folders ({total_bytes / (1024*1024):.1f} MB)")
