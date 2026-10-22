"""Print "<count>\t<nextCursor>" for a harvested registry page. UTF-8 always."""
import json, pathlib, sys

try:
    d = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
except Exception as e:                      # noqa: BLE001 - any parse failure is fatal here
    print(f"ERR\t{e}")
    raise SystemExit(1)

print(f"{len(d.get('servers', []))}\t{d.get('metadata', {}).get('nextCursor') or ''}")
