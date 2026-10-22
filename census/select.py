"""Registry pages -> candidate GitHub repositories, deduped.

Keeps only the current, active record for each server (isLatest + active), since
the registry stores every published version and counting versions would inflate
the population. Emits one row per distinct GitHub repository.
"""
import json, pathlib, re, sys

OFFICIAL = "io.modelcontextprotocol.registry/official"
GH = re.compile(r"^https?://github\.com/([^/]+)/([^/#?]+?)(?:\.git)?/?$", re.I)

records = []
for p in sorted(pathlib.Path(sys.argv[1]).glob("p*.json")):
    try:
        records.extend(json.loads(p.read_text(encoding="utf-8")).get("servers", []))
    except Exception:
        continue

seen: dict[str, dict] = {}
for r in records:
    meta = r.get("_meta", {}).get(OFFICIAL, {})
    if not meta.get("isLatest") or meta.get("status") != "active":
        continue
    s = r.get("server", {})
    url = ((s.get("repository") or {}).get("url") or "").strip()
    m = GH.match(url)
    if not m:
        continue
    owner, repo = m.group(1), m.group(2)
    key = f"{owner}/{repo}".lower()
    # One row per repository. Several registry entries can share a monorepo.
    entry = seen.setdefault(key, {"owner": owner, "repo": repo, "nwo": f"{owner}/{repo}",
                                  "servers": [], "subfolder": None})
    entry["servers"].append(s.get("name"))
    sub = (s.get("repository") or {}).get("subfolder")
    if sub and not entry["subfolder"]:
        entry["subfolder"] = sub

rows = sorted(seen.values(), key=lambda e: e["nwo"].lower())
pathlib.Path(sys.argv[2]).write_text(json.dumps(rows, indent=1), encoding="utf-8")
print(f"records            {len(records)}")
print(f"distinct repos     {len(rows)}")
print(f"  with subfolder   {sum(1 for r in rows if r['subfolder'])}")
print(f"servers covered    {sum(len(r['servers']) for r in rows)}")
