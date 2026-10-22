#!/usr/bin/env python3
"""Scan every fetched repository and aggregate the population numbers.

    ./census/harvest.sh
    python -m census.select .census/pages .census/candidates.json
    ./census/fetch.sh
    python -m census.census

Two different claims come out of this, and they rest on different evidence:

  * The annotation rate is a census. It needs no human judgement, only a
    parse, so it covers every tool found and is the number to quote.

  * Precision and recall are NOT reported here. They need hand-verified
    ground truth, and ground truth for several hundred repositories does not
    exist. `detector/measure.py` keeps those figures on the small pinned
    corpus where every finding is labelled, and `--sample` here draws a
    random subset of findings to hand-label so precision on the wider
    population can be estimated rather than assumed.

Conflating the two would be the easy mistake: scaling the corpus and then
quoting the old precision figure as if it still described the new population.

Read only. Nothing here imports, installs, executes or connects to anything
it scanned.
"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import random
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from detector.mcp_authz_scan import find_discrepancies, scan_tree  # noqa: E402

HINT_FIELDS = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")


def load_shas(path: pathlib.Path) -> dict[str, str]:
    if not path.exists():
        return {}
    out = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "\t" in line:
            nwo, sha = line.split("\t", 1)
            out[nwo.strip()] = sha.strip()
    return out


def collect(src: pathlib.Path, shas: dict[str, str]) -> dict:
    """Scan every repository directory under `src` and aggregate.

    Separated from main() so the counting can be tested against a fixture tree
    rather than against several hundred repositories off the network.
    """
    repos = sorted(p for p in src.iterdir() if p.is_dir())

    examined = with_python = with_tools = 0
    total_tools = 0
    annotated_tools = 0
    hint_counts: collections.Counter[str] = collections.Counter()
    kinds: collections.Counter[str] = collections.Counter()
    all_findings: list[dict] = []
    per_repo: list[dict] = []

    for repo in repos:
        examined += 1
        nwo = repo.name.replace("__", "/", 1)
        py = [p for p in repo.rglob("*.py")]
        if not py:
            per_repo.append({"repo": nwo, "sha": shas.get(nwo), "py_files": 0,
                             "tools": 0, "annotated": 0, "findings": 0})
            continue
        with_python += 1

        tools = scan_tree(repo)
        if tools:
            with_tools += 1
        findings = find_discrepancies(tools)

        annotated_here = 0
        for t in tools:
            total_tools += 1
            declared = t.declared or {}
            hints = [k for k in HINT_FIELDS if k in declared]
            if hints:
                annotated_tools += 1
                annotated_here += 1
                for k in hints:
                    hint_counts[k] += 1

        for f in findings:
            kinds[f.kind] += 1
            all_findings.append({
                "repo": nwo,
                "sha": shas.get(nwo),
                "tool": f.tool,
                "kind": f.kind,
                "severity": f.severity,
                "file": str(pathlib.Path(f.file).relative_to(repo)).replace("\\", "/"),
                "line": f.line,
                "detail": f.detail,
            })

        per_repo.append({"repo": nwo, "sha": shas.get(nwo), "py_files": len(py),
                         "tools": len(tools), "annotated": annotated_here,
                         "findings": len(findings)})

    rate = (annotated_tools / total_tools) if total_tools else 0.0
    return {
        "population": {"examined": examined, "with_python": with_python,
                       "with_tools": with_tools},
        "census": {"tools": total_tools, "annotated": annotated_tools,
                   "annotation_rate": round(rate, 4),
                   "by_field": dict(hint_counts)},
        "findings": all_findings,
        "by_kind": dict(kinds),
        "repos": per_repo,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--census", type=pathlib.Path, default=pathlib.Path(".census"))
    ap.add_argument("--json-out", type=pathlib.Path)
    ap.add_argument("--sample", type=int, default=0,
                    help="draw N findings at random for hand-labelling")
    ap.add_argument("--seed", type=int, default=20261022,
                    help="fixed so the sample is reproducible")
    args = ap.parse_args()

    src = args.census / "src"
    if not src.is_dir():
        print(f"no {src}. Run census/fetch.sh first", file=sys.stderr)
        return 2

    data = collect(src, load_shas(args.census / "shas.tsv"))
    pop, cen = data["population"], data["census"]
    examined, with_python, with_tools = pop["examined"], pop["with_python"], pop["with_tools"]
    total_tools, annotated_tools = cen["tools"], cen["annotated"]
    rate, hint_counts = cen["annotation_rate"], cen["by_field"]
    all_findings, kinds = data["findings"], collections.Counter(data["by_kind"])

    print("population")
    print(f"  repositories examined       {examined}")
    print(f"  containing python           {with_python}")
    print(f"  with MCP tools detected     {with_tools}")
    print()
    print("census (no human judgement, covers every tool found)")
    print(f"  tools                       {total_tools}")
    print(f"  declaring any annotation    {annotated_tools}")
    print(f"  annotation rate             {rate:.3f}")
    if hint_counts:
        print("  by field")
        for k in HINT_FIELDS:
            if hint_counts.get(k):
                print(f"    {k:<18} {hint_counts[k]}")
    print()
    print("declared-versus-actual contradictions (unlabelled, see docstring)")
    print(f"  findings                    {len(all_findings)}")
    for kind, n in kinds.most_common():
        print(f"    {kind:<26} {n}")

    if args.sample and all_findings:
        n = min(args.sample, len(all_findings))
        picked = random.Random(args.seed).sample(all_findings, n)
        print()
        print(f"--- random sample of {n} findings for hand-labelling "
              f"(seed {args.seed}) ---")
        for f in picked:
            print(f"  {f['kind']:<24} {f['repo']}  {f['file']}:{f['line']}  {f['tool']}")

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(data, indent=1), encoding="utf-8")
        print()
        print(f"wrote {args.json_out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
