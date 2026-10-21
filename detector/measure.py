#!/usr/bin/env python3
"""Score the detector against the hand-labelled corpus.

    ./detector/fetch_corpus.sh
    python -m detector.measure

Re-derives the precision and recall quoted in the README by scanning the
pinned corpus and comparing what the scanner reports to what a human decided
after reading the source. The labels live in `labels/mcp-corpus.yml` so the
numbers can be disputed rather than taken on trust.

A finding the labels do not mention is counted against precision, not ignored.
That is the direction that matters: a scanner whose new findings are silently
excused is a scanner whose score stops meaning anything.

Exit codes:
    0  the scan matches the labels
    1  it does not, so either the scanner changed or the labels are stale
    2  the corpus is missing
"""

from __future__ import annotations

import argparse
import pathlib
import sys

import yaml

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from detector.mcp_authz_scan import find_discrepancies, scan_tree  # noqa: E402

HERE = pathlib.Path(__file__).resolve().parent
LABELS = HERE / "labels" / "mcp-corpus.yml"

# Where each labelled corpus entry lives once fetch_corpus.sh has run.
CORPUS_PATHS = {
    "modelcontextprotocol/servers (git)": "mcp-servers/src/git",
    "modelcontextprotocol/servers (fetch)": "mcp-servers/src/fetch",
    "modelcontextprotocol/python-sdk": "python-sdk/examples",
    "PrefectHQ/fastmcp": "fastmcp/examples",
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", type=pathlib.Path, default=pathlib.Path(".corpus"))
    ap.add_argument("--strict", action="store_true",
                    help="fail if the scan no longer matches the labels")
    args = ap.parse_args()

    if not args.corpus.is_dir():
        print(f"corpus not found at {args.corpus}. Run ./detector/fetch_corpus.sh",
              file=sys.stderr)
        return 2

    labels = yaml.safe_load(LABELS.read_text(encoding="utf-8"))
    verdicts = {(f["tool"], f["kind"]): f["verdict"] for f in labels["findings"]}
    expected = labels["accuracy"]

    total_tools = 0
    observed: list[tuple[str, str]] = []

    print("corpus")
    for entry in labels["corpus"]:
        rel = CORPUS_PATHS.get(entry["name"])
        if rel is None:
            print(f"  {entry['name']:<40} no path mapping", file=sys.stderr)
            return 2
        path = args.corpus / rel
        if not path.exists():
            print(f"  {entry['name']:<40} MISSING at {path}", file=sys.stderr)
            return 2

        tools = scan_tree(path)
        findings = find_discrepancies(tools)
        total_tools += len(tools)
        observed.extend((f.tool, f.kind) for f in findings)
        print(f"  {entry['name']:<40} {len(tools):>4} tools  {len(findings)} finding(s)")

    tp = sum(1 for key in observed if verdicts.get(key) == "true_positive")
    fp = sum(1 for key in observed if verdicts.get(key) == "false_positive")
    unlabelled = [key for key in observed if key not in verdicts]
    misses = len(labels["known_misses"])

    # An unlabelled finding counts against precision until somebody reads it.
    fp += len(unlabelled)

    precision = round(tp / (tp + fp), 3) if (tp + fp) else 0.0
    recall = round(tp / (tp + misses), 3) if (tp + misses) else 0.0

    print()
    print(f"tools scanned     {total_tools}")
    print(f"findings          {len(observed)}")
    print(f"  true positives  {tp}")
    print(f"  false positives {fp}")
    print(f"known misses      {misses}")
    print()
    print(f"precision         {precision:.3f}   (labelled: {expected['precision']})")
    print(f"recall            {recall:.3f}   (labelled: {expected['recall']})")

    if unlabelled:
        print()
        print("--- findings with no label, counted against precision ---")
        for tool, kind in unlabelled:
            print(f"  {kind:<24} {tool}")
        print("  Read each, then add it to labels/mcp-corpus.yml with a verdict.")

    drifted = (
        total_tools != labels["total_tools"]
        or precision != expected["precision"]
        or recall != expected["recall"]
    )
    if drifted:
        print()
        print("::warning::the scan no longer matches the labels")
        if args.strict:
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
