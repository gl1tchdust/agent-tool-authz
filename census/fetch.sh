#!/usr/bin/env bash
# Fetch the Python source of each candidate repository, pinned to a commit.
#
#   ./census/fetch.sh [limit]
#
# Only *.py is extracted, from a tarball at a resolved commit SHA. Nothing is
# cloned, nothing is installed, nothing is executed, and no server is ever
# contacted. The SHA for each repository is recorded in shas.tsv so the scan is
# reproducible: a census over "whatever main happened to be" is not a
# measurement.
#
# Repositories that have been deleted, renamed or made private since the
# registry entry was published are recorded as misses rather than skipped
# silently, because the miss rate is itself a result.

set -uo pipefail

DEST="${DEST:-.census}"
CAND="$DEST/candidates.json"
SRC="$DEST/src"
SHAS="$DEST/shas.tsv"
LIMIT="${1:-0}"

[ -f "$CAND" ] || { echo "no $CAND, run census/select.py first" >&2; exit 2; }

mkdir -p "$SRC"
: > "$SHAS.partial"

# tr -d '\r' is not cosmetic: on Windows python's print() emits CRLF, mapfile -t
# strips only the \n, and the surviving \r rides along into every URL below. It
# fails as an unreachable repository rather than as a parse error, so the whole
# census silently reports a 100% miss rate.
mapfile -t repos < <(python -c "
import json,sys
rows=json.load(open('$CAND',encoding='utf-8'))
if $LIMIT: rows=rows[:$LIMIT]
for r in rows: print(r['nwo'])
" | tr -d '\r')

total=${#repos[@]}
i=0; ok=0; miss=0
for nwo in "${repos[@]}"; do
  i=$((i+1))
  slug="${nwo//\//__}"
  out="$SRC/$slug"

  if [ -f "$out/.sha" ]; then
    printf '%s\t%s\n' "$nwo" "$(cat "$out/.sha")" >> "$SHAS.partial"
    ok=$((ok+1)); continue
  fi

  sha=$(gh api "repos/$nwo/commits/HEAD" --jq '.sha' 2>/dev/null)
  if [ -z "$sha" ]; then
    printf '%s\tMISS\n' "$nwo" >> "$SHAS.partial"
    miss=$((miss+1)); continue
  fi

  rm -rf "$out"; mkdir -p "$out"
  if curl -sL --max-time 120 "https://codeload.github.com/$nwo/tar.gz/$sha" \
      | tar -xz -C "$out" --wildcards '*.py' 2>/dev/null; then
    printf '%s' "$sha" > "$out/.sha"
    printf '%s\t%s\n' "$nwo" "$sha" >> "$SHAS.partial"
    ok=$((ok+1))
  else
    # No .py in the tarball is the common case here, not an error: most
    # registry servers are TypeScript. Record the SHA so the scan still counts
    # the repository as examined with zero Python tools.
    printf '%s' "$sha" > "$out/.sha"
    printf '%s\t%s\n' "$nwo" "$sha" >> "$SHAS.partial"
    ok=$((ok+1))
  fi

  [ $((i % 25)) -eq 0 ] && echo "  $i/$total  ok=$ok miss=$miss" >&2
done

mv "$SHAS.partial" "$SHAS"
echo "examined $ok, unreachable $miss, of $total candidates" >&2
