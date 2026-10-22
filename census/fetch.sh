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
i=0; ok=0; miss=0; err=0
for nwo in "${repos[@]}"; do
  i=$((i+1))
  slug="${nwo//\//__}"
  out="$SRC/$slug"

  if [ -f "$out/.sha" ]; then
    printf '%s\t%s\n' "$nwo" "$(cat "$out/.sha")" >> "$SHAS.partial"
    ok=$((ok+1)); continue
  fi

  # Resolve the commit, distinguishing three outcomes that must never be
  # collapsed into one:
  #
  #   sha    the repository is there
  #   MISS   GitHub says Not Found, so it is genuinely gone or private
  #   ERROR  we could not tell, usually a secondary rate limit
  #
  # The first version of this recorded every failure as MISS. GitHub throttles
  # rapid sequential requests, so a bulk run reported 367 of 962 repositories
  # as deleted. Spot-checking six of them found five alive: the "38% of
  # registry entries are dead" result was entirely an artefact of my own
  # request rate. An unresolved repository has to stay visibly unresolved,
  # because a miss silently inflates the denominator of every rate computed
  # from this corpus.
  sha=""; verdict="ERROR"
  for attempt in 1 2 3 4 5; do
    resp=$(gh api "repos/$nwo/commits/HEAD" --jq '.sha' 2>&1)
    if [ -n "$resp" ] && [ "${resp:0:1}" != "{" ] && ! printf '%s' "$resp" | grep -qi 'message\|error'; then
      sha="$resp"; verdict="OK"; break
    fi
    if printf '%s' "$resp" | grep -qi 'not found'; then
      verdict="MISS"; break
    fi
    # Anything else (403, 429, abuse detection, transport) is retryable.
    sleep $((attempt * attempt * 2))
  done

  if [ "$verdict" != "OK" ]; then
    printf '%s\t%s\n' "$nwo" "$verdict" >> "$SHAS.partial"
    if [ "$verdict" = "MISS" ]; then miss=$((miss+1)); else err=$((err+1)); fi
    continue
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

  # A small pause keeps the request rate under GitHub's secondary limit,
  # which is cheaper than retrying past it.
  sleep 0.2

  [ $((i % 25)) -eq 0 ] && echo "  $i/$total  ok=$ok miss=$miss err=$err" >&2
done

mv "$SHAS.partial" "$SHAS"
echo "examined $ok, gone $miss, unresolved $err, of $total candidates" >&2
[ "$err" -gt 0 ] && echo "WARNING: $err repositories unresolved; rerun to retry them" >&2
