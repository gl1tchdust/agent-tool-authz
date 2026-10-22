#!/usr/bin/env bash
# Page the official MCP registry to disk.
#
#   ./census/harvest.sh            # start, or resume where it stopped
#
# The registry is the sampling frame for the census: a defined population
# published by the people who define the protocol, rather than whatever a
# GitHub code search happened to return. It is paged with a cursor and stores
# every version of every server, so `select.py` reduces it to one current
# record per server afterwards.
#
# Resumable on purpose. The registry is large and a single network blip used to
# end the run early, which looked exactly like reaching the end of the data.
#
# Read only: this talks to the registry's HTTP API and nothing else. No server
# listed in it is ever contacted.

set -uo pipefail

DEST="${DEST:-.census}"
PAGES="$DEST/pages"
LIMIT_PER_PAGE=100
MAX_PAGES="${MAX_PAGES:-2000}"

mkdir -p "$PAGES"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Resume from the last page already on disk rather than refetching it all.
page=$(ls "$PAGES"/p*.json 2>/dev/null | wc -l)
cursor=""
if [ "$page" -gt 0 ]; then
  last=$(ls "$PAGES"/p*.json | tail -1)
  cursor=$(python "$HERE/pageinfo.py" "$last" | cut -f2)
  echo "resuming after page $page, cursor ${cursor:-<none>}" >&2
  if [ -z "$cursor" ]; then
    echo "last page carries no cursor: harvest already complete" >&2
    exit 0
  fi
fi

total=0
while :; do
  page=$((page + 1))
  f="$PAGES/p$(printf '%04d' "$page").json"

  url="https://registry.modelcontextprotocol.io/v0/servers?limit=$LIMIT_PER_PAGE"
  if [ -n "$cursor" ]; then
    # The cursor contains ':' and '/', so it has to be percent-encoded.
    enc=$(python -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$cursor" | tr -d '\r')
    url="$url&cursor=$enc"
  fi

  # Retry: a transient timeout must not be mistaken for the end of the data.
  ok=0
  for attempt in 1 2 3; do
    if curl -s --max-time 45 "$url" -o "$f" \
       && python "$HERE/pageinfo.py" "$f" >/dev/null 2>&1; then
      ok=1
      break
    fi
    sleep $((attempt * 3))
  done
  if [ "$ok" -eq 0 ]; then
    echo "gave up on page $page after 3 attempts; rerun to resume" >&2
    rm -f "$f"
    break
  fi

  info=$(python "$HERE/pageinfo.py" "$f")
  n=$(printf '%s' "$info" | cut -f1 | tr -d '\r')
  cursor=$(printf '%s' "$info" | cut -f2 | tr -d '\r')

  total=$((total + n))
  [ $((page % 20)) -eq 0 ] && echo "  page $page  (+$total this run)" >&2

  if [ -z "$cursor" ] || [ "$n" -eq 0 ]; then
    echo "reached the end of the registry" >&2
    break
  fi
  if [ "$page" -ge "$MAX_PAGES" ]; then
    echo "stopped at MAX_PAGES=$MAX_PAGES; rerun to continue" >&2
    break
  fi
done

echo "pages on disk: $(ls "$PAGES"/p*.json 2>/dev/null | wc -l)" >&2
