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
# Resume from the newest page that actually carries a cursor, discarding any
# trailing empty ones. A sweep that stopped on a spurious empty page leaves it
# on disk; resuming from that page's (absent) cursor would conclude the
# harvest was finished and exit 0 again, which is how the truncated sweep
# stayed truncated.
cursor=""
page=0
while :; do
  last=$(ls "$PAGES"/p*.json 2>/dev/null | tail -1)
  [ -n "$last" ] || break
  cursor=$(python "$HERE/pageinfo.py" "$last" | cut -f2 | tr -d '\r')
  if [ -n "$cursor" ]; then
    page=$(ls "$PAGES"/p*.json | wc -l)
    echo "resuming after page $page, cursor $cursor" >&2
    break
  fi
  echo "discarding trailing page with no cursor: $(basename "$last")" >&2
  rm -f "$last"
done

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
  # Retry only a FAILED fetch, meaning a dead connection or a malformed body
  # (pageinfo exit 1). Exit 3 is a successfully fetched page that merely looks
  # like the end, and it has to reach the confirmation step below rather than
  # be retried as a failure: the registry's genuine last page carries rows and
  # no cursor, so treating exit 3 as a failed fetch discards the final page
  # and gives up three attempts later.
  ok=0
  verdict=1
  for attempt in 1 2 3; do
    if curl -s --max-time 45 "$url" -o "$f"; then
      python "$HERE/pageinfo.py" "$f" >/dev/null 2>&1
      verdict=$?
      if [ "$verdict" -eq 0 ] || [ "$verdict" -eq 3 ]; then
        ok=1
        break
      fi
    fi
    sleep $((attempt * 3))
  done
  if [ "$ok" -eq 0 ]; then
    echo "gave up on page $page after 3 attempts; rerun to resume" >&2
    rm -f "$f"
    break
  fi

  # An empty page is NOT accepted as the end of the registry on one answer.
  # The API intermittently returns zero servers and no cursor for a cursor
  # that works perfectly on the next attempt; believing it once truncated a
  # sweep to a fifth of the data and exited 0. Ask again, several times, and
  # only believe it if the answer keeps coming back empty.
  if [ "$verdict" -eq 3 ]; then
    confirmed=1
    for confirm in 1 2 3 4; do
      sleep $((confirm * 2))
      if curl -s --max-time 45 "$url" -o "$f.recheck" \
         && python "$HERE/pageinfo.py" "$f.recheck" >/dev/null 2>&1; then
        # Non-empty on a retry: the empty answer was a glitch. Take this one.
        mv "$f.recheck" "$f"
        confirmed=0
        echo "  page $page came back empty, retry $confirm returned data" >&2
        break
      fi
      rm -f "$f.recheck"
    done
    if [ "$confirmed" -eq 1 ]; then
      info=$(python "$HERE/pageinfo.py" "$f")
      n=$(printf '%s' "$info" | cut -f1 | tr -d '\r')
      total=$((total + n))
      echo "end of registry confirmed at page $page after 4 rechecks" >&2
      break
    fi
  fi

  info=$(python "$HERE/pageinfo.py" "$f")
  n=$(printf '%s' "$info" | cut -f1 | tr -d '\r')
  cursor=$(printf '%s' "$info" | cut -f2 | tr -d '\r')

  total=$((total + n))
  [ $((page % 20)) -eq 0 ] && echo "  page $page  (+$total this run)" >&2

  if [ -z "$cursor" ] || [ "$n" -eq 0 ]; then
    echo "end of registry at page $page" >&2
    break
  fi
  if [ "$page" -ge "$MAX_PAGES" ]; then
    echo "stopped at MAX_PAGES=$MAX_PAGES; rerun to continue" >&2
    break
  fi
done

echo "pages on disk: $(ls "$PAGES"/p*.json 2>/dev/null | wc -l)" >&2
