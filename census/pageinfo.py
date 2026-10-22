#!/usr/bin/env python3
"""Classify one harvested registry page for harvest.sh.

Prints "<count>\t<nextCursor>" and exits:

    0   the page carries servers                  -> keep paging
    3   the page is empty, or carries no cursor   -> SUSPICIOUS, confirm first
    1   the page could not be read or parsed      -> retry the fetch

Exit 3 exists because of a bug that cost most of a sweep. The registry
intermittently answers a perfectly valid cursor with zero servers and no
nextCursor. That response is indistinguishable in shape from the real end of
the registry, so the harvest concluded it was done and stopped at `com.m*`,
having collected about a fifth of the data and reported success.

Retrying the identical cursor returned 100 servers every time.

So an empty page is never allowed to mean "finished" on its own evidence. The
caller has to ask again and get the same answer repeatedly before believing
it. Reading UTF-8 explicitly matters for the same reason: on Windows the
platform default is cp1252, one em dash in a server description raised
UnicodeDecodeError, and that too was read as the end of the data.
"""

from __future__ import annotations

import json
import pathlib
import sys

EXIT_OK = 0
EXIT_PARSE = 1
EXIT_SUSPICIOUS_END = 3


def main() -> int:
    if len(sys.argv) != 2:
        print("ERR\tusage: pageinfo.py <page.json>")
        return EXIT_PARSE

    try:
        raw = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
        page = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        print(f"ERR\t{exc}")
        return EXIT_PARSE

    if not isinstance(page, dict):
        print(f"ERR\texpected a JSON object, got {type(page).__name__}")
        return EXIT_PARSE

    servers = page.get("servers")
    if not isinstance(servers, list):
        print("ERR\tno servers array")
        return EXIT_PARSE

    cursor = (page.get("metadata") or {}).get("nextCursor") or ""
    print(f"{len(servers)}\t{cursor}")

    if not servers or not cursor:
        return EXIT_SUSPICIOUS_END
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
