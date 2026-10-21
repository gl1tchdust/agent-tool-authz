#!/usr/bin/env bash
# Fetch the MCP servers the detector is scored against.
#
#   ./detector/fetch_corpus.sh
#   python -m detector.measure
#
# Pinned to commits. The accuracy figures in the README and the labels in
# detector/labels/mcp-corpus.yml describe these exact trees; a moving corpus
# would make both unverifiable, and "precision 0.8" against an unspecified
# version of someone else's repository is not a measurement.
#
# Fetched at run time, never vendored. All three are permissively licensed
# (MIT, MIT, Apache-2.0) but they are other people's code and this repository
# should not carry it.
#
# Read only. Nothing here runs, imports or connects to anything it clones.

set -euo pipefail

DEST="${DEST:-.corpus}"

# name|repo|commit|scan path
TARGETS=(
  "mcp-servers|https://github.com/modelcontextprotocol/servers.git|51b6382a3e827aceb6bce430b1208d69b93d95ea|src"
  "python-sdk|https://github.com/modelcontextprotocol/python-sdk.git|2af9e30|examples"
  "fastmcp|https://github.com/PrefectHQ/fastmcp.git|d922769|examples"
)

mkdir -p "$DEST"

for entry in "${TARGETS[@]}"; do
  IFS='|' read -r name repo commit _ <<< "$entry"
  target="$DEST/$name"

  if [ -d "$target/.git" ]; then
    echo "  $name: already present"
  else
    echo "  $name: cloning"
    git clone --quiet "$repo" "$target"
  fi

  git -C "$target" fetch --quiet origin "$commit" 2>/dev/null || git -C "$target" fetch --quiet origin
  git -C "$target" checkout --quiet "$commit"
  echo "  $name: pinned at $(git -C "$target" rev-parse --short HEAD)"
done

echo
echo "corpus ready in $DEST. Score it with: python -m detector.measure"
