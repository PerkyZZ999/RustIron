#!/bin/sh
# P09 same-host reproducibility: two pinned Rust builds, each with its own
# independently compiled SQLite. OUTDIR must not exist. No files are deleted.
#   systemd-run --user --wait --pipe -p MemoryMax=8G -p MemorySwapMax=0 \
#     --working-directory=$PWD $PWD/scripts/release/repro_build.sh OUTDIR
# Exit 0 = complete inventories match, 1 = differs, 2 = build/input error.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$HERE/repro_build.py" build "${1:?OUTDIR}"
