#!/bin/sh
# Synthetic signature/tamper tests; optional ARTIFACTS tree is never modified.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$HERE/release_sig_test.py" "$@"
