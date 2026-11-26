#!/bin/sh
# P09 release signing and verification (OpenSSH SSHSIG, Ed25519). This is
# the same tool and format the operator key uses (docs/operator/05-OPERATOR-KEY.md),
# but with its own namespace, rustiron-release-v1. The executor accepts only
# rustiron-plan-v1, so a release signature can never approve a plan, and a plan
# signature can never pass as a release signature.
#   release_sig.sh manifest DIR             write DIR/SHA256SUMS over every other file in DIR
#   release_sig.sh sign DIR KEY             sign DIR/SHA256SUMS -> DIR/SHA256SUMS.sig
#   release_sig.sh verify DIR ALLOWED ID    check file inventory/hashes and signature
#                                           (exit 0 = verified, 1 = rejected)
# DIR must be a private staging directory with no concurrent writers.
# Only single-link regular artifacts and real directories are supported.
set -eu
NS=rustiron-release-v1
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cmd=${1:?manifest|sign|verify}; DIR=${2:?DIR}
case $cmd in
manifest)
  python3 "$HERE/release_manifest.py" manifest "$DIR" ;;
sign)
  python3 "$HERE/release_manifest.py" check "$DIR"
  ssh-keygen -q -Y sign -n "$NS" -f "${3:?KEY}" "$DIR/SHA256SUMS" ;;
verify)
  ALLOWED=${3:?ALLOWED_SIGNERS}; ID=${4:?SIGNER_ID}
  python3 "$HERE/release_manifest.py" check "$DIR"
  ssh-keygen -Y verify -n "$NS" -f "$ALLOWED" -I "$ID" -s "$DIR/SHA256SUMS.sig" < "$DIR/SHA256SUMS" >/dev/null 2>&1 \
    || { echo "REJECTED: signature"; exit 1; }
  echo VERIFIED ;;
*) echo "unknown command" >&2; exit 2 ;;
esac
