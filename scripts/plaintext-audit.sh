#!/usr/bin/env bash
# plaintext-audit.sh — fails if anything that looks like a real secret is committed
# to the repo, or if a built vault file / app-data dump contains recognizable
# plaintext from the seeded demo data. Part of the SECURITY.md T1/T2 gate.
set -uo pipefail
cd "$(dirname "$0")/.."

fail=0
note() { echo "PLAINTEXT-AUDIT: $*"; }

# 1) No private keys or obvious credential material committed (excluding fixtures,
#    docs, and this script). .env must never be committed (only .env.example).
if git ls-files 2>/dev/null | grep -E '(^|/)\.env$' ; then
  note "FAIL: a .env file is tracked by git"; fail=1
fi

# Private-key PEM headers anywhere in tracked, non-doc files.
if git grep -nI -e '-----BEGIN [A-Z ]*PRIVATE KEY-----' -- \
     ':!*.md' ':!scripts/plaintext-audit.sh' 2>/dev/null; then
  note "FAIL: a private key is committed"; fail=1
fi

# Real-looking Linode PATs / Google client secrets hardcoded in source.
if git grep -nI -E '(GOCSPX-[A-Za-z0-9_-]{20,}|linode_[A-Za-z0-9]{40,})' -- \
     ':!*.md' ':!.env.example' 2>/dev/null; then
  note "FAIL: a hardcoded provider secret is committed"; fail=1
fi

# 2) If a demo vault artifact exists, it must be opaque — no seeded plaintext.
#    (Seeded canary strings that only ever live *inside* an item's plaintext.)
canaries=("hunter2-reused" "Tr0ub4dour-canary" "sentinel-demo-note-body")
for f in $(find . -name 'vault.db' -o -name '*.vault' 2>/dev/null); do
  for c in "${canaries[@]}"; do
    if grep -aqF "$c" "$f"; then
      note "FAIL: plaintext canary '$c' found in $f"; fail=1
    fi
  done
done

if [ "$fail" -eq 0 ]; then
  note "OK — no committed secrets, no plaintext in vault artifacts."
fi
exit "$fail"
