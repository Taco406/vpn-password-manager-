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

# 3) LOG HYGIENE — no log statement in a secret-handling module may interpolate a variable
#    whose name says it holds a secret. Logs are written to disk (applog.rs), mirrored to
#    stderr, and the user is invited to copy them from Settings, so a single `{password}` in a
#    format string exports the vault. This is a NAME-based check: it can't prove a value is
#    safe, but it stops the obvious class (println!("... {token}")) from ever landing.
secret_ident='password|passphrase|master_pw|[a-z_]*secret|[a-z_]*token|priv(ate)?_?key|vault_key|kek|proof|verifier|totp_secret|api_key'
log_macro='println!|eprintln!|dbg!|tracing::(trace|debug|info|warn|error)!|log::(trace|debug|info|warn|error)!|applog::(info|warn|error)'
if git grep -nI -E "($log_macro)[^;]*\{($secret_ident)[:}]" -- \
     'crates/core/src' 'apps/desktop/src-tauri/src' 'crates/nm-host/src' 'services/api/src' \
     ':!*/tests/*' ':!scripts/plaintext-audit.sh' 2>/dev/null; then
  note "FAIL: a log statement interpolates a secret-named variable"; fail=1
fi

# 4) TLS VERIFICATION SCOPE — accepting invalid certificates is allowed in exactly two places
#    (the self-signed Netdata agent, and the pre-trust TOFU probe that sends nothing). Any new
#    occurrence is a finding: it would silently un-verify a channel that carries credentials.
allowed_tls=2
found_tls=$(git grep -cI -E 'danger_accept_invalid_certs' -- \
    'crates' 'apps/desktop/src-tauri/src' 'services' 2>/dev/null | awk -F: '{s+=$2} END {print s+0}')
if [ "$found_tls" -gt "$allowed_tls" ]; then
  note "FAIL: $found_tls danger_accept_invalid_certs sites (expected $allowed_tls)"
  git grep -nI -E 'danger_accept_invalid_certs' -- 'crates' 'apps/desktop/src-tauri/src' 'services'
  note "  If a new one is genuinely needed, justify it in docs/security-review-*.md and raise the count."
  fail=1
fi

if [ "$fail" -eq 0 ]; then
  note "OK — no committed secrets, no plaintext in vault artifacts."
fi
exit "$fail"
