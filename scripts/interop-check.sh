#!/usr/bin/env bash
# Cross-component interop guards. The desktop (Rust), the sync server (Rust), and the iPhone
# (Swift) share byte-level formats and wire contracts that no compiler checks across the
# language boundary — these assertions are the tripwire. Run by `just ios-docs-check` and CI.
#
# If one of these fails, DO NOT delete or loosen the check: it means a change on one side of a
# desktop↔phone or app↔server contract didn't land on the other side. Fix the other side (see
# CLAUDE.md "Cross-component contracts").
set -euo pipefail
cd "$(dirname "$0")/.."

fail() { echo "INTEROP CHECK FAILED: $*" >&2; exit 1; }

SWIFT_CRYPTO=apps/ios-key/NorthKey/Crypto/VaultCrypto.swift
SWIFT_CHANNEL=apps/ios-key/NorthKey/Crypto/Channel.swift
SWIFT_API=apps/ios-key/NorthKey/Api/ApiClient.swift
SWIFT_SCAN=apps/ios-key/NorthKey/Onboarding/ScanSetupView.swift
RUST_KDF=crates/core/src/crypto/kdf.rs
RUST_SYNC=apps/desktop/src-tauri/src/sync.rs
API_ROUTES=services/api/src/routes.rs

# 1. HKDF info strings are protocol constants — identical on both platforms, never rebranded.
for s in 'sentinel/v1/pair/chan/desktop->phone' 'sentinel/v1/pair/chan/phone->desktop'; do
    grep -qF "$s" "$SWIFT_CHANNEL" || fail "$s missing from $SWIFT_CHANNEL"
    grep -qF "$s" "$RUST_KDF" || fail "$s missing from $RUST_KDF"
done
for s in 'sentinel/v1/vault/outer' 'sentinel/v1/vault/item' 'sentinel/v1/auth/login' 'sentinel/v1/file/blob'; do
    grep -qF "$s" "$SWIFT_CRYPTO" || fail "$s missing from $SWIFT_CRYPTO"
    grep -qF "$s" "$RUST_KDF" || fail "$s missing from $RUST_KDF"
done
echo "ok: HKDF info strings match across Rust and Swift"

# 2. Argon2 production parameters (m=64MiB, t=3, p=4) — the phone hard-codes what the desktop
#    selects by profile. Real escrowed blobs only ever use Production.
grep -q '3, 65536, 4' "$SWIFT_CRYPTO" || fail "Swift argon2 call no longer (t=3, m=65536, p=4)"
grep -q '(65536, 3, 4)' "$RUST_KDF" || fail "Rust PRODUCTION profile no longer (65536, 3, 4)"
echo "ok: Argon2 production params match"

# 3. The committed golden fixture exists (its content is verified by cargo test on the Rust
#    side and by NorthKeyTests on the Swift side).
test -s apps/ios-key/NorthKeyTests/Fixtures/golden-vault.json \
    || fail "golden-vault.json fixture missing"
echo "ok: golden fixture present"

# 4. The Add-a-device QR payload: every field the phone decodes must be minted by the desktop.
for k in v ip cert enroll ts; do
    grep -q "let $k" "$SWIFT_SCAN" || fail "QR field '$k' missing from Swift DesktopSetupQR"
    grep -q "\"$k\"" "$RUST_SYNC" || fail "QR field '$k' missing from desktop QR payload ($RUST_SYNC)"
done
echo "ok: QR payload fields match desktop mint and phone scan"

# 5. Every API path the phone calls must exist in the server's router. (Parameterized routes
#    are matched by prefix.)
for p in /v1/auth/enroll /v1/auth/bootstrap /v1/auth/refresh /v1/wrapped-keys /v1/vault \
         /v1/push/register /v1/devices/pin /v1/unlock-requests /v1/meta \
         /v1/auth/password/params /v1/auth/password /v1/transfers /v1/devices; do
    grep -qF "$p" "$SWIFT_API" || fail "path $p no longer used by ApiClient.swift (update this list)"
    grep -qF "\"$p" "$API_ROUTES" || fail "path $p used by the phone but missing from $API_ROUTES"
done
echo "ok: every phone API path exists in the server router"

# 6. Byte-format magics live on both sides.
for m in SNTL SVLT SFIL; do
    grep -q "$m" "$SWIFT_CRYPTO" || fail "magic $m missing from Swift"
    grep -rq "\"$m\"\|b\"$m\"" crates/core/src/ || fail "magic $m missing from Rust core"
done
echo "ok: SNTL/SVLT/SFIL magics present on both platforms"

NMHOST=apps/desktop/src-tauri/src/nmhost.rs
STATE=apps/desktop/src-tauri/src/state.rs
DESKTOP_SYNC=apps/desktop/src-tauri/src/sync.rs
TAURI_CONF=apps/desktop/src-tauri/tauri.conf.json

# 7. Chrome derives the extension ID from manifest.json's "key"; the desktop hard-codes that ID
#    in the native-messaging allow-list. Rotating the key (e.g. for a Web Store listing) without
#    updating EXTENSION_ID silently kills all autofill.
python3 - "$NMHOST" <<'PY' || fail "extension ID no longer matches manifest.json key"
import base64, hashlib, json, re, sys
key = json.load(open("apps/extension/manifest.json"))["key"]
digest = hashlib.sha256(base64.b64decode(key)).hexdigest()[:32]
derived = "".join(chr(ord('a') + int(c, 16)) for c in digest)
declared = re.search(r'EXTENSION_ID: &str = "([a-p]{32})"', open(sys.argv[1]).read()).group(1)
sys.exit(0 if derived == declared else f"derived {derived} != declared {declared}")
PY
echo "ok: extension ID matches the manifest key"

# 8. The keychain slot sync-restore WRITES must be the slot startup READS — a mismatch looks
#    like data loss on the next launch.
kc() { grep -o "$2 = \"[^\"]*\"" "$1" | head -1 | cut -d'"' -f2; }
[ "$(kc "$DESKTOP_SYNC" 'KC_SERVICE:[^=]*')" = "$(kc "$STATE" 'KEYCHAIN_SERVICE:[^=]*')" ] \
    || fail "keychain SERVICE differs between sync.rs and state.rs"
[ "$(kc "$DESKTOP_SYNC" 'KC_VAULT_KEY:[^=]*')" = "$(kc "$STATE" 'KEYCHAIN_ACCOUNT:[^=]*')" ] \
    || fail "keychain vault-key ACCOUNT differs between sync.rs and state.rs"
echo "ok: keychain constants agree between sync.rs and state.rs"

# 9. One native-messaging host name across Rust, TS, and the manifest template.
grep -q 'HOST_NAME: &str = "com.sentinel.host"' "$NMHOST" || fail "HOST_NAME changed in nmhost.rs"
grep -q 'NM_HOST_NAME = "com.sentinel.host"' packages/shared/src/nmProtocol.ts \
    || fail "NM_HOST_NAME changed in nmProtocol.ts"
test -f apps/extension/host/com.sentinel.host.json.tmpl || fail "host manifest template renamed"
echo "ok: native-messaging host name consistent (com.sentinel.host)"

# 10. The Tauri bundle identifier doubles as the app-data dir name (mirrored by the NM host and
#     logs) and the keychain service. All four must move together.
ident=$(python3 -c 'import json; print(json.load(open("'"$TAURI_CONF"'"))["identifier"])')
for f in "$NMHOST" "$STATE" apps/desktop/src-tauri/src/applog.rs; do
    grep -q "$ident" "$f" || fail "bundle identifier '$ident' missing from $f"
done
echo "ok: bundle identifier mirrored consistently ($ident)"

# 11. Every NM wire-type string the Rust protocol names must exist in the shared TS protocol.
grep -o 'rename = "[a-z_.]*\.[a-z_.]*"' crates/core/src/nm/protocol.rs | cut -d'"' -f2 | \
while read -r t; do
    grep -qF "\"$t\"" packages/shared/src/nmProtocol.ts \
        || fail "NM wire type '$t' missing from nmProtocol.ts"
done
echo "ok: NM wire-type strings present in the shared TS protocol"

# 12. The API container runs as uid 10001 (Dockerfile) and cloud-init chowns its volumes to that
#     uid; the image ships migrations where the server looks for them.
grep -q -- '--uid 10001' services/api/Dockerfile || fail "Dockerfile uid changed from 10001"
grep -q '10001:10001' crates/core/src/provision/cloudinit.rs || fail "cloud-init chown uid changed"
grep -q '/opt/sentinel/migrations' services/api/Dockerfile || fail "Dockerfile migrations path moved"
grep -q '/opt/sentinel/migrations' services/api/src/main.rs || fail "server migrations default moved"
echo "ok: container uid + migrations path agree between Dockerfile, cloud-init, and server"

# 13. The ghcr image the desktop deploys/updates and the updater endpoint must point at THIS
#     repo (they're hardcoded; a repo rename/transfer silently strands both). Runs when the repo
#     identity is known (CI, or a local clone with an origin remote).
repo="${GITHUB_REPOSITORY:-}"
if [ -z "$repo" ]; then
    repo=$(git remote get-url origin 2>/dev/null | sed -E 's#.*[:/]([^/]+/[^/]+?)(\.git)?$#\1#' || true)
fi
if [ -n "$repo" ]; then
    owner_lc=$(echo "${repo%%/*}" | tr '[:upper:]' '[:lower:]')
    grep -q "ghcr.io/$owner_lc/sentinel-api" "$DESKTOP_SYNC" \
        || fail "sync.rs image ref no longer ghcr.io/$owner_lc/sentinel-api (repo owner changed?)"
    grep -q "github.com/$repo/releases" "$TAURI_CONF" \
        || fail "updater endpoint in tauri.conf.json no longer points at $repo"
    echo "ok: image ref + updater endpoint point at $repo"
else
    echo "skip: repo identity unknown (no GITHUB_REPOSITORY, no origin remote)"
fi

echo "All interop checks passed."
