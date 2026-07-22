# SENTINEL task runner. `just` with no args lists recipes.
# Postgres binaries live under /usr/lib/postgresql/16/bin on Debian/Ubuntu.

set shell := ["bash", "-uc"]

pg_bin := "/usr/lib/postgresql/16/bin"
pgdata := justfile_directory() / ".pgdata"
pg_port := "5433"
export DATABASE_URL := "postgres://sentinel:sentinel@127.0.0.1:5433/sentinel"

default:
    @just --list

# --- setup ---------------------------------------------------------------
setup:
    pnpm install
    cargo fetch

# --- local Postgres dev cluster -----------------------------------------
# Postgres refuses to run as root. When invoked as root (e.g. inside a
# container), these recipes su to an unprivileged owner ($PG_OWNER, default
# `pgrunner`, auto-created). As a normal user they run directly.
db-init:
    #!/usr/bin/env bash
    set -euo pipefail
    owner="${PG_OWNER:-pgrunner}"
    as() { if [ "$(id -u)" = 0 ]; then su "$owner" -c "$1"; else bash -c "$1"; fi; }
    if [ "$(id -u)" = 0 ]; then
        id "$owner" >/dev/null 2>&1 || useradd -m -s /bin/bash "$owner"
        mkdir -p "{{pgdata}}"; chown -R "$owner":"$owner" "{{pgdata}}"
    fi
    if [ ! -f "{{pgdata}}/PG_VERSION" ]; then
        as "{{pg_bin}}/initdb -D {{pgdata}} -U postgres --auth=trust >/dev/null"
        echo "port = {{pg_port}}" >> "{{pgdata}}/postgresql.conf"
        echo "unix_socket_directories = '/tmp'" >> "{{pgdata}}/postgresql.conf"
    fi

db-up: db-init
    #!/usr/bin/env bash
    set -euo pipefail
    owner="${PG_OWNER:-pgrunner}"
    as() { if [ "$(id -u)" = 0 ]; then su "$owner" -c "$1"; else bash -c "$1"; fi; }
    if ! as "{{pg_bin}}/pg_ctl -D {{pgdata}} status" >/dev/null 2>&1; then
        as "{{pg_bin}}/pg_ctl -D {{pgdata}} -l {{pgdata}}/server.log -o '-p {{pg_port}}' start"
    fi
    for i in $(seq 1 30); do
        if {{pg_bin}}/pg_isready -h 127.0.0.1 -p {{pg_port}} -q; then break; fi
        sleep 1
    done
    {{pg_bin}}/psql -h 127.0.0.1 -p {{pg_port}} -U postgres -tc \
        "SELECT 1 FROM pg_roles WHERE rolname='sentinel'" | grep -q 1 || \
        {{pg_bin}}/psql -h 127.0.0.1 -p {{pg_port}} -U postgres -c \
        "CREATE ROLE sentinel LOGIN PASSWORD 'sentinel'"
    {{pg_bin}}/psql -h 127.0.0.1 -p {{pg_port}} -U postgres -tc \
        "SELECT 1 FROM pg_database WHERE datname='sentinel'" | grep -q 1 || \
        {{pg_bin}}/psql -h 127.0.0.1 -p {{pg_port}} -U postgres -c \
        "CREATE DATABASE sentinel OWNER sentinel"
    {{pg_bin}}/pg_isready -h 127.0.0.1 -p {{pg_port}}

db-down:
    #!/usr/bin/env bash
    owner="${PG_OWNER:-pgrunner}"
    if [ "$(id -u)" = 0 ]; then su "$owner" -c "{{pg_bin}}/pg_ctl -D {{pgdata}} stop -m fast" || true
    else {{pg_bin}}/pg_ctl -D "{{pgdata}}" stop -m fast || true; fi

db-migrate: db-up
    #!/usr/bin/env bash
    set -euo pipefail
    for f in services/api/migrations/[0-9]*.sql; do
        echo "applying $f"
        {{pg_bin}}/psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -q -f "$f"
    done

db-reset:
    -{{pg_bin}}/psql -h 127.0.0.1 -p {{pg_port}} -U postgres -c "DROP DATABASE IF EXISTS sentinel"
    @just db-up db-migrate

# --- rust ----------------------------------------------------------------
fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

clippy:
    cargo clippy --workspace --all-targets -- -D warnings

test-rust:
    cargo test --workspace

test-api: db-migrate
    cargo test -p sentinel-api

test-live:
    RUN_LIVE_VPN_TESTS=1 cargo test -p sentinel-core --features live-linode -- --ignored

# --- web -----------------------------------------------------------------
typecheck:
    pnpm -r typecheck

lint-web:
    pnpm -r lint

test-web:
    pnpm -r test

dev-web:
    pnpm --filter @sentinel/desktop dev

seed-json:
    cargo run -q -p sentinel-cli -- seed --json > packages/shared/src/seed.json

# Local runs use the dev container's prebuilt Chromium; CI installs its own and
# leaves SENTINEL_CHROMIUM unset so Playwright resolves it.
export SENTINEL_CHROMIUM := env_var_or_default("SENTINEL_CHROMIUM", "/opt/pw-browsers/chromium")

screenshots:
    pnpm --filter @sentinel/desktop build
    pnpm --filter @sentinel/desktop screenshots

# --- security / audit ----------------------------------------------------
audit:
    -cargo audit
    -pnpm audit --prod

plaintext-audit:
    bash scripts/plaintext-audit.sh

# Verify the iOS pairing channel shares the exact HKDF info strings with the Rust core
# (the interop invariant; the app isn't compiled in CI).
ios-docs-check:
    #!/usr/bin/env bash
    set -euo pipefail
    for s in 'sentinel/v1/pair/chan/desktop->phone' 'sentinel/v1/pair/chan/phone->desktop'; do
        grep -q "$s" apps/ios-key/NorthKey/Crypto/Channel.swift
        grep -q "$s" crates/core/src/crypto/kdf.rs
    done
    echo "iOS channel info strings match the Rust core."
    for s in 'sentinel/v1/vault/outer' 'sentinel/v1/vault/item'; do
        grep -q "$s" apps/ios-key/NorthKey/Crypto/VaultCrypto.swift
        grep -q "$s" crates/core/src/crypto/kdf.rs
    done
    echo "iOS vault info strings match the Rust core."
    grep -q '3, 65536, 4' apps/ios-key/NorthKey/Crypto/VaultCrypto.swift
    grep -q '(65536, 3, 4)' crates/core/src/crypto/kdf.rs
    test -s apps/ios-key/NorthKeyTests/Fixtures/golden-vault.json
    echo "iOS Argon2 params + golden fixture in place."

# --- release -------------------------------------------------------------
# Cut a release: bump the version across the desktop app, commit, tag `vVERSION`,
# and push the tag. The Release workflow then builds signed installers for all three
# OSes and publishes a GitHub Release the installed app self-updates from.
# Usage: just release 0.2.0
release VERSION:
    #!/usr/bin/env bash
    set -euo pipefail
    v="{{VERSION}}"
    [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "version must be X.Y.Z"; exit 1; }
    # tauri.conf.json
    python3 - "$v" <<'PY'
    import json, sys
    p = "apps/desktop/src-tauri/tauri.conf.json"
    d = json.load(open(p)); d["version"] = sys.argv[1]
    json.dump(d, open(p, "w"), indent=2); open(p, "a").write("\n")
    PY
    # apps/desktop/package.json
    python3 - "$v" <<'PY'
    import json, sys
    p = "apps/desktop/package.json"
    d = json.load(open(p)); d["version"] = sys.argv[1]
    json.dump(d, open(p, "w"), indent=2); open(p, "a").write("\n")
    PY
    # src-tauri Cargo.toml (pin its own version; matches either the workspace-inherit
    # form or an already-pinned version line)
    sed -i "0,/^version[[:space:]]*[.=].*/s//version = \"$v\"/" apps/desktop/src-tauri/Cargo.toml
    git add apps/desktop/src-tauri/tauri.conf.json apps/desktop/package.json apps/desktop/src-tauri/Cargo.toml
    git commit -m "release: v$v"
    git tag "v$v"
    git push origin HEAD
    git push origin "v$v"
    @echo "Tagged v$v — the Release workflow will build and publish installers."

# --- aggregate -----------------------------------------------------------
ci: fmt-check clippy test-rust test-api typecheck lint-web test-web
    @echo "CI recipe complete."
