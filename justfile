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
    {{pg_bin}}/psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f services/api/migrations/all.sql

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

screenshots:
    pnpm --filter @sentinel/desktop build
    pnpm --filter @sentinel/desktop screenshots

# --- security / audit ----------------------------------------------------
audit:
    -cargo audit
    -pnpm audit --prod

plaintext-audit:
    bash scripts/plaintext-audit.sh

# --- aggregate -----------------------------------------------------------
ci: fmt-check clippy test-rust test-api typecheck lint-web test-web
    @echo "CI recipe complete."
