# Running the SENTINEL sync server

The desktop app and vault work with **no server** — see the local-first note in the
README. You only need the sync API for multi-device sync, new-device approval, and
iPhone-unlock relay. It's a single Rust binary (`sentinel-api`) plus Postgres 16.

## What it stores (and never can read)

- Account records (Google `sub`, email) and an **encrypted** TOTP secret.
- Opaque wrapped-key blobs and opaque vault ciphertext + a monotonic version counter.
- Device registry, hashed refresh tokens, opaque unlock-request payloads, push tokens.

No column can hold a plaintext secret — a migrate-time guard and a test enforce this
(`schema_guard`). A full database dump plus a compromised Google account still cannot
decrypt your vault (`structural_zero_knowledge`).

## Quick start (a small VPS or home box)

```bash
# 1. Postgres 16
sudo apt install postgresql-16
sudo -u postgres createuser --pwprompt sentinel
sudo -u postgres createdb -O sentinel sentinel

# 2. Config
cp .env.example services/api/.env
# edit services/api/.env:
#   DATABASE_URL=postgres://sentinel:...@127.0.0.1:5432/sentinel
#   GOOGLE_OAUTH_CLIENT_ID=<your web client id>
#   SENTINEL_TOTP_ENC_KEY=$(openssl rand -base64 32)
openssl ecparam -genkey -name prime256v1 -noout -out services/api/jwt.pem
#   SENTINEL_JWT_ES256_PEM=./jwt.pem

# 3. Apply the schema
for f in services/api/migrations/[0-9]*.sql; do
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f "$f"
done

# 4. Run
cargo run --release -p sentinel-api
```

## systemd unit

```ini
[Unit]
Description=SENTINEL sync API
After=network.target postgresql.service

[Service]
WorkingDirectory=/opt/sentinel
EnvironmentFile=/opt/sentinel/services/api/.env
ExecStart=/opt/sentinel/target/release/sentinel-api
Restart=on-failure
User=sentinel
# Harden
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

## Notes

- Put the API behind TLS (a reverse proxy or the platform's TLS). All endpoints are
  authenticated and rate-limited.
- The Linode token for VPN provisioning lives in the **desktop's OS keychain**, never
  on the server.
- APNs (iPhone push) needs an Apple Developer APNs key — see
  [`apps/ios-key/README.md`](../apps/ios-key/README.md).
