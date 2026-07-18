# Running the SENTINEL sync server

The desktop app and vault work with **no server** — see the local-first note in the
README. You only need the sync API for multi-device sync, new-device approval, and
iPhone-unlock relay. It's a single Rust binary (`sentinel-api`) plus Postgres 16.

## Deploy with Docker (recommended)

The fastest path is the bundled `docker-compose.yml` (repo root). It builds the API,
starts Postgres 16 (with a health check and a persistent volume), applies the schema
migrations, and starts the server — all from one command.

### Recommended host

Any small VPS with Docker installed works. A **Linode Nanode ($5/mo)** (1 GB RAM) or
the equivalent on DigitalOcean/Hetzner/Vultr is plenty — the server stores only small
opaque blobs. Install Docker with the official convenience script and you're ready:

```bash
curl -fsSL https://get.docker.com | sh
```

### 1. Configure `.env`

All configuration lives in a single `.env` file at the repo root (git-ignored — it is
never committed and never baked into the image). Start from the example and edit it:

```bash
cp .env.example .env
```

Then set these values in `.env` (a complete Docker `.env` looks like this):

```dotenv
# Postgres — the DB host is the compose service name `db`, port 5432.
# Keep the password here in sync with POSTGRES_PASSWORD below.
POSTGRES_USER=sentinel
POSTGRES_PASSWORD=change-me-to-a-strong-password
POSTGRES_DB=sentinel
DATABASE_URL=postgres://sentinel:change-me-to-a-strong-password@db:5432/sentinel

# Your Google OAuth client id (see "Google OAuth client" below). When set, the
# server verifies real Google id_tokens against Google's JWKS. When UNSET, the
# server falls back to a mock verifier — do that only for local testing.
GOOGLE_OAUTH_CLIENT_ID=1234567890-abcdef.apps.googleusercontent.com

# 32-byte base64 key that encrypts account TOTP secrets at rest. Generate once:
#   openssl rand -base64 32
SENTINEL_TOTP_ENC_KEY=REPLACE_WITH_openssl_rand_base64_32

# ES256 private key (PEM) that signs short-lived access JWTs. Generated below and
# mounted read-only into the container at this path.
SENTINEL_JWT_ES256_PEM=/run/secrets/sentinel/jwt.pem

# Host port to publish the API on (behind TLS you'd normally proxy to this).
SENTINEL_API_PORT=8787
```

Generate the two secrets:

```bash
# TOTP-at-rest encryption key → paste into SENTINEL_TOTP_ENC_KEY
openssl rand -base64 32

# ES256 signing key → mounted at /run/secrets/sentinel/jwt.pem
mkdir -p secrets
openssl ecparam -genkey -name prime256v1 -noout -out secrets/jwt.pem
```

The `./secrets/` directory (git-ignored) is mounted read-only into the API container.
If you skip the PEM, the server logs a warning and uses an **ephemeral** signing key —
fine for a quick test, but every restart invalidates all issued access tokens.

### 2. Bring it up

```bash
docker compose up -d
```

That builds the `sentinel-api` image, waits for Postgres to be healthy, runs the
one-shot `migrate` service (applies `services/api/migrations/*.sql` in order), then
starts the API. Check it:

```bash
docker compose ps
docker compose logs -f api
curl http://localhost:8787/healthz     # {"status":"ok"}
```

Migrations are re-applied idempotently on every `up`, so upgrading is just
`git pull && docker compose up -d --build`. If you ever want to run them manually:

```bash
docker compose run --rm migrate
```

### 3. Put it behind TLS

The API speaks plain HTTP; **always** terminate TLS in front of it. The easiest option
is [Caddy](https://caddyserver.com/), which fetches and renews Let's Encrypt certs
automatically. Add a `Caddyfile` at the repo root:

```caddy
sync.example.com {
    reverse_proxy api:8787
}
```

…and add a `caddy` service to `docker-compose.yml` (it reaches the API over the compose
network, so you can then drop the `api` service's `ports:` mapping entirely):

```yaml
  caddy:
    image: caddy:2
    restart: unless-stopped
    depends_on: [api]
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
      - caddy_config:/config

volumes:
  caddy_data:
  caddy_config:
```

Point your domain's DNS at the VPS, run `docker compose up -d`, and Caddy provisions
HTTPS for `https://sync.example.com` on first request.

## Google OAuth client

Sign-in uses Google's **PKCE public-client** flow, so there is **no client secret** to
configure anywhere. Create the client id once:

1. In the [Google Cloud Console](https://console.cloud.google.com/apis/credentials),
   go to **APIs & Services → Credentials → Create credentials → OAuth client ID**.
2. Choose application type **"Desktop app"**. (Desktop/native apps use PKCE and a
   loopback redirect — no secret is needed or stored.)
3. Copy the generated **client id** (looks like `…-….apps.googleusercontent.com`).
4. Put the **same** client id in two places:
   - the **desktop app** configuration, and
   - the **server** env as `GOOGLE_OAUTH_CLIENT_ID` (see `.env` above).
5. The app receives the OAuth redirect on a **loopback** address —
   `http://127.0.0.1:<port>/callback` — which Google permits for Desktop-app clients
   without registering an explicit redirect URI.

When `GOOGLE_OAUTH_CLIENT_ID` is set, the server verifies each id_token's RS256
signature against Google's published JWKS and checks that `aud` equals your client id,
`iss` is a Google issuer, and the token is unexpired.

## What it stores (and never can read)

- Account records (Google `sub`, email) and an **encrypted** TOTP secret.
- Opaque wrapped-key blobs and opaque vault ciphertext + a monotonic version counter.
- Device registry, hashed refresh tokens, opaque unlock-request payloads, push tokens.

No column can hold a plaintext secret — a migrate-time guard and a test enforce this
(`schema_guard`). A full database dump plus a compromised Google account still cannot
decrypt your vault (`structural_zero_knowledge`).

## Manual install (without Docker)

Prefer to run the binary directly on a host? You still only need Postgres 16 and the
binary.

```bash
# 1. Postgres 16
sudo apt install postgresql-16
sudo -u postgres createuser --pwprompt sentinel
sudo -u postgres createdb -O sentinel sentinel

# 2. Config
cp .env.example services/api/.env
# edit services/api/.env:
#   DATABASE_URL=postgres://sentinel:...@127.0.0.1:5432/sentinel
#   GOOGLE_OAUTH_CLIENT_ID=<your Desktop-app client id>
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

### systemd unit

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

- Put the API behind TLS (the Caddy example above, another reverse proxy, or the
  platform's TLS). All endpoints are authenticated and rate-limited.
- The Linode token for VPN provisioning lives in the **desktop's OS keychain**, never
  on the server.
- APNs (iPhone push) needs an Apple Developer APNs key — see
  [`apps/ios-key/README.md`](../apps/ios-key/README.md).
