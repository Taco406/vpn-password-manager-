# syntax=docker/dockerfile:1
#
# Multi-stage build for the SENTINEL sync API (`sentinel-api`).
# Build context is the REPOSITORY ROOT (the whole Cargo workspace is needed):
#
#   docker build -f services/api/Dockerfile -t sentinel-api .
#
# It bundles NO secrets. All config comes from the environment at run time
# (see docs/self-hosting.md and .env.example).

# ---- build stage ---------------------------------------------------------
# Pinned to the workspace toolchain (rust-toolchain.toml → 1.94.1). The build
# is pure-Rust TLS (rustls/ring) + Postgres over rustls — no OpenSSL needed.
FROM rust:1.94-slim-bookworm AS builder
WORKDIR /build

# ca-certificates lets cargo fetch crates over HTTPS.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# The whole workspace is required: cargo must read every member manifest to
# resolve the graph, even though only `sentinel-api` is compiled.
COPY . .

# Cache the registry and target dir across builds; copy the release binary out
# of the cache mount so it survives into the runtime stage.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release -p sentinel-api --bin sentinel-api \
    && cp /build/target/release/sentinel-api /usr/local/bin/sentinel-api

# ---- runtime stage -------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# ca-certificates is REQUIRED at run time: the real Google verifier fetches
# Google's JWKS over HTTPS. Create an unprivileged user to run as.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --uid 10001 --shell /usr/sbin/nologin sentinel

COPY --from=builder /usr/local/bin/sentinel-api /usr/local/bin/sentinel-api
# Bundled for reference / manual migration runs; the compose stack applies them
# from the source tree via a one-shot `migrate` service.
COPY --from=builder /build/services/api/migrations /opt/sentinel/migrations

USER sentinel

# Inside a container the service must bind all interfaces so the published port
# reaches it. Override via SENTINEL_API_BIND if needed.
ENV SENTINEL_API_BIND=0.0.0.0:8787
EXPOSE 8787

ENTRYPOINT ["/usr/local/bin/sentinel-api"]
