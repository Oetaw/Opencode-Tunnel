# syntax=docker/dockerfile:1.7

# Multi-stage build for the OCT relay container.
#
# IMPORTANT: this image defaults to loopback. A public deployment must add
# `--allow-public`, terminate TLS/WSS in front of the relay, and use E2EE on
# both endpoints. Do not publish this port without those controls.

ARG RUST_VERSION=1.93.1

FROM rust:${RUST_VERSION}-bookworm AS builder

WORKDIR /build

ENV CARGO_NET_RETRY=5 \
    CARGO_TERM_COLOR=always

# Copy manifests first so dependency resolution is cached independently of
# source edits. The workspace has no external path dependencies.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates

RUN cargo build --locked --release -p oct-cli --bin oct

FROM debian:bookworm-slim AS runtime

# ca-certificates supports outbound TLS (when the relay needs it);
# curl is present only for the container healthcheck.
# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 oct \
    && useradd --system --uid 10001 --gid oct \
        --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin oct \
    && mkdir -p /etc/oct \
    && chown root:root /etc/oct \
    && chmod 0755 /etc/oct

COPY --from=builder /build/target/release/oct /usr/local/bin/oct

USER 10001:10001

EXPOSE 8080

# Proposed endpoint; see the warning at the top of this file.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["curl", "--fail", "--silent", "--show-error", "http://127.0.0.1:8080/healthz"]

ENTRYPOINT ["/usr/local/bin/oct"]
CMD ["relay", "--listen", "127.0.0.1:8080"]
