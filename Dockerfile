FROM rust:1-bookworm AS builder

WORKDIR /build

# Copy manifests first for dependency caching. Every workspace member must be
# present or Cargo refuses to resolve the workspace.
COPY Cargo.toml Cargo.lock ./
COPY crates/identity/Cargo.toml crates/identity/Cargo.toml
COPY crates/core/Cargo.toml crates/core/Cargo.toml
COPY crates/server/Cargo.toml crates/server/Cargo.toml
COPY crates/broker/Cargo.toml crates/broker/Cargo.toml
COPY crates/cli/Cargo.toml crates/cli/Cargo.toml

# Stub every target the manifests declare so the dependency build succeeds
# without real sources.
RUN mkdir -p crates/identity/src crates/core/src crates/server/src crates/broker/src crates/cli/src \
    && echo "pub fn _dummy() {}" > crates/identity/src/lib.rs \
    && echo "pub fn _dummy() {}" > crates/core/src/lib.rs \
    && echo "pub fn _dummy() {}" > crates/server/src/lib.rs \
    && echo "fn main() {}" > crates/server/src/main.rs \
    && echo "pub fn _dummy() {}" > crates/broker/src/lib.rs \
    && echo "fn main() {}" > crates/broker/src/main.rs \
    && echo "fn main() {}" > crates/cli/src/main.rs \
    && mkdir -p policies migrations \
    && touch policies/default.cedar \
    && touch migrations/001_init.sql

RUN cargo build --release --bin agent-cordon-server 2>/dev/null || true

# Copy real source
COPY crates/ crates/
COPY policies/ policies/
COPY migrations/ migrations/
COPY docs/ docs/
COPY data/ data/
COPY tools/ tools/

# Touch entry points so the stubs' fingerprints are invalidated
RUN touch crates/identity/src/lib.rs crates/core/src/lib.rs crates/server/src/lib.rs crates/server/src/main.rs \
    crates/broker/src/lib.rs crates/broker/src/main.rs crates/cli/src/main.rs

RUN cargo build --release --bin agent-cordon-server

# Runtime stage
FROM debian:trixie-slim

# Build metadata. The release workflow passes the tag's version and commit;
# a local `docker build` gets the defaults. The *binary's* own `--version`
# always comes from `[workspace.package] version` via CARGO_PKG_VERSION --
# these arguments only label the image.
ARG VERSION=dev
ARG VCS_REF=unknown

LABEL org.opencontainers.image.title="AgentCordon" \
      org.opencontainers.image.description="Credential brokering and policy enforcement for autonomous AI agents" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="https://github.com/agentcordon/agentcordon" \
      org.opencontainers.image.url="https://agentcordon.dev" \
      org.opencontainers.image.licenses="MIT"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash agtcrdn

COPY --from=builder /build/target/release/agent-cordon-server /usr/local/bin/agent-cordon-server
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
RUN mkdir -p /data && chown agtcrdn:agtcrdn /data

USER agtcrdn

ENV AGTCRDN_LISTEN_ADDR=0.0.0.0:3140
ENV AGTCRDN_DB_PATH=/data/agent-cordon.db

EXPOSE 3140

VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:3140/health || exit 1

ENTRYPOINT ["docker-entrypoint.sh"]
