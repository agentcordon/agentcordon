FROM rust:1-bookworm AS builder

WORKDIR /build

# Copy manifests first for dependency caching
COPY Cargo.toml Cargo.lock ./
COPY crates/core/Cargo.toml crates/core/Cargo.toml
COPY crates/server/Cargo.toml crates/server/Cargo.toml
COPY crates/gateway/Cargo.toml crates/gateway/Cargo.toml

# Create dummy source files to build dependencies
RUN mkdir -p crates/core/src crates/server/src crates/gateway/src \
    && echo "pub fn _dummy() {}" > crates/core/src/lib.rs \
    && echo "fn main() {}" > crates/server/src/main.rs \
    && echo "fn main() {}" > crates/gateway/src/main.rs \
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

# Touch source files to invalidate cache for actual build
RUN touch crates/core/src/lib.rs crates/server/src/main.rs

RUN cargo build --release --bin agent-cordon-server

# Runtime stage
FROM debian:bookworm-slim

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
