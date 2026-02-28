# ─── Build Stage ──────────────────────────────────────────────
FROM rust:1.93-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 1️⃣ Copy Cargo files dulu untuk caching dependencies
COPY Cargo.toml Cargo.lock ./
COPY .sqlx ./.sqlx

# Build dependencies only
RUN cargo fetch --locked

# 2️⃣ Copy source code dan build final binary
COPY src ./src
ENV SQLX_OFFLINE=true
RUN cargo build --release

# ─── Runtime Stage ───────────────────────────────────────────
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary dari stage builder
COPY --from=builder /app/target/release/yumana_api_v2 .

# Railway injects PORT env variable
EXPOSE 8080

CMD ["./yumana_api_v2"]
