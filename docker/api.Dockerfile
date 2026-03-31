# Citrate API Server Dockerfile
FROM rust:1.93.0-slim as builder

RUN apt-get update && apt-get install -y \
    pkg-config libssl-dev ca-certificates build-essential clang cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN cargo build --release --bin citrate-api

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates curl jq \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 citrate
COPY --from=builder /app/target/release/citrate-api /usr/local/bin/citrate-api
RUN mkdir -p /data /config && chown -R citrate:citrate /data /config
COPY docker/config/api.toml /config/api.toml

USER citrate
EXPOSE 3000 3001

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

CMD ["citrate-api", "--config", "/config/api.toml"]
