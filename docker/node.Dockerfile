# Citrate Node Dockerfile
FROM rust:1.93.0-slim as builder

RUN apt-get update && apt-get install -y \
    pkg-config libssl-dev ca-certificates build-essential clang cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN cargo build --release --bin citrate

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates curl jq \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 citrate
COPY --from=builder /app/target/release/citrate /usr/local/bin/citrate
RUN mkdir -p /data /config && chown -R citrate:citrate /data /config
COPY docker/config/node.toml /config/node.toml

USER citrate
EXPOSE 8545 8546 30303

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8545 || exit 1

CMD ["citrate", "--config", "/config/node.toml", "--data-dir", "/data"]
