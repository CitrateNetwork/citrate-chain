# Citrate Faucet Dockerfile
FROM rust:1.93.0-slim as builder

RUN apt-get update && apt-get install -y \
    pkg-config libssl-dev build-essential clang cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN cargo build --release --bin citrate-faucet

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 1000 citrate
COPY --from=builder /app/target/release/citrate-faucet /usr/local/bin/citrate-faucet

USER citrate
EXPOSE 3003
CMD ["citrate-faucet"]
