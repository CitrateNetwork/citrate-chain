FROM rust:1.93.0-slim as builder
WORKDIR /app
RUN apt-get update && apt-get install -y \
    build-essential clang cmake pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY . .
RUN cargo build --release -p node-app

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -m lattice
COPY --from=builder /app/target/release/node-app /usr/local/bin/node-app
USER lattice
EXPOSE 3000 8545 9100
ENTRYPOINT ["/usr/local/bin/node-app"]
