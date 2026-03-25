# Citrate Faucet — Multi-stage Docker build
# Serves testnet SALT tokens via HTTP API
#
# Build from workspace root:
#   docker build -f faucet/Dockerfile -t citrate-faucet .
#
# Run:
#   docker run -p 3002:3002 \
#     -e CITRATE_RPC_URL=https://rpc.citrate.ai \
#     -e FAUCET_ADDRESS=0x3333333333333333333333333333333333333333 \
#     citrate-faucet

FROM rust:1.77-bookworm AS builder

WORKDIR /build

# Copy workspace Cargo files first for layer caching
COPY Cargo.toml Cargo.lock ./
COPY core/ core/
COPY faucet/ faucet/
COPY node/ node/
COPY wallet/ wallet/
COPY cli/ cli/

# Build only the faucet binary
RUN cargo build --release -p citrate-faucet

# Runtime stage — minimal image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/citrate-faucet /usr/local/bin/citrate-faucet

EXPOSE 3002

ENV CITRATE_RPC_URL=http://localhost:8545
ENV CITRATE_CHAIN_ID=40204
ENV FAUCET_PORT=3002
ENV FAUCET_ADDRESS=0x3333333333333333333333333333333333333333

CMD ["citrate-faucet"]
