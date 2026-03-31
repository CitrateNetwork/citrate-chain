# docker/

Docker infrastructure for running Citrate services in containers.

## Dockerfiles

| File | Purpose |
|------|---------|
| `node.Dockerfile` | Citrate blockchain node (JSON-RPC on 8545, P2P on 30303) |
| `node-app.Dockerfile` | Node application wrapper (REST API on 3000) |
| `api.Dockerfile` | API server with MCP support (REST on 3000, MCP on 3001) |
| `faucet.Dockerfile` | Testnet token faucet |
| `ipfs.Dockerfile` | IPFS node for model/artifact storage |

## Compose Files

| File | Use Case |
|------|----------|
| `docker-compose.dev.yml` | Local development: 2 nodes, node-app, faucet |
| `docker-compose.prod.yml` | Production: node, API, IPFS, PostgreSQL, Redis, Prometheus, Grafana |

Start dev stack: `docker compose -f docker/docker-compose.dev.yml up --build`
Start prod stack: `docker compose -f docker/docker-compose.prod.yml up -d`

## Config Files (`config/`)

| File | Description |
|------|-------------|
| `node.toml` | Node configuration (GhostDAG k=18, RPC/WS, storage) |
| `api.toml` | API server configuration (node connection, PostgreSQL, Redis, IPFS) |
| `ipfs-config.json` | IPFS daemon settings (100GB storage, swarm tuning, experimental features) |

## Scripts (`scripts/`)

| File | Description |
|------|-------------|
| `ipfs-init.sh` | Initializes IPFS with production settings and starts the daemon |
