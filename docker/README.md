# docker/

Docker infrastructure for running Citrate services in containers.

## Dockerfiles

| File | Purpose |
|------|---------|
| `node.Dockerfile` | Citrate blockchain node (JSON-RPC on 8545, P2P on 30303) |
| `node-app.Dockerfile` | Node application wrapper (REST API on 3000, metrics on 9100) |
| `api.Dockerfile` | Historical API wrapper path; not part of the recommended open-source operator stack |
| `faucet.Dockerfile` | Testnet token faucet |
| `ipfs.Dockerfile` | IPFS node for model/artifact storage |

## Compose Files

| File | Use Case |
|------|----------|
| `docker-compose.dev.yml` | Local development: 2 nodes, node-app, faucet |
| `docker-compose.prod.yml` | Recommended operator stack: node, faucet, IPFS, Prometheus, Grafana |

Start dev stack: `docker compose -f docker/docker-compose.dev.yml up --build`
Start prod stack: `docker compose -f docker/docker-compose.prod.yml up -d`

Notes:
- The current recommended operator path uses the node itself as the primary JSON-RPC surface.
- The legacy `api.Dockerfile` and `config/api.toml` remain in-tree for historical/reference work, but they are not part of the clean default rollout path.

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
