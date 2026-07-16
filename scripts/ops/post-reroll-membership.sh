#!/usr/bin/env bash
# Post-re-roll ceremony for the Phase-D MONEY PATH (membership + treasury signer).
# Run this AFTER scripts/ops/post-reroll-redeploy.sh (the AA stack) on a fresh
# re-roll. It is the piece that used to be done by hand and MUST NOT be brushed
# under the rug — every re-roll needs it or the money path silently breaks.
#
# What it does (idempotent):
#   0. Ensure DETERMINISTIC operator keys exist (derive-operator-keys.sh). This
#      guarantees the same treasury/grant + sponsor + registrar addresses every
#      re-roll, so contract ownership + the paymaster sponsor are stable.
#   1. Deploy the membership contracts OWNED BY the deterministic grant signer:
#        MEMBERSHIP_OWNER=$GRANT_SIGNER_ADDRESS forge script DeployCoreMembership
#      Re-pin CitrateMemberSBT + MembershipStakeVault into contracts/addresses/40204.json.
#   2. Fund the grant signer with SALT for testing/operations (default 200k =
#      ~6 grants @ 32k). vault.grant is PAYABLE (msg.value == amount), so the
#      signer must hold `amount` per grant.
#   3. Print the treasury-signer redeploy steps for the droplet (the key is
#      deterministic, so the service just needs its env refreshed + restart).
#
# Inputs (from .env.testnet): RPC_URL/CITRATE_RPC_URL, DEPLOYER_PRIVATE_KEY,
#   TREASURY_PRIVATE_KEY, GRANT_SIGNER_ADDRESS (derived), LIQUID_STAKING_POOL (book).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CONTRACTS_DIR="${REPO_ROOT}/contracts"
ENV_FILE="${CITRATE_ENV_FILE:-$(cd "${REPO_ROOT}/.." && pwd)/.env.testnet}"
BOOK="${CONTRACTS_DIR}/addresses/40204.json"
RPC="$(grep -m1 '^CITRATE_RPC_URL=' "$ENV_FILE" | cut -d= -f2)"; RPC="${RPC:-https://rpc.citrate.ai}"
FUND_SALT="${GRANT_SIGNER_FUND_SALT:-200000}"

echo "== step 0: derive deterministic operator keys =="
bash "${REPO_ROOT}/scripts/ops/derive-operator-keys.sh"

GRANT_ADDR="$(grep -m1 '^GRANT_SIGNER_ADDRESS=' "$ENV_FILE" | cut -d= -f2)"
DK="$(grep -m1 '^DEPLOYER_PRIVATE_KEY=' "$ENV_FILE" | cut -d= -f2)"
TK="$(grep -m1 '^TREASURY_PRIVATE_KEY=' "$ENV_FILE" | cut -d= -f2)"

echo "== step 1: deploy membership contracts owned by grant signer $GRANT_ADDR =="
cd "$CONTRACTS_DIR"
OUT="$(MEMBERSHIP_OWNER="$GRANT_ADDR" FOUNDRY_VIA_IR=true forge script script/DeployCoreMembership.s.sol \
  --rpc-url "$RPC" --private-key "$DK" --broadcast --slow 2>&1)"
echo "$OUT" | grep -iE "CitrateMemberSBT|MembershipStakeVault|initialOwner"
SBT="$(echo "$OUT" | grep -iE 'CitrateMemberSBT ' | grep -oE '0x[0-9a-fA-F]{40}' | tail -1)"
VAULT="$(echo "$OUT" | grep -iE 'MembershipStakeVault' | grep -oE '0x[0-9a-fA-F]{40}' | tail -1)"
[ -n "$SBT" ] && [ -n "$VAULT" ] || { echo "failed to parse new addresses" >&2; exit 2; }

echo "== re-pin book: SBT=$SBT VAULT=$VAULT =="
PY=python3; command -v python3 >/dev/null || PY="uv run python3"
$PY - "$BOOK" "$SBT" "$VAULT" <<'PY'
import sys,json
p,sbt,vault=sys.argv[1:4]
d=json.load(open(p)); d["CitrateMemberSBT"]=sbt; d["MembershipStakeVault"]=vault
json.dump(d,open(p,"w"),indent=2); open(p,"a").write("\n"); print("book re-pinned")
PY

echo "== step 2: fund grant signer $GRANT_ADDR with ${FUND_SALT} SALT =="
cast send "$GRANT_ADDR" --value "${FUND_SALT}ether" --private-key "$TK" -r "$RPC" >/dev/null
echo "  balance: $(cast balance "$GRANT_ADDR" -r "$RPC")"

cat <<EOF

== step 3: redeploy the droplet treasury-signer (manual, @rule8) ==
The signing key is deterministic; only the CONTRACT addresses change on a
re-roll (DeployCoreMembership uses plain CREATE, nonce-based), so on the
identity droplet (157.230.55.191) refresh the env + rebuild + recreate:
  1. Refresh /etc/citrate-treasury-signer.env with:
       TREASURY_SIGNER_KEY=<GRANT_SIGNER_PRIVATE_KEY from .env.testnet>
       MEMBERSHIP_STAKE_VAULT_ADDRESS=${VAULT}
       CITRATE_MEMBER_SBT_ADDRESS=${SBT}
     (keep TREASURY_SIGNER_TOKEN + TREASURY_DAILY_CAP_WEI + CITRATE_RPC_URL + CITRATE_CHAIN_ID)
  2. Copy the latest service source then rebuild + RECREATE the container.
     NOTE: 'docker restart' does NOT re-read --env-file; you MUST rm + run so the
     new SBT/VAULT/cap take effect. The --network flag is REQUIRED so Caddy can
     reach the container by name for the HTTPS route.
       scp citrate-identity/services/treasury-signer/{server.mjs,package.json,Dockerfile} \\
           root@157.230.55.191:/opt/citrate-treasury-signer/
       cd /opt/citrate-treasury-signer && docker build -t citrate-treasury-signer .
       docker rm -f citrate-treasury-signer
       docker run -d --name citrate-treasury-signer --restart unless-stopped \\
         --network citrate-identity_default \\
         -p 127.0.0.1:8790:8790 --env-file /etc/citrate-treasury-signer.env \\
         -v /var/lib/citrate-treasury-signer:/var/lib/citrate-treasury-signer citrate-treasury-signer
  3. Confirm the Caddy TLS route still exists (it persists across re-rolls; only
     re-add if the Caddyfile was rebuilt). /opt/citrate-identity/Caddyfile must
     contain, inside the {\$ISSUER_HOST} block:
       @treasury path /_ops/treasury/*
       handle @treasury { uri strip_prefix /_ops/treasury; reverse_proxy citrate-treasury-signer:8790 }
     After any Caddyfile edit: docker restart citrate-identity-caddy-1
     (a plain 'caddy reload' does NOT pick up new handle blocks — restart the container).
  4. Verify local + public:
       curl -s http://127.0.0.1:8790/health                     # signer == ${GRANT_ADDR}
       curl -s https://auth.citrate.ai/_ops/treasury/health     # same JSON via TLS
Then re-pin the new SBT/VAULT into core-membership's Vercel env + redeploy, and
confirm TREASURY_SIGNER_URL=https://auth.citrate.ai/_ops/treasury/grant is set
there (the URL + token are STABLE across re-rolls; only SBT/VAULT change).
Service source: citrate-identity/services/treasury-signer/.
EOF
echo "post-reroll membership ceremony complete."
