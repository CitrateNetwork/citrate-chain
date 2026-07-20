#!/usr/bin/env bash
# Put every local keystore / secret file "away safely": one passphrase-encrypted
# (AES-256) custody archive, for the pre-reroll key-safe-state step.
#
# It changes NO key value — pure at-rest wrapping. It prints NO secret. gpg
# prompts interactively for the passphrase (never on the command line).
#
# Usage:
#   keystore-safe-away.sh            # pack + round-trip verify (non-destructive)
#   keystore-safe-away.sh --shred    # ALSO shred the redundant plaintext *.bak.* backups
#                                     # (only after a successful pack+verify; never shreds .env.testnet)
set -euo pipefail
umask 077

ROOT="/home/saul/Projects/Citrate-Labs"
OUT="$HOME/citrate-custody-$(date -u +%Y%m%d-%H%M%S).gpg"
SHRED=0; [ "${1:-}" = "--shred" ] && SHRED=1
cd "$ROOT"

echo "== 1. keystore perms + git safety =="
[ -f .env.testnet ] || { echo "FATAL: no $ROOT/.env.testnet"; exit 1; }
chmod 600 .env.testnet
if git ls-files --error-unmatch .env.testnet >/dev/null 2>&1; then
  echo "FATAL: .env.testnet is git-TRACKED — untrack before encrypting (never commit secrets)"; exit 1
fi
git check-ignore -q .env.testnet 2>/dev/null && echo "  .env.testnet gitignored ✓" \
  || echo "  ⚠ .env.testnet NOT gitignored — add '.env.*' to .gitignore"

echo "== 2. collect files to pack (keystore + local backups + comms master key + real .env files) =="
FILES=()
add() { [ -e "$1" ] && { FILES+=("$1"); echo "  + $1"; }; }
add .env.testnet
add .env.core-membership.custody                  # core-membership NON-DERIVABLE secrets (MEMBERSHIP_ENC_KEY KEK, DATABASE_URL, Stripe, KYC, entitlements-admin — Vercel-prod may be the only copy)
add .env.citrate-identity.custody                 # citrate-identity NON-DERIVABLE secrets (KYC_MASTER_KEY, COOKIE_KEYS, DB/Redis/SMTP pw, Sumsub, Google secret, identity signer — droplet /opt/citrate-identity/.env may be the only copy)
add .env.citrate-identity-jwks.json               # citrate-identity RS256 OIDC SIGNING KEY (jwks.json) — CROWN JEWEL: lost = every issued token breaks; only lives in the droplet's identity_keys docker volume
shopt -s nullglob
for f in .env.testnet.bak.* .env.testnet.bak-*; do add "$f"; done
shopt -u nullglob
add "$HOME/.config/citrate-comms-backup"          # comms relay master key (off-box requirement)
add "$HOME/.config/citrate-comms-backup/master.key"
# other real (non-.example) env files that may hold live secrets — extend as needed:
for f in citrate-agent-runtime/.env.hermes citrate-explorer/.env.indexer citrate-identity/.env.kyc; do add "$f"; done
[ ${#FILES[@]} -gt 0 ] || { echo "FATAL: nothing to pack"; exit 1; }

echo "== 3. encrypt -> $OUT  (AES-256; you'll be prompted for a passphrase) =="
tar -czf - -- "${FILES[@]}" | gpg --symmetric --cipher-algo AES256 --no-symkey-cache -o "$OUT"
chmod 600 "$OUT"

echo "== 4. round-trip verify (decrypt + list contents; nothing extracted) =="
if gpg -d "$OUT" 2>/dev/null | tar -tzf - >/dev/null; then
  echo "  round-trip OK ✓  ($(gpg -d "$OUT" 2>/dev/null | tar -tzf - | wc -l) files sealed)"
else
  echo "  FATAL: round-trip failed — do NOT rely on this archive / do NOT shred anything"; exit 1
fi

echo "== 5. custody reminders =="
echo "  archive:    $OUT   (0600)"
echo "  passphrase: store in your password manager, SEPARATE from the archive"
echo "  copies:     keep two (e.g. vault + an offline copy)"

if [ "$SHRED" -eq 1 ]; then
  echo "== 6. --shred: removing redundant plaintext *.bak backups (NOT .env.testnet) =="
  shopt -s nullglob
  for f in .env.testnet.bak.* .env.testnet.bak-*; do shred -u "$f" && echo "  shredded $f"; done
  shopt -u nullglob
  echo "  .env.testnet kept (live keystore, 0600); it is also sealed inside the archive."
else
  echo "== next (optional, after you confirm the archive + passphrase are safe) =="
  echo "  re-run with --shred to remove the redundant plaintext .bak backups, or:"
  echo "    shopt -s nullglob; shred -u $ROOT/.env.testnet.bak.* $ROOT/.env.testnet.bak-*"
fi
echo "DONE."
