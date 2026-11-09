#!/usr/bin/env bash
# mempool_lock_order_tripwire.sh — keep the mempool's locks in one order.
#
# core/sequencer/src/mempool.rs declares its lock order on a single line:
#
#   // LOCK-ORDER: transactions, by_sender, priority_queue, ...
#
# All of those locks are fair tokio RwLocks: a queued writer blocks new
# readers, so two methods that take two locks in opposite orders wedge each
# other under concurrent writes even when both only read. This scan checks the
# file against its own declared order:
#
#   * every `RwLock` field of `struct Mempool` appears on the LOCK-ORDER line;
#   * while a guard is held, any further acquisition must be of a lock that comes
#     strictly later in the order (no going back, no taking the same lock twice);
#   * nothing is acquired while a write guard is held;
#   * nothing else is awaited while a guard is held (no calls back into the pool
#     or out to a reader with a guard live).
#
# A guard is "held" for: a `let g = self.x.read().await;` binding (until its
# block closes or `drop(g)`), an `if let` / `while let` / `match` / `for`
# scrutinee (until that block closes), or a temporary (until the statement ends).
#
# Usage: mempool_lock_order_tripwire.sh              # scan mempool.rs
#        mempool_lock_order_tripwire.sh --self-test  # prove it still detects its class
#        mempool_lock_order_tripwire.sh <file.rs>    # scan another file
set -uo pipefail

REPO_ROOT="${MEMPOOL_LOCK_ORDER_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
TARGET="$REPO_ROOT/core/sequencer/src/mempool.rs"

scan() { # <file> ; prints violations, exit 0 iff clean
  python3 -I - "$1" <<'PY'
import re, sys

path = sys.argv[1]
src = open(path, encoding="utf-8").read()

m = re.search(r"^\s*//\s*LOCK-ORDER:\s*(.+)$", src, re.M)
if not m:
    print(f"{path}: no '// LOCK-ORDER:' line"); sys.exit(1)
order = [x.strip() for x in m.group(1).split(",") if x.strip()]
rank = {name: i for i, name in enumerate(order)}

errors = []

# Every RwLock field of the struct must be ranked.
sm = re.search(r"pub struct Mempool\s*\{(.*?)\n\}", src, re.S)
if sm:
    for f in re.findall(r"(\w+)\s*:\s*Arc<\s*RwLock<", sm.group(1)):
        if f not in rank:
            errors.append(f"struct Mempool lock `{f}` is not on the LOCK-ORDER line")

# Production code only: stop at the unit-test module.
cut = re.search(r"#\[cfg\(test\)\]\s*mod\s+\w+", src)
code = src[: cut.start()] if cut else src

# Blank out comments, strings and char literals in ONE left-to-right pass (so a
# quote inside a comment, or an `r"` at the end of a string, cannot flip the
# code/string parity), keeping offsets and newlines.
LEX = re.compile(
    r'//[^\n]*'                              # line comment
    r'|/\*.*?\*/'                            # block comment
    r'|\br(?P<h>#*)"(?:.|\n)*?"(?P=h)'       # raw string
    r'|b?"(?:\\.|[^"\\])*"'                  # string
    r"|b?'(?:\\.|[^'\\\n])'"                 # char literal (not a lifetime)
    , re.S)
def blank(mt):
    return re.sub(r"[^\n]", " ", mt.group(0))
code = LEX.sub(blank, code)

def line_of(pos):
    return code.count("\n", 0, pos) + 1

TOK = re.compile(
    r"(?P<acq>self\s*\.\s*(?P<field>\w+)\s*\.\s*(?P<kind>read|write)\s*\(\s*\)(?P<aw>\s*\.\s*await)?)"
    r"|(?P<drop>\bdrop\s*\(\s*(?P<dname>\w+)\s*\))"
    r"|(?P<await>\.\s*await\b)"
    r"|(?P<open>\{)|(?P<close>\})|(?P<semi>;)"
)

depth = 0
stmt_start = 0          # offset where the current statement began
held = []               # dicts: field, kind, name, release ('depth', d) | ('stmt', d) | ('block', d)
pending_block = []      # scrutinee guards waiting for their block's `{`

def live():
    return held

for t in TOK.finditer(code):
    kind = t.lastgroup
    pos = t.start()
    if t.group("acq"):
        field, mode = t.group("field"), t.group("kind")
        if field not in rank:
            continue  # not a pool lock (e.g. a config field) or the outer wrapper
        for g in live():
            if g["kind"] == "write":
                errors.append(f"{path}:{line_of(pos)}: acquires `{field}` while holding a write guard on `{g['field']}`")
            elif rank[field] <= rank[g["field"]]:
                errors.append(f"{path}:{line_of(pos)}: acquires `{field}` while holding `{g['field']}` (LOCK-ORDER puts `{field}` first)")
        prefix = code[stmt_start:pos]
        after = code[t.end():t.end() + 40]
        bind = re.fullmatch(r"\s*let\s+(?:mut\s+)?(\w+)\s*(?::[^=]+)?=\s*", prefix)
        g = {"field": field, "kind": mode, "name": None}
        if bind and t.group("aw") and re.match(r"\s*;", after):
            g["name"] = bind.group(1)
            g["release"] = ("depth", depth)
            held.append(g)
        elif re.match(r"\s*(?:if\s+let|while\s+let|match|for)\b", prefix):
            pending_block.append(g)       # held through the block that follows
            g["release"] = ("stmt", depth)
            held.append(g)
        else:
            g["release"] = ("stmt", depth)  # temporary: until `;`, `{` or `}`
            held.append(g)
    elif kind == "drop":
        name = t.group("dname")
        held[:] = [g for g in held if g["name"] != name]
    elif kind == "await":
        for g in live():
            errors.append(f"{path}:{line_of(pos)}: awaits while holding `{g['field']}` (take a snapshot and drop the guard first)")
    elif kind == "open":
        depth += 1
        for g in pending_block:
            g["release"] = ("block", depth)
        pending_block.clear()
        # plain temporaries in an `if` / `while` condition end here
        held[:] = [g for g in held if g["release"][0] != "stmt"]
        stmt_start = t.end()
    elif kind == "close":
        depth -= 1
        held[:] = [g for g in held
                   if not ((g["release"][0] == "depth" and depth < g["release"][1])
                           or (g["release"][0] == "block" and depth < g["release"][1])
                           or g["release"][0] == "stmt")]
        stmt_start = t.end()
    elif kind == "semi":
        held[:] = [g for g in held if not (g["release"][0] == "stmt" and g["release"][1] == depth)]
        stmt_start = t.end()

seen = set()
for e in errors:
    if e not in seen:
        seen.add(e); print(e)
sys.exit(1 if errors else 0)
PY
}

self_test() {
  local d rc=0
  d="$(mktemp -d)"; trap 'rm -rf "${d:?}"' RETURN
  local hdr='// LOCK-ORDER: transactions, by_sender, sender_nonces
pub struct Mempool {
    transactions: Arc<RwLock<A>>,
    by_sender: Arc<RwLock<B>>,
    sender_nonces: Arc<RwLock<C>>,
}
impl Mempool {'
  expect_flag() { # <name> <body>
    printf '%s\n%s\n}\n' "$hdr" "$2" > "$d/m.rs"
    if scan "$d/m.rs" >/dev/null; then echo "self-test: missed $1"; rc=1; fi
  }
  expect_clean() {
    printf '%s\n%s\n}\n' "$hdr" "$2" > "$d/m.rs"
    if ! out="$(scan "$d/m.rs")"; then echo "self-test: false positive on $1: $out"; rc=1; fi
  }
  expect_flag "inverted named guards" '
    async fn f(&self) {
        let s = self.by_sender.read().await;
        let t = self.transactions.read().await;
    }'
  expect_flag "inverted, multi-line receiver" '
    async fn f(&self) {
        let s = self.by_sender.read().await;
        let n = self
            .transactions
            .read()
            .await
            .len();
    }'
  expect_flag "inverted acquisition inside if-let scrutinee block" '
    async fn f(&self) {
        if let Some(x) = self.sender_nonces.read().await.get(&k) {
            let t = self.transactions.read().await.len();
        }
    }'
  expect_flag "inversion after a string that ends in r" '
    async fn f(&self) {
        let who = "owner";
        let s = self.by_sender.read().await;
        let t = self.transactions.read().await;
    }'
  expect_flag "acquisition while holding a write guard" '
    async fn f(&self) {
        let mut t = self.transactions.write().await;
        let s = self.by_sender.read().await;
    }'
  expect_flag "await while holding a guard" '
    async fn f(&self) {
        let t = self.transactions.read().await;
        self.remove_transaction(&h).await;
    }'
  expect_flag "same lock twice in one statement" '
    async fn f(&self) {
        let n = self.by_sender.read().await.len() + self.by_sender.read().await.len();
    }'
  printf '// LOCK-ORDER: transactions\npub struct Mempool {\n    transactions: Arc<RwLock<A>>,\n    banned: Arc<RwLock<B>>,\n}\n' > "$d/m.rs"
  if scan "$d/m.rs" >/dev/null; then echo "self-test: missed an unranked lock field"; rc=1; fi
  expect_clean "in-order guards, drop, temporaries, block scopes" '
    async fn f(&self) {
        let t = self.transactions.read().await;
        let s = self.by_sender.read().await;
        let mut n = self.sender_nonces.write().await;
    }
    async fn g(&self) {
        let s = self.by_sender.read().await;
        drop(s);
        let t = self.transactions.read().await.len();
        if self.sender_nonces.read().await.is_empty() {
            self.remove_transaction(&h).await;
        }
        {
            let n = self.sender_nonces.write().await;
        }
        let t2 = self.transactions.write().await;
        drop(t2);
        self.clear().await;
        // self.by_sender.read() then self.transactions.read() in a comment
        let msg = "self.by_sender.read() self.transactions.read()";
    }'
  [ $rc -eq 0 ] && echo "mempool lock-order tripwire self-test: ok"
  return $rc
}

if [ "${1:-}" = "--self-test" ]; then self_test; exit $?; fi
[ -n "${1:-}" ] && TARGET="$1"
if ! out="$(scan "$TARGET")"; then
  echo "$out"
  echo "mempool lock-order tripwire: FAILED (see the LOCK ORDER rule at the top of mempool.rs)"
  exit 1
fi
echo "mempool lock-order tripwire: clean"
