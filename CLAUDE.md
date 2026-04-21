# CLAUDE.md — citrate_v0.01.1

This file provides guidance to Claude Code when working within the `citrate_v0.01.1/` workspace.
For project-wide rules, see the root `CLAUDE.md`. For the Agentile framework, see `.agentile/AGENT_ENTRY.md`.

---

## 🚨 CRITICAL IMPLEMENTATION GUIDELINES

### No Mocks, Stubs, or Incomplete Implementations

**MANDATORY:** All code delivered MUST be fully functional and production-ready. Do NOT create:
- Mock implementations or placeholder functions
- TODO comments or stub methods
- Partial implementations that require "future completion"
- Test-only or demonstration code unless explicitly requested
- **Default constructors that silently use fake/test backends** (see THE_RULE_FOLLOWERS_PARADOX.md)

**The Wittgenstein Loophole:** An agent will create a type called `StubFooBackend`, rationalize it as "for testing," then wire it as the default in `Service::new()`. The result: production code silently returns fake data. This satisfies the surface pattern while violating the semantic property. To prevent this:
- Test-only types MUST be behind `#[cfg(test)]`
- `Service::new()` MUST use real backends (filesystem, network, chain)
- If the real backend can't be built yet, the service can't be created

**The "Real Backend" Loophole (discovered 2026-03-28):** An agent will name a type `RealXxxBackend` or `RpcXxxBackend` and give it methods that return hardcoded default data or empty vectors, then claim the service is "implemented." Examples:
- `EmbeddedNodeBackend.start_node()` that logs and returns `Ok(())` without starting anything
- `RpcLearningBackend.list_pools()` that returns a hardcoded `vec![PoolInfo { name: "Global Pool" }]` without querying any contract
- `RpcModelBackend.list_models()` that returns hardcoded model info without calling any RPC
- `RpcBlockBackend.get_block_transactions()` that returns `Vec::new()`

These pass the surface check (no `Stub` in the name, not behind `#[cfg(test)]`) but violate the semantic property (they don't connect to real data). To prevent this:
- **Every "real" backend method MUST name its data source** in a code comment: contract address, RPC method, or file path
- **Methods that return hardcoded data are stubs** regardless of the type name
- **Before claiming a service is "done," verify the data source exists and is reachable**
- **Acceptance criteria MUST name data sources** (Rule 11): "Dashboard shows block height from eth_blockNumber" not "Dashboard shows block height"

**The "Test Count" Loophole (discovered 2026-03-28):** An agent will optimize for test count (747 tests!) and TLA+ spec count (23 specs!) while the actual product doesn't work. Tests verify backend service logic in isolation. TLA+ verifies state machine properties. Neither verifies that the user can click a button and see a result. To prevent this:
- **Test count is necessary but not sufficient** — visual testing is required at every gate
- **Services with zero UI wiring don't count as "done"** — a service that passes 50 tests but has no callback chain from Slint → App → main.rs → service is incomplete
- **"Compiles" ≠ "works"** — a Slint component that renders but has no TouchArea callbacks is a visual mock
- **The definition of done includes "Larry can use it"** — not just "cargo test passes"

**REQUIREMENTS for all implementations:**
- **Complete functionality** - Every feature must work end-to-end
- **Proper error handling** - Handle all edge cases and error conditions
- **Production security** - Input validation, access controls, and secure patterns
- **Comprehensive testing** - Unit tests, integration tests, and validation
- **Full documentation** - API docs, usage examples, and clear explanations

#### Rule: Data Source Tracing (NEW)

Every IPC command or API endpoint MUST identify its data source BEFORE implementation:

| Step | Requirement | Gate |
|------|-------------|------|
| 1 | Name the on-chain contract + method (e.g., "LearningPool.getPool() via eth_call") | BLOCKER — cannot create IPC command without this |
| 2 | Implement the contract query/transaction code FIRST | BLOCKER |
| 3 | Write the IPC command wrapping the real call | — |
| 4 | Write an integration test verifying end-to-end data flow | GATE — WP cannot close without this |

**If the contract doesn't exist yet:**
- Write the contract FIRST (it's a dependency)
- If the contract can't be written this sprint, the IPC command CANNOT be created
- The frontend shows a loading/unavailable state, NOT fake data

**Mock budget: 0 per sprint. No exceptions.**

#### Rule: Zero Unwraps

**All code — production AND test — must have zero `.unwrap()` calls at each gate.**

| Context | Use Instead |
|---------|------------|
| Production code, Result | `?` operator or `match` with proper error handling |
| Production code, Option | `.ok_or_else(\|\| AppError::...)` then `?` |
| Production code, Mutex::lock | `.expect("mutex not poisoned")` or recover with `.unwrap_or_else` |
| Test code, Result | `.expect("descriptive context")` |
| Test code, Option | `.expect("descriptive context")` |
| Test code, error path | `.expect_err("expected error")` |

**Gate criterion:** `grep -rn '\.unwrap()' src/ tests/ | grep -v unwrap_or | wc -l` returns **0**.

**Why:** `.unwrap()` provides no context on failure. `.expect("msg")` tells you what went wrong. `?` propagates errors properly. In a blockchain wallet, a panic from `.unwrap()` in production means lost user trust. In tests, `.unwrap()` produces "called Option::unwrap on None" — useless for debugging. `.expect("wallet unlock should succeed")` tells you immediately what failed.

#### Acceptance Criteria Must Name Data Sources

Sprint WP acceptance criteria MUST specify WHERE the data comes from:

- BAD: "Dashboard shows earnings"
- GOOD: "Dashboard shows earnings from ContributionAccounting.sol via eth_call, verified by integration test"

If the acceptance criteria don't name a data source, the WP is incomplete.

#### Mock Registry (Transition Period)

For existing mocks being replaced:
1. All mocks are listed in `MOCKS.md` at the project root
2. Each mock has a replacement WP in the current or next sprint's backlog
3. Release builds fail if any mock exists without a registered replacement WP
4. `dev-mode` feature flag gates mock code for local development only

#### Verification

```bash
# Must return 0 results in release builds:
grep -rn "seed data\|mock\|hardcoded\|placeholder" src/ --include="*.rs" --include="*.ts"

# Rust mock gate (added to src-tauri/src/lib.rs or equivalent):
# #[cfg(not(feature = "allow-mocks"))]
# compile_error!("Production builds must not contain mocks. See MOCKS.md");
```

**On violation:** GATE. Sprint cannot close with unregistered mocks. Registered mocks must have replacement WPs.

**Background:** See `.agentile/docs/case_studies/MOCK_PERSISTENCE.md` for the full case study (Knight Capital $440M loss, TODO lifespan data, 6 persistence mechanisms).

#### Rule: Document Timestamps (Rule 12)

Every document created in this workspace MUST include frontmatter with `created`, `branch`, `author`, `status` fields. See `.agentile/rules/CORE_RULES.md` Rule 12 for the full specification. Documents without frontmatter are pre-rule historical artifacts — do not treat them as current guidance.

#### Rule: Document Authority Hierarchy

Document authority follows tiers (see `.agentile/AGENT_ENTRY.md`):
- **Tier 1**: CONFIG.md, PRODUCT_SPEC.md, CORE_RULES.md — canonical constants, product definition, operating rules
- **Tier 2**: CURRENT.md, formal/specs/INDEX.md — live status, spec inventory
- **Tier 3**: Crate READMEs, guides — usage and procedures

When documents disagree, the higher tier wins. If a feature is not in PRODUCT_SPEC.md, it is out of scope.

---

## Build & Test Commands

```bash
# Build entire workspace
cargo build --release

# Run all tests
cargo test --workspace

# Lint (must pass clean)
cargo clippy --all-targets --all-features -D warnings

# Format
cargo fmt --all

# GUI tests (Slint-native)
cargo test -p citrate-gui-native
# Visual proof suite
scripts/run_gui_visual_proofs.sh

# Forge tests
cd contracts && forge test
```

## Benchmark Requirement

Every work session touching core crates (consensus, execution, storage, api, sequencer, network) MUST end with a benchmark run:

```bash
cd tests/load
./target/release/benchmark-suite http://127.0.0.1:8545 10000 60 ../../benchmarks/
```

Baselines:
- **Network baseline (March 20, 2026)**: 5,000 TPS sustained, 10,000 TPS ceiling via
  `benchmark-suite` (HTTP RPC to a live node).
- **Executor ceiling (April 21, 2026, Sprint P950-A-5)**: 773K tx/s @ 8 workers,
  321K tx/s @ 1 worker on disjoint-senders workload
  (`benches/tps_parallel.rs`). The journal + CAS path achieves 2.41× speedup
  from 1 → 8 workers. Real-world TPS is RPC/signature-bound and sits well
  below this ceiling; closing the gap is tracked separately.

Regression policy: >10% regression on EITHER baseline blocks the commit.
