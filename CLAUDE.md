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

# GUI tests
cd gui/citrate_gui_v2 && npx vitest run

# Forge tests
cd contracts && forge test
```

## Benchmark Requirement

Every work session touching core crates (consensus, execution, storage, api, sequencer, network) MUST end with a benchmark run:

```bash
cd tests/load
./target/release/benchmark-suite http://127.0.0.1:8545 10000 60 ../../benchmarks/
```

Baseline (March 20, 2026): 5,000 TPS sustained, 10,000 TPS ceiling. >10% regression blocks the commit.
