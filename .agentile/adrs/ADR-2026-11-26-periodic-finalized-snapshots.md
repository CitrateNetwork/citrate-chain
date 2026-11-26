---
created: 2026-11-26T00:00:00Z
branch: docs/500-periodic-snapshot-adr
author: Sisyphus (OpenCode), for issue #500
status: proposed
repo: citrate-chain
adr: ADR-2026-11-26-periodic-finalized-snapshots
issue: "#500"
parent_issue: "#498, Workstream B"
related_pr: "#499, separate Workstream A slice"
---

# ADR-2026-11-26: Periodic finalized snapshot bootstrap

## Status and authority

**Proposed.** This ADR is the design and security gate for [issue #500](https://github.com/CitrateNetwork/citrate-chain/issues/500), `sync: specify periodic finalized snapshot bootstrap`. It does not approve a trust root, signer set, quorum, file format, release process, implementation, or mainnet claim. Source changes remain unauthorized until the applicable approval gates below are satisfied.

Issue #500 is a child of [#498](https://github.com/CitrateNetwork/citrate-chain/issues/498), Workstream B. [PR #499](https://github.com/CitrateNetwork/citrate-chain/pull/499) is the separate Workstream A slice, not this snapshot-bootstrap design.

## Problem

A node that starts from block zero must replay the full chain before it can serve current state. The desired eventual behavior is an occasional artifact that lets a node begin from an accepted finalized height `H`, verify it before use, atomically activate it, and then validate ordinary peer-supplied history from `H + 1` through the current tip. Block-zero peer sync remains the mandatory fallback.

The artifact must not turn distribution trust into consensus trust. Nor may it weaken finality, ancestry, validator signing protection, durability, or the recovery guarantees already used by the node.

## Current facts and constraints

* On r1007, the canonical state commitment is the Ethereum-compatible MPT root committed by the canonical block post-state. See [`docs/consensus/STATE_ROOT_MPT.md`](../../docs/consensus/STATE_ROOT_MPT.md). A snapshot root must be checked against the selected block's canonical commitment, not merely against a publisher assertion.
* Checkpoint finality is specified, but it is not currently authoritative or running in production. [`docs/consensus/CHECKPOINT_FINALITY_WIRING.md`](../../docs/consensus/CHECKPOINT_FINALITY_WIRING.md) says no production path currently proposes, selects a committee, signs, or broadcasts checkpoint votes. Therefore an artifact cannot silently assume that a live checkpoint certificate is an available finalized trust anchor.
* [`node/src/cold_resync.rs`](../../node/src/cold_resync.rs) is a peer-driven local database move-aside and rebuild from genesis. It is not a portable snapshot mechanism. Its journal, durable writes, recovery ordering, and refusal to start after incomplete signed-vote carry are reusable safety patterns, not a finished import design.
* `StateStore::create_snapshot` is an in-database account-record helper. It does not create a consistent portable artifact, include all required state, bind data to chain history, verify a manifest, or activate an imported database.
* [`core/storage/src/signed_votes.rs`](../../core/storage/src/signed_votes.rs) exports, binds, merges, durably imports, and read-backs signed-vote records. Together with cold-resync, it establishes the required protection pattern for any validator database replacement or import.
* At-rest encryption, RocksDB format behavior, filesystem locking, atomic replacement semantics, and the release/distribution path are unresolved. An orderly rename alone does not prove crash safety, especially across volumes or platforms.

## Goals

1. Permit an optional, periodic bootstrap artifact at an accepted finalized height `H`.
2. Verify chain identity, finality authority, artifact integrity, compatibility, resource limits, and state commitment before activation.
3. Restore and activate only through a crash-recoverable, atomic-or-fail-safe local transition, then validate peer history from `H + 1` to tip under ordinary block and ancestry rules.
4. Retain block-zero peer sync as a supported fallback and recovery path.
5. Fail closed whenever finality, trust, integrity, compatibility, space limits, or ancestry cannot be established.

## Non-goals and claim boundaries

This ADR does not implement snapshots, change block validity or fork choice, make checkpoint finality authoritative, select any signing or quorum policy, promise a raw database format is portable, or authorize automatic import. A distribution signature proves only the approved release/distribution statement for its key policy. It is not proof of consensus correctness. A successful import proves only the checks actually performed; it must not be described as mainnet-safe until the mainnet evidence gate passes.

## Decision questions, alternatives, and recommendation subject to approval

### D1. Finalized trust anchor and correctness layers

**Alternatives:** (a) a verified, authoritative checkpoint certificate bound to `(chain_id, genesis, H, block_hash)`; (b) a release-controlled checkpoint assertion; (c) an artifact publisher signature alone; (d) no snapshot import until checkpoint finality is authoritative.

**Tradeoff:** (a) can establish a consensus-layer anchor only after finality wiring, activation, and independent verification are approved. (b) and (c) may authenticate a release but cannot independently establish consensus finality. (d) is safest now but delays bootstrap benefit.

**Recommendation, subject to approval:** permit snapshot activation only when an importer independently verifies an authoritative finalized trust anchor and binds it to the canonical block and state commitment. Until that exists, do not ship a path that labels a snapshot finalized. Keep consensus correctness, artifact integrity, and release/distribution authenticity as separate mandatory checks.

### D2. Signer, quorum, lifecycle, and downgrade policy

**Alternatives:** single release signer, threshold release quorum, or no publisher signatures beyond digest transport. Each can be combined with an authoritative finality certificate once available.

**Tradeoff:** thresholds reduce a single-key failure but add key rotation, revocation, expiry, recovery, and operational complexity. A single signer simplifies operations but concentrates risk.

**Recommendation, subject to security and release approval:** require a versioned policy that identifies signers or quorum, signature domain separation, rotation, revocation, expiry, provenance, anti-downgrade floor, and the response to unavailable policy metadata. Import must reject missing quorum, revoked or expired credentials, unknown policy versions, and artifacts below the local approved minimum. The actual signer set and quorum remain unresolved.

### D3. Payload representation and scope

**Alternatives:**

1. Logical portable payload, canonical records exported independently of RocksDB internals.
2. Raw RocksDB checkpoint or file copy.
3. Hybrid, a logical authoritative payload plus optional database-specific acceleration cache.

**Tradeoff:** logical data is more portable and independently verifiable but may cost export/import time. Raw RocksDB may be fast only within tightly controlled versions, filesystems, and encryption settings. It is not portable by default. A hybrid adds complexity and must never make an optional cache authoritative.

**Recommendation, subject to storage approval:** prefer a logical portable authoritative payload with explicit canonical encoding and versioned semantics. Treat raw RocksDB data, if later accepted, as a constrained optimization that must be separately verified against the logical commitment and rejected outside its declared compatibility range.

The implementation design must enumerate included data, excluded reconstructible indexes and caches, canonical ordering, account and storage encodings, code, trie material if needed, block/header and finalized-anchor material, and all schema/database versions. It must also state how encryption-at-rest affects export, staging, key access, local artifact confidentiality, and backup retention. No key material belongs in an artifact or manifest.

### D4. Manifest, compatibility, publication, and retention

**Alternatives:** JSON, canonical CBOR, protobuf, or another deterministic versioned encoding; one publisher, mirrored immutable objects, or peer distribution.

**Tradeoff:** human-readable JSON needs an explicit canonicalization rule before signatures. Binary encodings can be deterministic but need independent parser and compatibility tests. Mirrors improve availability but expand supply-chain and retention responsibilities.

**Recommendation, subject to owner, security, and release approval:** define one canonical, versioned manifest encoding before any exporter. It must include at least:

* chain/network ID and genesis hash;
* finalized height and block hash;
* state root or equivalent canonical state commitment;
* artifact digest and byte size;
* snapshot format, schema, and database versions;
* exporter source SHA and importer-supported version range;
* creation timestamp, expiry, and anti-downgrade ordering data;
* signatures, signer policy identifier, and quorum evidence;
* compression/archive algorithm, decoded-size, file-count, and extraction limits;
* optional certificate and provenance links.

The publication plan must identify authority, immutable naming, mirrors, retention period, deletion and revocation behavior, availability expectations, and how an offline or stale mirror is handled. Missing or unverifiable manifest fields fail closed.

### D5. Import, recovery, and platform behavior

**Alternatives:** explicit operator-only import, opt-in automatic import with confirmation, or automatic bootstrap by default.

**Tradeoff:** explicit import limits surprise and operator risk. Automatic import reduces friction but expands the remote attack and support surface. No option can bypass verification.

**Recommendation, subject to release/operator approval:** start with explicit, operator-visible import after all verification succeeds. A later opt-in automatic mode requires separate approval and evidence.

Import must stage outside the active database, verify before activation, journal every durable phase, detect an existing or open destination, preserve an intact rollback target, and recover deterministically after interruption. It must document and test same-volume atomic activation, cross-volume refusal or copy-and-verify behavior, Windows file-lock and rename behavior, parent-directory durability where supported, and the exact fallback where platform guarantees are weaker. The cold-resync journal is a model for ordering and refusal, not proof that the new protocol is safe.

For validators, signed-vote protection is mandatory: either carry and verify the bound record before any signing can occur, or use an owner-approved key rotation/re-registration policy. Omission, conflict, unreadability, or failed read-back must block activation and validator start.

### D6. Post-import ancestry and catch-up

**Alternatives:** trust the artifact as tip, fetch only headers after `H`, or independently validate normal peer blocks from `H + 1` through tip.

**Recommendation, subject to chain-owner approval:** after activation, require the imported `(H, block_hash, state_root)` to be on the locally verified finalized anchor, then run normal peer validation and canonical ancestry checks for `H + 1..tip`. Conflicting peers, absent ancestry, or a block that cannot connect to `H` must not advance the imported state. Block-zero sync remains available when this cannot complete.

## Rejection criteria

The importer must refuse without activating the candidate when any required check fails, including unknown chain/genesis, incompatible format or importer range, missing authoritative finality proof, state-root mismatch, digest or size mismatch, signature-policy failure, stale or downgraded artifact, expired manifest, unsafe archive structure, resource-limit breach, insufficient disk space, active destination lock, incomplete journal, missing validator vote carry, unprovable ancestry, or unsupported platform activation path. Refusal must retain enough non-secret diagnostic evidence for operators and must not overwrite a working database.

## Staged implementation boundaries

1. **ADR approval only.** Resolve D1 through D6, owners, threat model, and gates. No source implementation.
2. **Manifest, types, verifier.** Add deterministic manifest/types and an independent verifier that fails closed. No importer activation.
3. **Consistent exporter.** Produce a bounded, reproducible artifact at a verified anchor with provenance and integrity evidence.
4. **Fail-safe importer and recovery.** Add staging, verification, journaling, rollback, signed-vote safeguards, and platform-specific behavior.
5. **Publisher, retention, revocation.** Implement approved publication, mirror, retention, signer lifecycle, and revocation procedures.
6. **Cross-platform packaged and live import-to-tip verification.** Test supported operating systems, including Windows, using artifacts imported to `H` and normally validated to tip.
7. **Comparative benchmark against block-zero sync.** Measure time, bandwidth, CPU, disk, and failure recovery against a defined block-zero baseline.

Each phase is separately reviewable. Advancing a phase does not approve the next one.

## Approval and evidence gates

### Gate A, before coding: design authorization

All named approvers must record approval of this ADR and the selected D1 through D6 values:

| Approver | Required evidence |
|---|---|
| Chain owner | Finalized-anchor semantics, canonical `(H, hash, root)` binding, post-import `H + 1..tip` validation, and block-zero fallback are accepted. |
| Security owner | Threat model, signer/quorum lifecycle, revocation and anti-downgrade policy, archive/resource limits, encryption posture, and validator vote-protection policy are accepted. |
| Storage owner | Payload scope, canonical encoding, schema/database compatibility, staging/recovery journal, durability assumptions, and rollback behavior are accepted. |
| Release/operator owner | Publisher/mirror/retention plan, operator UX, explicit-import policy, supported platforms, disk requirements, and incident playbook are accepted. |
| Independent verifier | A review plan confirms that finality, state-root, artifact integrity, and activation claims can be checked independently from the exporter. |

### Gate B, before merge: implementation evidence

The implementing PR set must provide all of the following, reviewed by the same roles:

* Specification and test vectors for canonical manifest encoding, signature domain, compatibility decisions, and every required manifest field.
* Independent verification of chain ID, genesis, finalized anchor, block hash, state root, digest, signatures/quorum, version ranges, expiry, downgrade policy, compression limits, and payload completeness.
* Deterministic exporter evidence that identifies the source SHA and produces equivalent verified output from the same accepted source state.
* Import-recovery evidence proving journaled behavior and preservation of the prior database under each specified crash point and platform path.
* Validator evidence that signed-vote carry is bound to chain, genesis, and validator, merged conflict-safely, durably imported and read back before signing, or that an approved rotation path blocks old-key signing.
* Packaged supported-platform tests, with Windows-specific lock, rename, cross-volume, and durability behavior recorded rather than assumed.

### Gate C, before mainnet claims: operational proof

The chain owner, security owner, storage owner, release/operator owner, and independent verifier must approve a signed evidence record containing: a live or representative finalized anchor under the approved policy; end-to-end export, publication, mirror retrieval, verification, explicit import, restart recovery, and validated catch-up from `H + 1` to tip; revocation and downgrade drills; disk-exhaustion and interrupted-import drills; validator protection drills; cross-platform packaged results; monitoring and operator runbook; and a comparative benchmark against block-zero sync. No result may be called mainnet-ready or mainnet-safe before this gate.

## Adversarial test matrix

| Scenario | Required result |
|---|---|
| Artifact or manifest tampering | Digest/signature/root verification fails before activation. |
| Wrong chain, genesis, block hash, or state root | Refuse without changing active state. |
| Stale, expired, or downgraded artifact | Enforce approved expiry and anti-downgrade policy, then refuse. |
| Revoked signer, missing quorum, or unknown signer policy | Refuse. |
| Truncation or inconsistent declared size | Refuse before extraction or activation. |
| Archive traversal, duplicate paths, symlinks, bombs, or limit violations | Refuse without writes outside staging. |
| Disk exhaustion at download, staging, verification, activation, or rollback | Fail closed, preserve a recoverable active or rollback state. |
| Crash at every journal phase | Restart resumes safely or refuses with intact recovery evidence. |
| Destination exists or is open | Detect lock/state and refuse rather than race or overwrite. |
| Cross-volume activation | Use the explicitly tested safe path or refuse. |
| Conflicting peers after import | Do not advance past unprovable ancestry; normal validation decides or bootstrap fails. |
| Validator vote-carry omission, corruption, conflict, or wrong binding | Block validator activation/signing and preserve evidence. |

## References

This ADR links to existing sources rather than reproducing their specifications, consistent with Rule 9.

* [Issue #500](https://github.com/CitrateNetwork/citrate-chain/issues/500), periodic finalized snapshot bootstrap.
* [Parent issue #498](https://github.com/CitrateNetwork/citrate-chain/issues/498), Workstream B, and [PR #499](https://github.com/CitrateNetwork/citrate-chain/pull/499), separate Workstream A.
* [PR #478](https://github.com/CitrateNetwork/citrate-chain/pull/478), [PR #483](https://github.com/CitrateNetwork/citrate-chain/pull/483), [PR #486](https://github.com/CitrateNetwork/citrate-chain/pull/486), and [PR #490](https://github.com/CitrateNetwork/citrate-chain/pull/490).
* [`docs/consensus/STATE_ROOT_MPT.md`](../../docs/consensus/STATE_ROOT_MPT.md), canonical r1007 state-root definition and fast-sync status.
* [`docs/consensus/CHECKPOINT_FINALITY_WIRING.md`](../../docs/consensus/CHECKPOINT_FINALITY_WIRING.md), specified checkpoint finality and signed-vote protection.
* [`node/src/cold_resync.rs`](../../node/src/cold_resync.rs), peer-driven rebuild, vote carry, and journal safety pattern.
* [`core/storage/src/signed_votes.rs`](../../core/storage/src/signed_votes.rs), bound durable signed-vote record export/import.
* [`docs/ops/REHEARSAL_1_EXPORT.md`](../../docs/ops/REHEARSAL_1_EXPORT.md), manifest, provenance, integrity, staging, and handoff practices.
