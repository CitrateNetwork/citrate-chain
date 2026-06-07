// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Kernel} from "@kernel/Kernel.sol";
import {IEntryPoint} from "@kernel/interfaces/IEntryPoint.sol";

/**
 * @title CitrateWallet — Citrate's ERC-4337 v0.7 / ERC-7579 modular account
 * @notice Thin Citrate-branded adapter over ZeroDev's audited Kernel v3.3
 *         (MIT) wallet implementation. The factory (`CitrateWalletFactory`)
 *         deploys ERC-1967 minimal proxies that delegate-call into a single
 *         deployment of this contract; each user smart wallet is one such
 *         proxy.
 *
 *         The Kernel v3 surface is preserved unchanged so our validators
 *         (`WebAuthnP256Validator`, `CitrateECDSAValidator`) and recovery
 *         module (`GuardianRecoveryModule`) — all of which speak the
 *         ERC-7579 module ABI — install + execute byte-identically to
 *         upstream tests.
 *
 *         **Domain separation:** EIP-712 signatures issued by a Citrate
 *         wallet are already domain-separated from upstream Kernel
 *         deployments by `verifyingContract` (the proxy address) +
 *         `chainId` per the EIP-712 spec. We do NOT override
 *         `_domainNameAndVersion()` — upstream marks it as a final
 *         override of Solady's `EIP712._domainNameAndVersion`, and the
 *         override-path benefit would be purely cosmetic given the
 *         address + chain-id separation is already enforced.
 *
 *         **What this adapter buys us:**
 *           - A Citrate-named symbol in the deployment artifacts +
 *             explorer + bundler logs (operators see `CitrateWallet`,
 *             not the upstream name).
 *           - A stable extension point: when we later add Citrate-
 *             specific state (e.g. on-chain KYC-status pointer per
 *             ADR-2026-06-05-ew-paymaster-policy), it lands here
 *             without touching the vendored submodule.
 *           - Patch isolation from upstream: future Kernel patches
 *             arrive via the submodule; our Citrate-specific code
 *             stays in this single file.
 *
 *         Upstream license: MIT (ZeroDev 2023). License notice preserved
 *         in `contracts/lib/kernel/LICENSE.txt` and per-source SPDX
 *         headers.
 *
 *         **Storage-slot reservation:** intentionally NONE here at the
 *         struct level — Kernel uses explicit assembly storage slots
 *         (see `contracts/lib/kernel/src/storage/`) for upgradeability,
 *         and any Citrate-specific state will use its own assembly
 *         slot constants to avoid colliding with the upstream layout.
 *         If you add Citrate-specific state to this contract, declare
 *         a constant `bytes32 CITRATE_STORAGE_SLOT` keyed via
 *         `keccak256("citrate.wallet.v1.<field>") - 1` per the
 *         ERC-1967-style pattern.
 */
contract CitrateWallet is Kernel {
    /// @dev Upstream constructor takes the EntryPoint v0.7 address as
    ///      `immutable`; we pass it through. The implementation contract
    ///      itself is deployed once; users get ERC-1967 proxies.
    constructor(IEntryPoint _entrypoint) Kernel(_entrypoint) {}
}
