// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../script/Salts.sol";
import {CitrateMemberSBT} from "../src/core_membership/CitrateMemberSBT.sol";
import {MemberBond} from "../src/core_membership/MemberBond.sol";
import {MembershipStakeVault} from "../src/core_membership/MembershipStakeVault.sol";
import {ValidatorRegistry} from "../src/ValidatorRegistry.sol";

/// @title CoreMembershipCreate2Test — WS-1 reroll-freeze tripwire.
///
/// Mirrors Create2Determinism.t.sol for the core-membership money-path
/// contracts. Two layers of regression teeth:
///
///   1. CREATE2 usage: an in-test `new X{salt:…}(…)` lands at
///      `computeCreate2Address(salt, keccak256(initCode), address(this))`. If
///      anyone reverts `DeployCoreMembership` back to plain `new X(…)`, the
///      resulting CREATE (nonce-dependent) address stops matching and this
///      test fails — so the address-scramble bug cannot silently return.
///
///   2. Frozen projection: the Arachnid-factory (0x4e59…4956C) projections —
///      the ACTUAL on-chain addresses `DeployCoreMembership` produces — are
///      pinned as literals. Any bytecode drift or constructor/initializer-arg
///      change moves the init_code hash → address, and this test fails BEFORE
///      a reroll deploys to an unexpected address.
///
/// ## RE-PINNED FOR M-2 (2026-07-29)
///
/// Every address here MOVED, deliberately, and this is what moved them:
///
///   - `CitrateMemberSBT` gained the `kycVerified` flag (M-2.3), changing its
///     bytecode.
///   - `MembershipStakeVault` stopped depositing into `LiquidStakingPool` and
///     became UUPS (M-2.0 + M-2.1). It now has NO constructor args, and the
///     address the federation pins is the **ERC1967 proxy**, not the
///     implementation.
///   - `MemberBond` is new.
///
/// The dependency chain is real and is asserted below: the proxy's init_code
/// embeds its initialize calldata, which embeds the SBT, MemberBond and
/// REGISTRY addresses. Change any of those and the vault address moves.
///
/// This is the LAST time the vault address moves. Under UUPS every later change
/// is an in-place upgrade behind the proxy — that is the payoff for doing
/// M-2.0 before M-2.1 so the storage layout froze once.
contract CoreMembershipCreate2Test is Test {
    // Determinism inputs — PINNED, identical to DeployCoreMembership.s.sol.
    address internal constant ARACHNID = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    address internal constant FROZEN_OWNER = 0xF42a19194fee89E71dC4b8631a71a9CeCf42B483;
    address internal constant REGISTRY = 0x61D44D8A14443646B756905410BE951e6eCE95A6;

    // ── init_code builders (keccak256(creationCode ++ abi.encode(ctorArgs))) ──

    function _sbtInit() internal pure returns (bytes memory) {
        return abi.encodePacked(type(CitrateMemberSBT).creationCode, abi.encode(FROZEN_OWNER));
    }

    function _bondInit() internal pure returns (bytes memory) {
        return type(MemberBond).creationCode; // no constructor args
    }

    function _vaultImplInit() internal pure returns (bytes memory) {
        return type(MembershipStakeVault).creationCode; // no constructor args
    }

    // ── Arachnid projections, derived (not hand-copied) ──────────────────

    function _sbtAddr() internal pure returns (address) {
        return vm.computeCreate2Address(
            Salts.salt("CitrateMemberSBT"), keccak256(_sbtInit()), ARACHNID
        );
    }

    function _bondAddr() internal pure returns (address) {
        return vm.computeCreate2Address(
            Salts.salt("MemberBond"), keccak256(_bondInit()), ARACHNID
        );
    }

    function _vaultImplAddr() internal pure returns (address) {
        return vm.computeCreate2Address(
            Salts.salt("MembershipStakeVault.impl"), keccak256(_vaultImplInit()), ARACHNID
        );
    }

    /// The proxy init_code — this is where the whole dependency chain lands.
    function _proxyInit() internal pure returns (bytes memory) {
        return abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(
                _vaultImplAddr(),
                abi.encodeCall(
                    MembershipStakeVault.initialize,
                    (
                        FROZEN_OWNER,
                        ValidatorRegistry(payable(REGISTRY)),
                        CitrateMemberSBT(_sbtAddr()),
                        _bondAddr()
                    )
                )
            )
        );
    }

    function _vaultAddr() internal pure returns (address) {
        return vm.computeCreate2Address(
            Salts.salt("MembershipStakeVault"), keccak256(_proxyInit()), ARACHNID
        );
    }

    // ── Layer 1: the deploys are CREATE2 (nonce-independent). ────────────

    function test_sbt_is_create2() public {
        CitrateMemberSBT sbt =
            new CitrateMemberSBT{salt: Salts.salt("CitrateMemberSBT")}(FROZEN_OWNER);
        address expected = vm.computeCreate2Address(
            Salts.salt("CitrateMemberSBT"), keccak256(_sbtInit()), address(this)
        );
        assertEq(address(sbt), expected, "SBT deploy is not CREATE2 / wrong salt");
    }

    function test_memberBond_is_create2() public {
        MemberBond bond = new MemberBond{salt: Salts.salt("MemberBond")}();
        address expected = vm.computeCreate2Address(
            Salts.salt("MemberBond"), keccak256(_bondInit()), address(this)
        );
        assertEq(address(bond), expected, "MemberBond deploy is not CREATE2 / wrong salt");
    }

    function test_vaultImpl_is_create2() public {
        MembershipStakeVault impl =
            new MembershipStakeVault{salt: Salts.salt("MembershipStakeVault.impl")}();
        address expected = vm.computeCreate2Address(
            Salts.salt("MembershipStakeVault.impl"), keccak256(_vaultImplInit()), address(this)
        );
        assertEq(address(impl), expected, "vault impl deploy is not CREATE2 / wrong salt");
    }

    // ── Layer 2: the frozen Arachnid projections don't move. ─────────────
    //
    // Pinned literals, regenerated 2026-07-29 for M-2. If one of these fails,
    // read the diff before touching the number: it means the deployed bytecode
    // changed, and the federation's address book, the desktop app's compile-time
    // pins and the droplet signer env all have to move with it.

    address internal constant SBT_FROZEN = 0xAD826D0439f7ad5a3512A8927B632Cbca2840e10;
    address internal constant BOND_FROZEN = 0x394660A2d48DB86c04B5838c7117E2D4B5DE4513;
    address internal constant VAULT_IMPL_FROZEN = 0xCd59F9c2d8cD1D41f2F4911b5a171C62F1b6bEA8;
    address internal constant VAULT_FROZEN = 0x04c32967816187B2efDcd4937DbBa59E051F99dB;

    function test_sbt_frozen_projection() public pure {
        assertEq(_sbtAddr(), SBT_FROZEN, "SBT frozen address moved");
    }

    function test_memberBond_frozen_projection() public pure {
        assertEq(_bondAddr(), BOND_FROZEN, "MemberBond frozen address moved");
    }

    function test_vaultImpl_frozen_projection() public pure {
        assertEq(_vaultImplAddr(), VAULT_IMPL_FROZEN, "vault implementation frozen address moved");
    }

    function test_vault_frozen_projection() public pure {
        assertEq(_vaultAddr(), VAULT_FROZEN, "vault proxy frozen address moved");
    }

    // ── The dependency chain is real, and must stay visible. ─────────────

    /// The vault proxy address depends on the SBT and MemberBond addresses
    /// through its initialize calldata. If someone "simplifies" initialize to
    /// stop taking them, this stops being true and the freeze story silently
    /// weakens — the proxy would no longer move when its dependencies do.
    function test_vaultAddressDependsOnItsDependencies() public pure {
        bytes memory withReal = _proxyInit();
        bytes memory withOther = abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(
                _vaultImplAddr(),
                abi.encodeCall(
                    MembershipStakeVault.initialize,
                    (
                        FROZEN_OWNER,
                        ValidatorRegistry(payable(REGISTRY)),
                        CitrateMemberSBT(address(0xdead)), // a different SBT
                        _bondAddr()
                    )
                )
            )
        );
        assertTrue(
            keccak256(withReal) != keccak256(withOther),
            "the vault proxy address must move when its SBT dependency moves"
        );
    }

    /// Distinct salts (no accidental collision between the four contracts).
    function test_salts_distinct() public pure {
        bytes32 a = Salts.salt("CitrateMemberSBT");
        bytes32 b = Salts.salt("MembershipStakeVault");
        bytes32 c = Salts.salt("MemberBond");
        bytes32 d = Salts.salt("MembershipStakeVault.impl");
        assertTrue(a != b && a != c && a != d, "salt collision");
        assertTrue(b != c && b != d, "salt collision");
        assertTrue(c != d, "salt collision");
    }
}
