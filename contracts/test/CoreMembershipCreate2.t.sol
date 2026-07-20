// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "../script/Salts.sol";
import {CitrateMemberSBT} from "../src/core_membership/CitrateMemberSBT.sol";
import {MembershipStakeVault} from "../src/core_membership/MembershipStakeVault.sol";
import {LiquidStakingPool} from "../src/LiquidStakingPool.sol";

/// @title CoreMembershipCreate2Test — WS-1 reroll-freeze tripwire.
///
/// Mirrors Create2Determinism.t.sol for the two core-membership money-path
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
///      pinned as literals. WS-2 changed CitrateMemberSBT's bytecode, moving
///      the SBT address; these pins capture the NEW frozen addresses. Any
///      future bytecode drift (SBT or vault) or constructor-arg change moves
///      the init_code hash → address, and this test fails BEFORE a reroll
///      deploys to an unexpected address.
///
/// NB: in a forge TEST `new X{salt:}` deploys via CREATE2 from `address(this)`,
/// not the genesis Arachnid proxy that forge SCRIPTS use. Layer 1 therefore
/// uses `address(this)` as deployer; layer 2 recomputes the real Arachnid
/// projection explicitly.
contract CoreMembershipCreate2Test is Test {
    // Determinism inputs — PINNED, identical to DeployCoreMembership.s.sol.
    address internal constant ARACHNID = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    address internal constant DEFAULT_POOL = 0xFD272195B55Cb4F5A240a5bE75AABaB0D1C5685E;
    // ROTATED 2026-07-20 with the deployer — see DeployCoreMembership.s.sol.
    address internal constant FROZEN_OWNER = 0xF42a19194fee89E71dC4b8631a71a9CeCf42B483;

    // Frozen projections (Arachnid deployer). Re-pinned 2026-07-20 for the
    // deployer/owner rotation (FROZEN_OWNER → new grant signer).
    address internal constant SBT_FROZEN = 0x3e0c2B1cD29a615E4eA2E263C8e7df3Aef243E42;
    address internal constant VAULT_FROZEN = 0x61E324cFd6B7Cb106AC0AD1dF163bdFef2b74268;

    // init_code hashes = keccak256(creationCode ++ abi.encode(ctorArgs)).
    bytes32 internal constant SBT_INIT_HASH =
        0x15db7207cbfa5e97d671a3f53aaacf60c4fb04fe70129b782f152a6ea54aa08c;
    bytes32 internal constant VAULT_INIT_HASH =
        0x234d1004c881a86019bfbc32729a1eb54b40f65c56129049a1afb06e6e660d15;

    function _sbtInit() internal pure returns (bytes memory) {
        return abi.encodePacked(type(CitrateMemberSBT).creationCode, abi.encode(FROZEN_OWNER));
    }

    function _vaultInit() internal pure returns (bytes memory) {
        return abi.encodePacked(
            type(MembershipStakeVault).creationCode,
            abi.encode(FROZEN_OWNER, LiquidStakingPool(payable(DEFAULT_POOL)))
        );
    }

    // ── Layer 1: the deploy is CREATE2 (nonce-independent). ────────────

    function test_sbt_is_create2() public {
        CitrateMemberSBT sbt =
            new CitrateMemberSBT{salt: Salts.salt("CitrateMemberSBT")}(FROZEN_OWNER);
        address expected = vm.computeCreate2Address(
            Salts.salt("CitrateMemberSBT"), keccak256(_sbtInit()), address(this)
        );
        assertEq(address(sbt), expected, "SBT deploy is not CREATE2 / wrong salt");
    }

    function test_vault_is_create2() public {
        MembershipStakeVault vault = new MembershipStakeVault{
            salt: Salts.salt("MembershipStakeVault")
        }(FROZEN_OWNER, LiquidStakingPool(payable(DEFAULT_POOL)));
        address expected = vm.computeCreate2Address(
            Salts.salt("MembershipStakeVault"), keccak256(_vaultInit()), address(this)
        );
        assertEq(address(vault), expected, "vault deploy is not CREATE2 / wrong salt");
    }

    // ── Layer 2: the frozen Arachnid projections don't move. ───────────

    function test_sbt_init_hash_frozen() public pure {
        assertEq(keccak256(_sbtInit()), SBT_INIT_HASH, "SBT init_code hash drifted (bytecode/args)");
    }

    function test_vault_init_hash_frozen() public pure {
        assertEq(keccak256(_vaultInit()), VAULT_INIT_HASH, "vault init_code hash drifted");
    }

    function test_sbt_frozen_projection() public pure {
        address projected = vm.computeCreate2Address(
            Salts.salt("CitrateMemberSBT"), SBT_INIT_HASH, ARACHNID
        );
        assertEq(projected, SBT_FROZEN, "SBT frozen address moved");
    }

    function test_vault_frozen_projection() public pure {
        address projected = vm.computeCreate2Address(
            Salts.salt("MembershipStakeVault"), VAULT_INIT_HASH, ARACHNID
        );
        assertEq(projected, VAULT_FROZEN, "vault frozen address moved");
    }

    /// Distinct salts (no accidental collision between the two contracts).
    function test_salts_distinct() public pure {
        assertTrue(
            Salts.salt("CitrateMemberSBT") != Salts.salt("MembershipStakeVault"),
            "salt collision"
        );
    }
}
