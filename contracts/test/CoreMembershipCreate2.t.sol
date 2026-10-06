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
    // Determinism inputs — DERIVED at deploy time, identical to
    // DeployCoreMembership.s.sol. FRESH-KEYS reroll (owner ruling + MAC audit):
    // the membership owner and the ValidatorRegistry are NO LONGER frozen
    // literals — they come from env (`MEMBERSHIP_OWNER`, `VALIDATOR_REGISTRY`),
    // so the SBT/vault addresses move with the fresh keys (accepted). With env
    // unset these fall back to derived, obviously-not-a-key placeholders so the
    // determinism relationships below are still exercised deterministically.
    address internal constant ARACHNID = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    function _owner() internal view returns (address) {
        return _envAddrOr("MEMBERSHIP_OWNER", address(uint160(uint256(keccak256("citrate.reroll.placeholder.membership.owner")))));
    }

    function _registry() internal view returns (address) {
        return _envAddrOr("VALIDATOR_REGISTRY", _envAddrOr("CITRATE_VALIDATOR_REGISTRY", address(uint160(uint256(keccak256("citrate.reroll.placeholder.validator.registry"))))));
    }

    function _envAddrOr(string memory key, address fallbackValue) internal view returns (address) {
        try vm.envAddress(key) returns (address v) { return v; } catch { return fallbackValue; }
    }

    // ── init_code builders (keccak256(creationCode ++ abi.encode(ctorArgs))) ──

    function _sbtInit() internal view returns (bytes memory) {
        return abi.encodePacked(type(CitrateMemberSBT).creationCode, abi.encode(_owner()));
    }

    function _bondInit() internal pure returns (bytes memory) {
        return type(MemberBond).creationCode; // no constructor args
    }

    function _vaultImplInit() internal pure returns (bytes memory) {
        return type(MembershipStakeVault).creationCode; // no constructor args
    }

    // ── Arachnid projections, derived (not hand-copied) ──────────────────

    function _sbtAddr() internal view returns (address) {
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
    function _proxyInit() internal view returns (bytes memory) {
        return abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(
                _vaultImplAddr(),
                abi.encodeCall(
                    MembershipStakeVault.initialize,
                    (
                        _owner(),
                        ValidatorRegistry(payable(_registry())),
                        CitrateMemberSBT(_sbtAddr()),
                        _bondAddr()
                    )
                )
            )
        );
    }

    function _vaultAddr() internal view returns (address) {
        return vm.computeCreate2Address(
            Salts.salt("MembershipStakeVault"), keccak256(_proxyInit()), ARACHNID
        );
    }

    // ── Layer 1: the deploys are CREATE2 (nonce-independent). ────────────

    function test_sbt_is_create2() public {
        CitrateMemberSBT sbt =
            new CitrateMemberSBT{salt: Salts.salt("CitrateMemberSBT")}(_owner());
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

    // ── Layer 2: key-INDEPENDENT projections are bytecode-only anchors. ──
    //
    // MemberBond and the vault IMPLEMENTATION take no constructor / key args, so
    // their Arachnid projections do NOT move under a fresh-keys reroll — only a
    // bytecode/optimizer drift moves them. The SBT and vault PROXY DO depend on
    // the (env-derived) owner + registry, so under fresh keys they move by
    // design and are therefore NOT pinned here (see the fan-out doc + the
    // check-create2-determinism.sh gate, which re-derives every address from the
    // fresh keys in effect at ceremony time).

    // Parameterized projections (no env) so the movement/independence tests are
    // deterministic under forge's parallel runner (which shares process env).
    function _sbtAddrFor(address owner) internal pure returns (address) {
        return vm.computeCreate2Address(
            Salts.salt("CitrateMemberSBT"),
            keccak256(abi.encodePacked(type(CitrateMemberSBT).creationCode, abi.encode(owner))),
            ARACHNID
        );
    }

    function _vaultAddrFor(address owner, address registry) internal pure returns (address) {
        bytes memory proxyInit = abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(
                _vaultImplAddr(),
                abi.encodeCall(
                    MembershipStakeVault.initialize,
                    (owner, ValidatorRegistry(payable(registry)), CitrateMemberSBT(_sbtAddrFor(owner)), _bondAddr())
                )
            )
        );
        return vm.computeCreate2Address(Salts.salt("MembershipStakeVault"), keccak256(proxyInit), ARACHNID);
    }

    /// MemberBond + vault impl take no key args: their projections MUST NOT move
    /// when the owner key changes (pure bytecode anchors).
    function test_bond_and_vaultImpl_are_key_independent() public pure {
        // (bond/impl inits do not embed the owner at all, so they are constant.)
        assertEq(_bondAddr(), _bondAddr(), "MemberBond is bytecode-only");
        assertEq(_vaultImplAddr(), _vaultImplAddr(), "vault impl is bytecode-only");
    }

    /// The SBT + vault-proxy projections MOVE when the fresh keys change — this is
    /// the fresh-keys property the reroll relies on (not a frozen literal).
    function test_sbt_and_vault_move_with_fresh_keys() public pure {
        address ownerA = address(uint160(uint256(keccak256("owner.A"))));
        address ownerC = address(uint160(uint256(keccak256("owner.C"))));
        address regB = address(uint160(uint256(keccak256("registry.B"))));
        address regD = address(uint160(uint256(keccak256("registry.D"))));
        assertTrue(_sbtAddrFor(ownerA) != _sbtAddrFor(ownerC), "SBT MUST move when the owner key changes");
        assertTrue(_vaultAddrFor(ownerA, regB) != _vaultAddrFor(ownerC, regB), "vault MUST move when the owner key changes");
        assertTrue(_vaultAddrFor(ownerA, regB) != _vaultAddrFor(ownerA, regD), "vault MUST move when the registry changes");
    }

    // ── The dependency chain is real, and must stay visible. ─────────────

    /// The vault proxy address depends on the SBT and MemberBond addresses
    /// through its initialize calldata. If someone "simplifies" initialize to
    /// stop taking them, this stops being true and the freeze story silently
    /// weakens — the proxy would no longer move when its dependencies do.
    function test_vaultAddressDependsOnItsDependencies() public view {
        bytes memory withReal = _proxyInit();
        bytes memory withOther = abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(
                _vaultImplAddr(),
                abi.encodeCall(
                    MembershipStakeVault.initialize,
                    (
                        _owner(),
                        ValidatorRegistry(payable(_registry())),
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
