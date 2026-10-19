// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {MemberBond} from "../../src/core_membership/MemberBond.sol";
import {MembershipStakeVault} from "../../src/core_membership/MembershipStakeVault.sol";
import {CitrateMemberSBT} from "../../src/core_membership/CitrateMemberSBT.sol";
import {ValidatorRegistry} from "../../src/ValidatorRegistry.sol";

/// Drives the Track M money path with random grants, KYC flips, activations,
/// exits, chain progress (blocks and wall clock separately, so stalls happen)
/// and attacker pokes. The handler owns the vault and the SBT, standing in for
/// the grant signer.
contract MemberBondHandler is Test {
    uint256 internal constant GRANT = 32_000 ether;
    uint256 internal constant MEMBERS = 4;

    ValidatorRegistry public registry;
    CitrateMemberSBT public sbt;
    MembershipStakeVault public vault;

    address public attacker = address(0xBAD);
    address[MEMBERS] public members;
    uint256[MEMBERS] public tokenIds;
    bool[MEMBERS] public granted;
    uint256[MEMBERS] public grantIds;

    /// Number of SALT payouts to a member that happened while the bond was
    /// still locked or the member was not KYC-verified. Must stay zero.
    uint256 public earlyOrUnverifiedPayouts;
    /// Number of attacker calls that did not revert. Must stay zero.
    uint256 public attackerSuccesses;

    constructor() {
        registry = new ValidatorRegistry(
            address(0x6011), address(0x5142), address(0x11d7), GRANT, 1 ether, 5000, 10_000 ether
        );
        sbt = new CitrateMemberSBT(address(this));
        MemberBond bondImpl = new MemberBond();
        MembershipStakeVault impl = new MembershipStakeVault();
        vault = MembershipStakeVault(
            payable(
                address(
                    new ERC1967Proxy(
                        address(impl),
                        abi.encodeCall(MembershipStakeVault.initialize, (address(this), registry, sbt, address(bondImpl)))
                    )
                )
            )
        );
        vm.deal(address(this), GRANT * MEMBERS);
        for (uint256 i = 0; i < MEMBERS; i++) {
            members[i] = address(uint160(0x3E3B0 + i));
            tokenIds[i] = sbt.mintMember(
                members[i],
                keccak256(abi.encode("sub", i)),
                uint64(block.timestamp),
                uint64(block.timestamp + 365 days)
            );
        }
    }

    function memberCount() external pure returns (uint256) {
        return MEMBERS;
    }

    function pubkeyOf(uint256 i) public pure returns (bytes32) {
        return bytes32(uint256(0xA000 + i));
    }

    function bondOf(uint256 i) public view returns (MemberBond) {
        return MemberBond(payable(vault.bondOf(members[i])));
    }

    // ── actions ────────────────────────────────────────────────────────────

    function grant(uint256 seed) external {
        uint256 i = seed % MEMBERS;
        if (granted[i]) return;
        grantIds[i] = vault.grant{value: GRANT}(members[i], GRANT, tokenIds[i]);
        granted[i] = true;
    }

    function setKyc(uint256 seed, bool verified) external {
        uint256 i = seed % MEMBERS;
        sbt.setKycVerified(tokenIds[i], verified);
    }

    function activate(uint256 seed) external {
        uint256 i = seed % MEMBERS;
        if (!granted[i]) return;
        vm.mockCall(address(0x0120), bytes(""), abi.encode(uint256(1)));
        vm.prank(members[i]);
        try bondOf(i).activate(pubkeyOf(i), new bytes(64)) {} catch {}
    }

    function withdrawUnactivated(uint256 seed) external {
        uint256 i = seed % MEMBERS;
        if (!granted[i]) return;
        MemberBond bond = bondOf(i);
        bool allowed = bond.isUnlocked() && bond.isKycVerified();
        uint256 before = members[i].balance;
        vm.prank(members[i]);
        try bond.withdrawUnactivated() {
            if (!allowed && members[i].balance > before) earlyOrUnverifiedPayouts++;
        } catch {}
    }

    function requestRelease(uint256 seed) external {
        uint256 i = seed % MEMBERS;
        if (!granted[i]) return;
        vm.prank(members[i]);
        try bondOf(i).requestRelease() {} catch {}
    }

    function withdrawToMember(uint256 seed) external {
        uint256 i = seed % MEMBERS;
        if (!granted[i]) return;
        MemberBond bond = bondOf(i);
        bool allowed = bond.isUnlocked() && bond.isKycVerified();
        uint256 before = members[i].balance;
        vm.prank(members[i]);
        try bond.withdrawToMember() {
            if (!allowed && members[i].balance > before) earlyOrUnverifiedPayouts++;
        } catch {}
    }

    function recordRelease(uint256 seed) external {
        uint256 i = seed % MEMBERS;
        if (!granted[i]) return;
        try vault.recordRelease(grantIds[i]) {} catch {}
    }

    function lapseOrRenew(uint256 seed, bool lapse) external {
        uint256 i = seed % MEMBERS;
        if (!granted[i]) return;
        if (lapse) {
            try vault.lapse(grantIds[i]) {} catch {}
        } else {
            try vault.renew(grantIds[i]) {} catch {}
        }
    }

    /// Blocks and wall clock advance independently: a chain stall is time
    /// without blocks.
    function advance(uint32 blocks, uint32 secs) external {
        vm.roll(block.number + (uint256(blocks) % 20_000_000));
        vm.warp(block.timestamp + (uint256(secs) % 400 days));
    }

    function attackerPoke(uint256 seed, uint8 which) external {
        uint256 i = seed % MEMBERS;
        if (!granted[i]) return;
        MemberBond bond = bondOf(i);
        vm.startPrank(attacker);
        bool ok;
        if (which % 4 == 0) {
            try bond.withdrawUnactivated() { ok = true; } catch {}
        } else if (which % 4 == 1) {
            try bond.withdrawToMember() { ok = true; } catch {}
        } else if (which % 4 == 2) {
            try bond.activate(bytes32(uint256(0xBAD)), new bytes(64)) { ok = true; } catch {}
        } else {
            try vault.grant{value: 0}(attacker, 1, tokenIds[i]) { ok = true; } catch {}
        }
        vm.stopPrank();
        if (ok) attackerSuccesses++;
    }

    receive() external payable {}
}

contract MemberBondInvariant is Test {
    uint256 internal constant GRANT = 32_000 ether;
    MemberBondHandler internal h;

    function setUp() public {
        vm.roll(10_000);
        h = new MemberBondHandler();
        targetContract(address(h));
    }

    /// Grants pass through the vault in the same transaction; it never holds SALT.
    function invariant_vaultHoldsNothing() public view {
        assertEq(address(h.vault()).balance, 0);
    }

    /// Conservation: every granted SALT is in a bond, held by the registry
    /// (bonded or escrowed), or with its member, and nowhere else. The registry
    /// is funded only by these bonds in this model (no rewards are minted).
    function invariant_principalIsConserved() public view {
        uint256 total;
        uint256 grants;
        for (uint256 i = 0; i < h.memberCount(); i++) {
            if (!h.granted(i)) continue;
            grants++;
            total += h.members(i).balance + address(h.bondOf(i)).balance;
        }
        assertEq(total + address(h.registry()).balance, grants * GRANT, "principal leaked");
    }

    /// No SALT reaches a member while their bond is locked or unverified.
    function invariant_noEarlyOrUnverifiedPayout() public view {
        assertEq(h.earlyOrUnverifiedPayouts(), 0);
    }

    /// Nobody but the member moves a bond, and nobody but the owner grants.
    function invariant_attackerNeverSucceeds() public view {
        assertEq(h.attackerSuccesses(), 0);
        assertEq(h.attacker().balance, 0);
    }

    /// A paid-out member is never still counted as attributed stake.
    function invariant_paidOutMemberIsNotAttributedAfterRecord() public view {
        MembershipStakeVault v = h.vault();
        for (uint256 i = 0; i < h.memberCount(); i++) {
            if (!h.granted(i)) continue;
            MembershipStakeVault.Grant memory g = v.getGrant(h.grantIds(i));
            if (g.state == MembershipStakeVault.GrantState.Released) {
                assertEq(v.attributedStake(h.members(i)), 0, "released grant still attributed");
            }
            if (g.state == MembershipStakeVault.GrantState.Attributed) {
                assertEq(v.attributedStake(h.members(i)), GRANT, "attributed grant not counted");
            }
        }
    }
}
