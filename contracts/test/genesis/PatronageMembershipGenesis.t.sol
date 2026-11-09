// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {PatronageLedger} from "../../src/coop/PatronageLedger.sol";
import {CitrateMemberSBT} from "../../src/core_membership/CitrateMemberSBT.sol";

/// Test double for the KYC side only: every member verified, so the call under test reaches
/// the membership check.
contract KycAllVerified {
    function isVerified(address) external pure returns (bool) {
        return true;
    }

    function identityOf(address) external pure returns (bytes32) {
        return bytes32(uint256(1));
    }
}

/// An isMember-compatible membership source (what governance would wire later).
contract MembershipAllMembers {
    function isMember(address) external pure returns (bool) {
        return true;
    }
}

/// r1006 block 0 wires PatronageLedger's membership to #331's canonical CitrateMemberSBT (lead
/// decision 2026-10-27). That SBT has no `isMember(address)`, so the ledger stays dormant: even
/// once governance grants SETTLER_ROLE and commits a round, a patronage mint reverts, and it
/// reverts CLEANLY (no unit, no record, no year total moves). Minting needs governance to wire
/// an isMember-compatible membership source first.
contract PatronageMembershipGenesisTest is Test {
    PatronageLedger ledger;
    CitrateMemberSBT sbt;
    address governance = address(0x6060);
    address settler = address(0x5e77);
    address member = address(0xbeef);
    bytes32 round = keccak256("round-1");

    function setUp() public {
        sbt = new CitrateMemberSBT(governance);
        ledger = new PatronageLedger(address(new KycAllVerified()), address(sbt), governance);
        vm.startPrank(governance);
        ledger.grantRole(ledger.SETTLER_ROLE(), settler);
        vm.stopPrank();
        vm.prank(settler);
        ledger.commitRound(round, keccak256("merged"));
    }

    function test_the_canonical_membership_sbt_has_no_isMember() public {
        (bool ok,) = address(sbt).staticcall(abi.encodeWithSignature("isMember(address)", member));
        assertFalse(ok, "CitrateMemberSBT answers isMember: the ledger would not be dormant");
    }

    function test_a_patronage_mint_reverts_cleanly_until_governance_wires_membership() public {
        uint256 year = ledger.currentYear();
        vm.prank(settler);
        vm.expectRevert();
        ledger.recordContribution(round, member, 1_000, 5_000);
        assertFalse(ledger.recorded(round, member), "no record");
        assertEq(ledger.units(member), 0, "no units");
        assertEq(ledger.totalUnits(), 0, "no total");
        assertEq(ledger.yearUnits(year, member), 0, "no year units");
        assertEq(ledger.yearTotalUnits(year), 0, "no year total");
        assertEq(ledger.pendingDividend(member), 0, "no dividend");
    }

    /// Control: with an isMember-compatible source the same mint records units, so the revert
    /// above is the membership wiring and nothing else.
    function test_control_an_ismember_source_mints() public {
        PatronageLedger wired =
            new PatronageLedger(address(new KycAllVerified()), address(new MembershipAllMembers()), governance);
        vm.startPrank(governance);
        wired.grantRole(wired.SETTLER_ROLE(), settler);
        vm.stopPrank();
        vm.startPrank(settler);
        wired.commitRound(round, keccak256("merged"));
        wired.recordContribution(round, member, 1_000, 5_000);
        vm.stopPrank();
        assertTrue(wired.recorded(round, member));
        assertGt(wired.units(member), 0);
    }
}
