// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {DeployGenesisMembership} from "../../script/DeployGenesisMembership.s.sol";
import {DeployGenesisGovernance} from "../../script/DeployGenesisGovernance.s.sol";
import {MultisigProposer} from "../../src/genesis/MultisigProposer.sol";
import {CitrateMemberSBT} from "../../src/core_membership/CitrateMemberSBT.sol";
import {MemberBond} from "../../src/core_membership/MemberBond.sol";
import {MembershipStakeVault} from "../../src/core_membership/MembershipStakeVault.sol";
import {ValidatorRegistry} from "../../src/ValidatorRegistry.sol";

/// @title DeployGenesisMembership.t: the Track M money path in the genesis set (C2 D9 / C4)
contract DeployGenesisMembershipTest is Test {
    address constant SENDER = 0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38; // forge default sender
    address constant ARACHNID = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    uint256 constant GRANT = 32_000 ether;

    DeployGenesisGovernance.Deployed internal gov;
    address[] internal govOwners;
    ValidatorRegistry internal registry;
    address internal grantor;

    function setUp() public {
        gov = _governance(48 hours);
        grantor = makeAddr("treasury-signer");
        registry = new ValidatorRegistry(
            gov.governanceTimelock, makeAddr("slasher"), makeAddr("minter"), GRANT, 1 ether, 5000, 10_000 ether
        );
        vm.mockCall(address(0x0120), bytes(""), abi.encode(uint256(1))); // ed25519 precompile
    }

    function _governance(uint256 delay) internal returns (DeployGenesisGovernance.Deployed memory g) {
        govOwners = new address[](5);
        address[] memory grdOwners = new address[](3);
        for (uint256 i = 0; i < 5; i++) {
            govOwners[i] = address(uint160(0xA000 + i));
        }
        for (uint256 i = 0; i < 3; i++) {
            grdOwners[i] = address(uint160(0xB000 + i));
        }
        g = new DeployGenesisGovernance().deployWith(
            SENDER,
            DeployGenesisGovernance.Council({owners: govOwners, threshold: 3, minDelay: delay}),
            DeployGenesisGovernance.Council({owners: grdOwners, threshold: 2, minDelay: 1 hours}),
            false
        );
    }

    function _deploy() internal returns (DeployGenesisMembership.Deployed memory d) {
        d = new DeployGenesisMembership().deployWith(SENDER, gov.governanceTimelock, grantor, address(registry));
    }

    function _pass(bytes memory data) internal {
        MultisigProposer ms = MultisigProposer(gov.governanceMultisig);
        vm.prank(govOwners[0]);
        bytes32 id = ms.propose(data);
        vm.prank(govOwners[1]);
        ms.approve(id);
        vm.prank(govOwners[2]);
        ms.approve(id);
        vm.prank(govOwners[0]);
        ms.execute(id);
    }

    /// Schedule + 48 h + execute `target.call(payload)` as the GOVERNANCE timelock.
    function _govern(address target, bytes memory payload) internal {
        TimelockController tl = TimelockController(payable(gov.governanceTimelock));
        _pass(abi.encodeCall(tl.schedule, (target, 0, payload, bytes32(0), 0, 48 hours)));
        vm.warp(block.timestamp + 48 hours);
        _pass(abi.encodeCall(tl.execute, (target, 0, payload, bytes32(0), 0)));
    }

    // ── Hand-over ───────────────────────────────────────────────────────────

    function test_roles_are_split_between_governance_and_the_grantor() public {
        DeployGenesisMembership.Deployed memory d = _deploy();
        MembershipStakeVault v = MembershipStakeVault(payable(d.vault));
        assertEq(v.owner(), grantor, "grantor places grants");
        assertEq(v.governance(), gov.governanceTimelock, "governance holds upgrade authority");
        assertEq(v.pendingGovernance(), address(0));
        assertEq(CitrateMemberSBT(d.sbt).owner(), grantor, "grantor mints + attests KYC");
        assertEq(address(v.registry()), address(registry));
        assertEq(address(v.sbt()), d.sbt);
        assertEq(v.bondImplementation(), d.bondImplementation);
        assertEq(d.vault.balance, 0);
    }

    function test_deployer_and_factory_hold_nothing() public {
        DeployGenesisMembership.Deployed memory d = _deploy();
        address[2] memory targets = [d.vault, d.sbt];
        for (uint256 i = 0; i < 2; i++) {
            (bool ok, bytes memory ret) = targets[i].staticcall(abi.encodeWithSignature("owner()"));
            assertTrue(ok);
            address o = abi.decode(ret, (address));
            assertTrue(o != SENDER && o != ARACHNID, "deploy account left as owner");
        }
        MembershipStakeVault v = MembershipStakeVault(payable(d.vault));
        assertTrue(v.governance() != SENDER && v.governance() != ARACHNID);
    }

    function test_addresses_are_create2_through_the_factory() public {
        DeployGenesisMembership.Deployed memory d = _deploy();
        bytes32 bondSalt = keccak256(abi.encodePacked("citrate.v1.", "MemberBond"));
        address expected = vm.computeCreate2Address(bondSalt, keccak256(type(MemberBond).creationCode), ARACHNID);
        assertEq(d.bondImplementation, expected);
    }

    function test_rerun_reuses_everything_and_sends_no_second_handover() public {
        DeployGenesisMembership.Deployed memory d1 = _deploy();
        DeployGenesisMembership.Deployed memory d2 = _deploy();
        assertEq(d1.sbt, d2.sbt);
        assertEq(d1.bondImplementation, d2.bondImplementation);
        assertEq(d1.vaultImplementation, d2.vaultImplementation);
        assertEq(d1.vault, d2.vault);
        assertEq(MembershipStakeVault(payable(d2.vault)).owner(), grantor);
    }

    // ── What each role can and cannot do afterwards ─────────────────────────

    function test_grantor_grants_end_to_end_and_member_activates() public {
        DeployGenesisMembership.Deployed memory d = _deploy();
        MembershipStakeVault v = MembershipStakeVault(payable(d.vault));
        CitrateMemberSBT sbt = CitrateMemberSBT(d.sbt);
        address member = makeAddr("member");

        vm.startPrank(grantor);
        uint256 tokenId =
            sbt.mintMember(member, keccak256("sub"), uint64(block.timestamp), uint64(block.timestamp + 365 days));
        vm.deal(grantor, GRANT);
        v.grant{value: GRANT}(member, GRANT, tokenId);
        vm.stopPrank();

        MemberBond bond = MemberBond(payable(v.bondOf(member)));
        assertEq(address(bond).balance, GRANT);
        vm.prank(member);
        bond.activate(bytes32(uint256(0xA11CE)), new bytes(64));
        assertEq(registry.stakeOf(bytes32(uint256(0xA11CE))), GRANT, "the grant is the validator bond");
    }

    function test_grantor_cannot_upgrade_the_vault() public {
        DeployGenesisMembership.Deployed memory d = _deploy();
        MembershipStakeVault v = MembershipStakeVault(payable(d.vault));
        MembershipStakeVault next = new MembershipStakeVault();
        vm.prank(grantor);
        vm.expectRevert(MembershipStakeVault.NotGovernance.selector);
        v.upgradeToAndCall(address(next), bytes(""));
    }

    function test_governance_upgrades_through_the_timelock() public {
        DeployGenesisMembership.Deployed memory d = _deploy();
        MembershipStakeVault next = new MembershipStakeVault();
        _govern(d.vault, abi.encodeWithSignature("upgradeToAndCall(address,bytes)", address(next), bytes("")));
        bytes32 slot = vm.load(d.vault, 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc);
        assertEq(address(uint160(uint256(slot))), address(next));
        assertEq(MembershipStakeVault(payable(d.vault)).owner(), grantor, "grant role survives the upgrade");
    }

    /// A lost or compromised grant signer is replaceable without the signer's cooperation.
    function test_governance_replaces_a_compromised_grantor() public {
        DeployGenesisMembership.Deployed memory d = _deploy();
        address fresh = makeAddr("fresh-signer");
        _govern(d.vault, abi.encodeCall(MembershipStakeVault.setOwner, (fresh)));
        assertEq(MembershipStakeVault(payable(d.vault)).owner(), fresh);
    }

    // ── Fail closed ─────────────────────────────────────────────────────────

    function test_refuses_a_non_timelock_governance() public {
        DeployGenesisMembership s = new DeployGenesisMembership();
        vm.expectRevert(bytes("GOVERNANCE_TIMELOCK is not a TimelockController"));
        s.deployWith(SENDER, makeAddr("eoa"), grantor, address(registry));
    }

    function test_refuses_governance_below_48h_on_the_genesis_chain() public {
        vm.chainId(40204);
        address[] memory council = new address[](1);
        council[0] = makeAddr("council");
        TimelockController weak = new TimelockController(1 hours, council, council, address(0));
        DeployGenesisMembership s = new DeployGenesisMembership();
        vm.expectRevert(bytes("GOVERNANCE_TIMELOCK: minDelay below the 48 h genesis floor"));
        s.deployWith(SENDER, address(weak), grantor, address(registry));
    }

    function test_accepts_48h_governance_on_the_genesis_chain() public {
        vm.chainId(40204);
        DeployGenesisMembership.Deployed memory d = _deploy();
        assertEq(MembershipStakeVault(payable(d.vault)).governance(), gov.governanceTimelock);
    }

    function test_refuses_the_deployer_as_grantor() public {
        DeployGenesisMembership s = new DeployGenesisMembership();
        vm.expectRevert(bytes("MEMBERSHIP_GRANTOR cannot be the deployer"));
        s.deployWith(SENDER, gov.governanceTimelock, SENDER, address(registry));
    }

    function test_refuses_the_governance_timelock_as_grantor() public {
        DeployGenesisMembership s = new DeployGenesisMembership();
        vm.expectRevert(bytes("MEMBERSHIP_GRANTOR cannot be the governance timelock"));
        s.deployWith(SENDER, gov.governanceTimelock, gov.governanceTimelock, address(registry));
    }

    function test_refuses_a_zero_grantor() public {
        DeployGenesisMembership s = new DeployGenesisMembership();
        vm.expectRevert(bytes("MEMBERSHIP_GRANTOR must be set"));
        s.deployWith(SENDER, gov.governanceTimelock, address(0), address(registry));
    }

    function test_refuses_a_codeless_registry() public {
        DeployGenesisMembership s = new DeployGenesisMembership();
        vm.expectRevert(bytes("VALIDATOR_REGISTRY has no code on this chain"));
        s.deployWith(SENDER, gov.governanceTimelock, grantor, makeAddr("nothing"));
    }

    function test_refuses_a_registry_whose_min_stake_exceeds_the_grant() public {
        ValidatorRegistry steep = new ValidatorRegistry(
            gov.governanceTimelock, makeAddr("slasher"), makeAddr("minter"), GRANT + 1, 1 ether, 5000, 10_000 ether
        );
        DeployGenesisMembership s = new DeployGenesisMembership();
        vm.expectRevert(bytes("VALIDATOR_REGISTRY minStake exceeds the 32,000 SALT grant: members could never activate"));
        s.deployWith(SENDER, gov.governanceTimelock, grantor, address(steep));
    }

    function test_refuses_a_broadcaster_that_is_not_the_deployer() public {
        DeployGenesisMembership s = new DeployGenesisMembership();
        vm.expectRevert(bytes("broadcast sender is not the configured deployer (DEPLOYER_ADDRESS)"));
        s.deployWith(makeAddr("someone-else"), gov.governanceTimelock, grantor, address(registry));
    }

    // ── Output ──────────────────────────────────────────────────────────────

    function test_book_names_every_contract_and_the_lock() public {
        DeployGenesisMembership s = new DeployGenesisMembership();
        DeployGenesisMembership.Deployed memory d =
            s.deployWith(SENDER, gov.governanceTimelock, grantor, address(registry));
        string memory json = s.bookJson(SENDER, gov.governanceTimelock, grantor, address(registry), d);
        assertEq(vm.parseJsonAddress(json, ".contracts.MembershipStakeVault"), d.vault);
        assertEq(vm.parseJsonAddress(json, ".contracts.CitrateMemberSBT"), d.sbt);
        assertEq(vm.parseJsonAddress(json, ".contracts.MemberBond"), d.bondImplementation);
        assertEq(vm.parseJsonAddress(json, ".contracts.GovernanceTimelock"), gov.governanceTimelock);
        assertEq(vm.parseJsonAddress(json, ".params.grantor"), grantor);
        assertEq(vm.parseJsonUint(json, ".params.lockSeconds"), 364 days);
        assertEq(vm.parseJsonUint(json, ".params.lockBlocks"), 364 days / 2);
    }
}
