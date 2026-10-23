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
import {CheckDeployedAdmins} from "../../script/CheckDeployedAdmins.s.sol";
import {Salts} from "../../script/Salts.sol";
import {RoleLogArchive} from "./RoleHistoryHarness.sol";
import {MembershipWithNode, GateWithNode} from "./NodeChainIdHarness.sol";
import {SelfReportingForwarder} from "./DeployDormantLedgers.t.sol";

/// @title DeployGenesisMembership.t: the Track M money path in the genesis set (C2 D9 / C4)
contract DeployGenesisMembershipTest is Test {
    address constant SENDER = 0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38; // forge default sender
    address constant ARACHNID = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    uint256 constant GRANT = 32_000 ether;
    address constant P256_VERIFIER = 0xc2b78104907F722DABAc4C69f826a522B2754De4;
    string constant GOV_SALT = "Genesis.GovernanceMultisig";

    DeployGenesisGovernance.Deployed internal gov;
    address[] internal govOwners;
    ValidatorRegistry internal registry;
    address internal grantor;
    RoleLogArchive internal archive;
    /// setUp's governance book (DeployGenesisGovernance's contracts section): its verified
    /// GuardianCanceller is the GOVERNANCE timelock's one allowed extra CANCELLER.
    string internal govBookJson;
    uint256 internal timelockSeq;

    function setUp() public {
        // The timelock role history the script replays (no node in forge test: RoleHistoryHarness).
        vm.recordLogs();
        archive = new RoleLogArchive();
        gov = _governance(48 hours);
        govBookJson = _book(gov);
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
        g = new DeployGenesisGovernance()
            .deployWith(
                SENDER,
                DeployGenesisGovernance.Council({
                    owners: govOwners, threshold: 3, minDelay: delay, proposalTtl: 14 days
                }),
                DeployGenesisGovernance.Council({
                        owners: grdOwners, threshold: 2, minDelay: 1 hours, proposalTtl: 14 days
                    }),
                false,
                false
            );
    }

    /// A governance book (contracts section, this chain) as DeployGenesisGovernance writes it.
    function _book(DeployGenesisGovernance.Deployed memory g) internal view returns (string memory) {
        return string.concat(
            '{"chainId":',
            vm.toString(block.chainid),
            ',"deployer":"',
            vm.toString(SENDER),
            '","contracts":{"GovernanceTimelock":"',
            vm.toString(g.governanceTimelock),
            '","GovernanceMultisig":"',
            vm.toString(g.governanceMultisig),
            '","GuardianTimelock":"',
            vm.toString(g.guardianTimelock),
            '","GuardianMultisig":"',
            vm.toString(g.guardianMultisig),
            '","GuardianCanceller":"',
            vm.toString(g.guardianCanceller),
            '"},"aaStack":{},"params":{}}'
        );
    }

    /// The script with the test's recorded role history standing in for the node.
    function _script() internal returns (DeployGenesisMembership s) {
        MembershipWithNode h = new MembershipWithNode();
        h.useArchive(archive);
        s = h;
    }

    function _gate() internal returns (CheckDeployedAdmins c) {
        GateWithNode g = new GateWithNode();
        g.useArchive(archive);
        c = g;
    }

    /// `vm.expectRevert`, after moving the recorded logs into the archive from THIS frame: a
    /// reverted script call would roll back an absorb made inside it (RoleHistoryHarness).
    function _expectRevert(bytes memory reason) internal {
        archive.absorb();
        vm.expectRevert(reason);
    }

    function _deploy() internal returns (DeployGenesisMembership.Deployed memory d) {
        d = _script()
            .deployWith(SENDER, gov.governanceTimelock, gov.governanceMultisig, grantor, address(registry), govBookJson);
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
        DeployGenesisMembership s = _script();
        _expectRevert(bytes("GOVERNANCE_TIMELOCK is not a TimelockController"));
        s.deployWith(SENDER, makeAddr("eoa"), gov.governanceMultisig, grantor, address(registry));
    }

    /// A correctly handed-over ceremony council passes off the genesis chain; the genesis profile
    /// (chosen by the chain id the node reports) refuses a delay under 48 h and a council under 3-of-5.
    function test_genesis_profile_floor_is_48h_and_3_of_5() public {
        DeployGenesisGovernance.Deployed memory weakDelay = _council(3, 5, 24 hours);
        // 72 h: the timelock's CREATE2 address depends on (deployer, delay), and setUp owns 48 h.
        DeployGenesisGovernance.Deployed memory weakCouncil = _council(2, 3, 72 hours);
        DeployGenesisMembership s = _script();
        string memory weakDelayBook = _book(weakDelay);
        string memory weakCouncilBook = _book(weakCouncil);
        s.deployWith(
            SENDER,
            weakDelay.governanceTimelock,
            weakDelay.governanceMultisig,
            grantor,
            address(registry),
            weakDelayBook
        );

        vm.chainId(40204);
        _expectRevert(bytes("GOVERNANCE timelock: minDelay below the 48 h genesis floor"));
        s.deployWith(
            SENDER,
            weakDelay.governanceTimelock,
            weakDelay.governanceMultisig,
            grantor,
            address(registry),
            weakDelayBook
        );
        _expectRevert(bytes("GOVERNANCE multisig: below the 3-of-5 genesis floor"));
        s.deployWith(
            SENDER,
            weakCouncil.governanceTimelock,
            weakCouncil.governanceMultisig,
            grantor,
            address(registry),
            weakCouncilBook
        );

        // P1 (chain id): the same weak council against a node reporting 40204 while forge
        // simulates chain 1 (--chain-id 1 / --chain 1 / FOUNDRY_CHAIN_ID=1) is refused, and
        // nothing is broadcast.
        MembershipWithNode m = new MembershipWithNode();
        m.useArchive(archive);
        m.nodeReports(40204);
        vm.chainId(1);
        uint64 nonceBefore = vm.getNonce(SENDER);
        _expectRevert(
            bytes(
                "chain id mismatch: node reports 40204, forge simulates 1 (drop --chain-id / --chain / FOUNDRY_CHAIN_ID)"
            )
        );
        m.deployWith(
            SENDER,
            weakDelay.governanceTimelock,
            weakDelay.governanceMultisig,
            grantor,
            address(registry),
            weakDelayBook
        );
        assertEq(vm.getNonce(SENDER), nonceBefore, "nothing broadcast");
        // And 40204 with no node to ask fails closed.
        m.noNode();
        vm.chainId(40204);
        _expectRevert(bytes("genesis profile needs a live node: run with --rpc-url (eth_chainId unavailable)"));
        m.deployWith(SENDER, gov.governanceTimelock, gov.governanceMultisig, grantor, address(registry), govBookJson);
    }

    function test_accepts_48h_governance_on_the_genesis_chain() public {
        vm.chainId(40204);
        DeployGenesisMembership.Deployed memory d = _deploy();
        assertEq(MembershipStakeVault(payable(d.vault)).governance(), gov.governanceTimelock);
    }

    function test_refuses_the_deployer_as_grantor() public {
        DeployGenesisMembership s = _script();
        _expectRevert(bytes("MEMBERSHIP_GRANTOR cannot be the deployer"));
        s.deployWith(SENDER, gov.governanceTimelock, gov.governanceMultisig, SENDER, address(registry), govBookJson);
    }

    function test_refuses_the_governance_timelock_as_grantor() public {
        DeployGenesisMembership s = _script();
        _expectRevert(bytes("MEMBERSHIP_GRANTOR cannot be the governance timelock"));
        s.deployWith(
            SENDER,
            gov.governanceTimelock,
            gov.governanceMultisig,
            gov.governanceTimelock,
            address(registry),
            govBookJson
        );
    }

    function test_refuses_the_governance_multisig_as_grantor() public {
        DeployGenesisMembership s = _script();
        _expectRevert(bytes("MEMBERSHIP_GRANTOR cannot be the governance multisig"));
        s.deployWith(
            SENDER,
            gov.governanceTimelock,
            gov.governanceMultisig,
            gov.governanceMultisig,
            address(registry),
            govBookJson
        );
    }

    function test_refuses_a_zero_grantor() public {
        DeployGenesisMembership s = _script();
        _expectRevert(bytes("MEMBERSHIP_GRANTOR must be set"));
        s.deployWith(SENDER, gov.governanceTimelock, gov.governanceMultisig, address(0), address(registry), govBookJson);
    }

    function test_refuses_a_codeless_registry() public {
        DeployGenesisMembership s = _script();
        _expectRevert(bytes("VALIDATOR_REGISTRY has no code on this chain"));
        s.deployWith(SENDER, gov.governanceTimelock, gov.governanceMultisig, grantor, makeAddr("nothing"), govBookJson);
    }

    function test_refuses_a_registry_whose_min_stake_exceeds_the_grant() public {
        ValidatorRegistry steep = new ValidatorRegistry(
            gov.governanceTimelock, makeAddr("slasher"), makeAddr("minter"), GRANT + 1, 1 ether, 5000, 10_000 ether
        );
        DeployGenesisMembership s = _script();
        _expectRevert(bytes("VALIDATOR_REGISTRY minStake exceeds the 32,000 SALT grant: members could never activate"));
        s.deployWith(SENDER, gov.governanceTimelock, gov.governanceMultisig, grantor, address(steep), govBookJson);
    }

    function test_refuses_a_broadcaster_that_is_not_the_deployer() public {
        DeployGenesisMembership s = _script();
        _expectRevert(bytes("broadcast sender is not the configured deployer (DEPLOYER_ADDRESS)"));
        s.deployWith(
            makeAddr("someone-else"),
            gov.governanceTimelock,
            gov.governanceMultisig,
            grantor,
            address(registry),
            govBookJson
        );
    }

    // ── Output ──────────────────────────────────────────────────────────────

    function test_book_names_every_contract_and_the_lock() public {
        DeployGenesisMembership s = _script();
        DeployGenesisMembership.Deployed memory d = s.deployWith(
            SENDER, gov.governanceTimelock, gov.governanceMultisig, grantor, address(registry), govBookJson
        );
        string memory json =
            s.bookJson(SENDER, gov.governanceTimelock, gov.governanceMultisig, grantor, address(registry), d);
        assertEq(vm.parseJsonAddress(json, ".contracts.MembershipStakeVault"), d.vault);
        assertEq(vm.parseJsonAddress(json, ".contracts.CitrateMemberSBT"), d.sbt);
        assertEq(vm.parseJsonAddress(json, ".contracts.MemberBond"), d.bondImplementation);
        assertEq(vm.parseJsonAddress(json, ".contracts.GovernanceTimelock"), gov.governanceTimelock);
        assertEq(vm.parseJsonAddress(json, ".contracts.GovernanceMultisig"), gov.governanceMultisig);
        assertEq(vm.parseJsonAddress(json, ".params.grantor"), grantor);
        assertEq(vm.parseJsonUint(json, ".params.lockSeconds"), 364 days);
        assertEq(vm.parseJsonUint(json, ".params.lockBlocks"), 364 days / 2);
    }

    /// The only test that sets MEMBERSHIP_GRANTOR / VALIDATOR_REGISTRY / GENESIS_MEMBERSHIP_OUT
    /// (env is process-global, and DeployDormantLedgers.t sets GOVERNANCE_* concurrently with the
    /// same values). The book it writes passes the admin gate, TIMELOCK-HOLDERS included
    /// (GovernanceTimelock is paired with its GovernanceMultisig).
    function test_run_requires_env_then_writes_a_gated_book() public {
        vm.setEnv("DEPLOYER_ADDRESS", vm.toString(SENDER));
        vm.setEnv("GOVERNANCE_TIMELOCK", vm.toString(gov.governanceTimelock));
        vm.setEnv("GOVERNANCE_MULTISIG", vm.toString(gov.governanceMultisig));
        vm.setEnv("VALIDATOR_REGISTRY", vm.toString(address(registry)));
        vm.setEnv("GENESIS_MEMBERSHIP_OUT", "genesis/test-genesis-membership.json");
        vm.createDir("genesis", true);
        vm.writeFile("genesis/test-genesis-membership-gov.json", govBookJson);
        DeployGenesisMembership s = _script();
        archive.absorb();
        vm.expectRevert();
        s.run(); // MEMBERSHIP_GRANTOR unset
        vm.setEnv("MEMBERSHIP_GRANTOR", vm.toString(grantor));

        // Set right before each run: dormant-ledger tests set GENESIS_GOVERNANCE_BOOK concurrently.
        vm.setEnv("GENESIS_GOVERNANCE_BOOK", "genesis/test-genesis-membership-gov.json");
        DeployGenesisMembership.Deployed memory d = s.run();
        string memory book = vm.readFile("genesis/test-genesis-membership.json");
        assertEq(vm.parseJsonAddress(book, ".contracts.MembershipStakeVault"), d.vault);
        assertEq(vm.parseJsonAddress(book, ".contracts.GovernanceTimelock"), gov.governanceTimelock);
        assertEq(vm.parseJsonAddress(book, ".contracts.GovernanceMultisig"), gov.governanceMultisig);

        vm.etch(P256_VERIFIER, hex"600160005260206000f3");
        CheckDeployedAdmins c = _gate();
        string[] memory extras = new string[](1);
        extras[0] = govBookJson;
        c.checkAll(book, extras, true);
        assertEq(c.timelockHolders(), 0, "the GuardianCanceller is verified from the governance book");
        assertEq(c.deployerAdmin(), 0, "DEPLOYER-ADMIN reads 0 after hand-over");
        assertEq(c.factoryAdmin(), 0);
        vm.removeFile("genesis/test-genesis-membership.json");
        vm.removeFile("genesis/test-genesis-membership-gov.json");
    }

    // ── Governance: the council is authenticated and the holder sets are complete ──

    function test_refuses_a_council_that_is_not_the_timelocks_multisig() public {
        DeployGenesisMembership s = _script();
        MultisigProposer stranger = new MultisigProposer(gov.governanceTimelock, govOwners, 3, 14 days);
        _expectRevert(bytes("GOVERNANCE_TIMELOCK: multisig lacks a timelock role"));
        s.deployWith(SENDER, gov.governanceTimelock, address(stranger), grantor, address(registry), govBookJson);
        _expectRevert(bytes("GOVERNANCE_MULTISIG has no code on this chain"));
        s.deployWith(SENDER, gov.governanceTimelock, makeAddr("nomultisig"), grantor, address(registry), govBookJson);
        // The GUARDIAN council is a genuine ceremony multisig, but not GOVERNANCE's.
        _expectRevert(bytes("GOVERNANCE_TIMELOCK: multisig lacks a timelock role"));
        s.deployWith(SENDER, gov.governanceTimelock, gov.guardianMultisig, grantor, address(registry), govBookJson);
    }

    /// A single-signer forwarder that reports a compliant 3-of-5 council and is the timelock's
    /// sole proposer / executor / canceller is refused on CREATE2 provenance, before broadcast.
    function test_refuses_a_self_reporting_forwarder_council() public {
        vm.chainId(40204);
        TimelockController tl = new TimelockController(48 hours, new address[](0), new address[](0), SENDER);
        SelfReportingForwarder fwd = new SelfReportingForwarder(address(tl), makeAddr("lone-signer"), govOwners);
        _grantCouncil(tl, address(fwd));
        _finish(tl);
        DeployGenesisMembership s = _script();
        uint64 nonceBefore = vm.getNonce(SENDER);
        _expectRevert(
            bytes(
                "GOVERNANCE_MULTISIG: not the MultisigProposer the ceremony deploys (Genesis.GovernanceMultisig) for this timelock, owners, threshold and proposal TTL"
            )
        );
        s.deployWith(SENDER, address(tl), address(fwd), grantor, address(registry));
        assertEq(vm.getNonce(SENDER), nonceBefore, "nothing broadcast");
    }

    /// Named-account checks pass (no deploy account holds anything); the complete holder sets
    /// do not: an extra admin, proposer, executor or canceller is refused before broadcast.
    function test_refuses_any_extra_timelock_role_holder() public {
        vm.chainId(40204);
        bytes32[4] memory roles =
            [bytes32(0x00), keccak256("PROPOSER_ROLE"), keccak256("EXECUTOR_ROLE"), keccak256("CANCELLER_ROLE")];
        string[4] memory reasons = [
            "GOVERNANCE_TIMELOCK: DEFAULT_ADMIN_ROLE holders are not exactly the timelock itself",
            "GOVERNANCE_TIMELOCK: PROPOSER_ROLE holders are not exactly the multisig",
            "GOVERNANCE_TIMELOCK: EXECUTOR_ROLE holders are not exactly the multisig",
            "GOVERNANCE_TIMELOCK: CANCELLER_ROLE is held by an account other than the multisig"
        ];
        DeployGenesisMembership s = _script();
        for (uint256 i = 0; i < 4; i++) {
            (TimelockController tl, MultisigProposer ms) = _handedTimelock();
            vm.prank(SENDER);
            tl.grantRole(roles[i], makeAddr("operator"));
            _finish(tl);
            uint64 nonceBefore = vm.getNonce(SENDER);
            _expectRevert(bytes(reasons[i]));
            s.deployWith(SENDER, address(tl), address(ms), grantor, address(registry));
            assertEq(vm.getNonce(SENDER), nonceBefore, "nothing broadcast");
        }
    }

    /// A hand-built timelock with exactly the ceremony council and nothing else passes, so the
    /// check above is about the extra holder, not about the hand-built setup.
    function test_accepts_a_hand_built_timelock_with_exact_holders() public {
        vm.chainId(40204);
        (TimelockController tl, MultisigProposer ms) = _handedTimelock();
        _finish(tl);
        DeployGenesisMembership.Deployed memory d =
            _script().deployWith(SENDER, address(tl), address(ms), grantor, address(registry));
        assertEq(MembershipStakeVault(payable(d.vault)).governance(), address(tl));
    }

    /// The GOVERNANCE timelock's one extra CANCELLER is the GuardianCanceller from the
    /// governance book, verified on chain (GenesisProfile `_bookGuardianCanceller`). Without the
    /// book it is an unexpected canceller; a book whose canceller does not verify is refused;
    /// and no other extra canceller is accepted even with the book.
    function test_extra_canceller_is_the_verified_guardian_canceller() public {
        vm.chainId(40204);
        DeployGenesisMembership s = _script();
        _expectRevert(bytes("GOVERNANCE_TIMELOCK: CANCELLER_ROLE is held by an account other than the multisig"));
        s.deployWith(SENDER, gov.governanceTimelock, gov.governanceMultisig, grantor, address(registry));

        string memory forged =
            vm.replace(govBookJson, vm.toString(gov.guardianCanceller), vm.toString(makeAddr("not-the-canceller")));
        _expectRevert(
            bytes(
                "GENESIS_GOVERNANCE_BOOK: GuardianCanceller is not at its CREATE2 address for (GovernanceTimelock, GuardianTimelock)"
            )
        );
        s.deployWith(SENDER, gov.governanceTimelock, gov.governanceMultisig, grantor, address(registry), forged);

        DeployGenesisMembership.Deployed memory d = s.deployWith(
            SENDER, gov.governanceTimelock, gov.governanceMultisig, grantor, address(registry), govBookJson
        );
        assertEq(MembershipStakeVault(payable(d.vault)).governance(), gov.governanceTimelock);

        // A second canceller next to the verified one is still refused.
        vm.prank(gov.governanceTimelock);
        TimelockController(payable(gov.governanceTimelock)).grantRole(keccak256("CANCELLER_ROLE"), makeAddr("x"));
        _expectRevert(bytes("GOVERNANCE_TIMELOCK: CANCELLER_ROLE is held by an account other than the multisig"));
        s.deployWith(SENDER, gov.governanceTimelock, gov.governanceMultisig, grantor, address(registry), govBookJson);
    }

    /// The vault leaves the ceremony with no treasury: only GOVERNANCE sets it, two-step,
    /// through the timelock; the grantor cannot.
    function test_treasury_is_set_only_by_governance() public {
        DeployGenesisMembership.Deployed memory d = _deploy();
        MembershipStakeVault v = MembershipStakeVault(payable(d.vault));
        assertEq(v.treasury(), address(0));
        vm.prank(grantor);
        vm.expectRevert(MembershipStakeVault.NotGovernance.selector);
        v.setTreasury(grantor);
        address t = makeAddr("treasury");
        _govern(d.vault, abi.encodeCall(MembershipStakeVault.setTreasury, (t)));
        vm.prank(t);
        v.acceptTreasury();
        assertEq(v.treasury(), t);
    }

    /// No node behind the role-history read (the production path under `forge test`): refused
    /// before anything is sent.
    function test_missing_role_history_fails_closed() public {
        DeployGenesisMembership live = new DeployGenesisMembership();
        uint64 nonceBefore = vm.getNonce(SENDER);
        _expectRevert(
            bytes(
                string.concat(
                    "GOVERNANCE_TIMELOCK: role history unavailable: eth_getLogs failed for blocks 0-",
                    vm.toString(block.number)
                )
            )
        );
        live.deployWith(SENDER, gov.governanceTimelock, gov.governanceMultisig, grantor, address(registry));
        assertEq(vm.getNonce(SENDER), nonceBefore, "nothing broadcast");
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    function _council(uint256 threshold, uint256 n, uint256 delay)
        internal
        returns (DeployGenesisGovernance.Deployed memory)
    {
        address[] memory owners = new address[](n);
        for (uint256 i = 0; i < n; i++) {
            owners[i] = address(uint160(0xC000 + (threshold << 8) + (n << 4) + i));
        }
        address[] memory grdOwners = new address[](3);
        for (uint256 i = 0; i < 3; i++) {
            grdOwners[i] = address(uint160(0xB000 + i));
        }
        return new DeployGenesisGovernance()
            .deployWith(
                SENDER,
                DeployGenesisGovernance.Council({
                    owners: owners, threshold: threshold, minDelay: delay, proposalTtl: 14 days
                }),
                // GUARDIAN delay = delay / 2: its timelock address depends on (deployer, delay), and
                // setUp's 1 h guardian timelock is already handed over.
                DeployGenesisGovernance.Council({
                    owners: grdOwners, threshold: 2, minDelay: delay / 2, proposalTtl: 14 days
                }),
                false,
                true // rehearsal chain: weak councils are the point of this helper
            );
    }

    /// A >= 48 h OZ timelock deployed as the ceremony does (CREATE2 through the factory under
    /// "Genesis.GovernanceTimelock", so its role history provably starts at its construction),
    /// deployer-administered for now, with a ceremony-provenance council holding all three
    /// seats. The delay is 48 h plus a sequence number of seconds: setUp owns the exact-48 h
    /// address. The caller adds any extra seats, then `_finish`.
    function _handedTimelock() internal returns (TimelockController tl, MultisigProposer ms) {
        bytes memory tlInit = abi.encodePacked(
            type(TimelockController).creationCode,
            abi.encode(48 hours + (++timelockSeq), new address[](0), new address[](0), SENDER)
        );
        (bool okTl, bytes memory retTl) =
            ARACHNID.call(abi.encodePacked(Salts.salt("Genesis.GovernanceTimelock"), tlInit));
        require(okTl && retTl.length == 20, "factory deploy failed");
        tl = TimelockController(payable(address(bytes20(retTl))));
        bytes memory init = abi.encodePacked(
            type(MultisigProposer).creationCode, abi.encode(address(tl), govOwners, uint256(3), uint256(14 days))
        );
        (bool ok, bytes memory ret) = ARACHNID.call(abi.encodePacked(Salts.salt(GOV_SALT), init));
        require(ok && ret.length == 20, "factory deploy failed");
        ms = MultisigProposer(address(bytes20(ret)));
        _grantCouncil(tl, address(ms));
    }

    function _grantCouncil(TimelockController tl, address ms) internal {
        vm.startPrank(SENDER);
        tl.grantRole(tl.PROPOSER_ROLE(), ms);
        tl.grantRole(tl.EXECUTOR_ROLE(), ms);
        tl.grantRole(tl.CANCELLER_ROLE(), ms);
        vm.stopPrank();
    }

    function _finish(TimelockController tl) internal {
        bytes32 adminRole = tl.DEFAULT_ADMIN_ROLE();
        vm.prank(SENDER);
        tl.renounceRole(adminRole, SENDER);
    }
}
