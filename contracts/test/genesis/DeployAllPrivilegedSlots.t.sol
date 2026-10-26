// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {DeployAll} from "../../script/DeployAll.s.sol";
import {ComputeMarketplace} from "../../src/ComputeMarketplace.sol";
import {ComputeVerifier} from "../../src/ComputeVerifier.sol";
import {X402Facilitator} from "../../src/X402Facilitator.sol";
import {ModelMarketplace} from "../../src/ModelMarketplace.sol";
import {TreasuryGovernor} from "../../src/TreasuryGovernor.sol";
import {AdminChecks} from "../../script/lib/AdminChecks.sol";
import {CheckDeployedAdmins} from "../../script/CheckDeployedAdmins.s.sol";
import {ScriptEnv} from "../../script/ScriptEnv.sol";

contract SlotSweep is AdminChecks {
    function problem(address t, address deployer) external view returns (string memory) {
        return _deployerAdminProblem(t, deployer);
    }
}

/// Exposes the TREASURY input rule under a caller-chosen key, so tests can
/// set unique environment keys without racing each other.
contract TreasuryInput is ScriptEnv {
    function read(string memory key, address deployer, address governance) external view returns (address) {
        return requiredTreasury(key, deployer, governance);
    }
}

/// After DeployAll the deploy account holds nothing: no fee recipient, no
/// bound caller, no role. The compute stack it leaves behind is wired, so a
/// job can be posted and settled straight away, with the protocol fee paid to
/// the treasury the ceremony named.
contract DeployAllPrivilegedSlotsTest is Test {
    address constant SENDER = 0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38; // forge default sender = the deployer

    address governance = makeAddr("governance");
    address guardian = makeAddr("guardian");

    DeployAll.Deployed d;

    // Commitment-tier job (value <= ComputeVerifier.VALUE_THRESHOLD).
    uint256 constant PRICE = 8 ether;
    bytes32 constant MODEL = keccak256("deployall-e2e-model");
    bytes constant OUTPUT = hex"01020304";
    bytes32 constant NONCE = keccak256("deployall-e2e-nonce");

    function setUp() public {
        d = new DeployAll().deployWith(SENDER, governance, guardian);
    }

    function test_feeRecipients_areNotTheDeployer() public view {
        assertTrue(X402Facilitator(d.facilitator).treasury() != SENDER, "X402Facilitator.treasury is the deployer");
        assertTrue(
            ModelMarketplace(payable(d.modelMarketplace)).treasuryAddress() != SENDER,
            "ModelMarketplace.treasuryAddress is the deployer"
        );
        assertTrue(
            ComputeMarketplace(payable(d.computeMarketplace)).treasury() != SENDER,
            "ComputeMarketplace.treasury is the deployer"
        );
    }

    function test_computeVerifier_isBoundToTheDeployedMarketplace() public view {
        assertEq(
            ComputeVerifier(d.verifier).marketplace(), d.computeMarketplace, "verifier's caller is the marketplace"
        );
    }

    /// Post -> bid -> assign -> execute -> commit -> verify -> complete on the
    /// stack exactly as DeployAll left it (no governance step in between).
    function test_computeMarketplace_jobRunsEndToEnd() public {
        ComputeMarketplace cm = ComputeMarketplace(payable(d.computeMarketplace));
        address requester = makeAddr("requester");
        address provider = makeAddr("provider");
        vm.deal(requester, 100 ether);
        vm.deal(provider, 2_000 ether);

        bytes32[] memory models = new bytes32[](1);
        models[0] = MODEL;
        vm.prank(provider);
        cm.registerProvider{value: 1_000 ether}(models);

        vm.prank(requester);
        (bool posted, bytes memory ret) = address(cm).call{value: PRICE}(
            abi.encodeCall(
                cm.postJob, (MODEL, abi.encodePacked(bytes32(uint256(1))), PRICE, ComputeVerifier.VerificationTier.Commitment, 10, 100)
            )
        );
        assertTrue(posted, "a job can be posted on the deployed marketplace");
        uint256 jobId = abi.decode(ret, (uint256));

        vm.prank(provider);
        cm.bidOnJob(jobId, 6 ether, 100);
        cm.assignBestBid(jobId);
        vm.prank(provider);
        cm.startExecution(jobId);
        bytes32 commitment = keccak256(abi.encodePacked(OUTPUT, NONCE));
        vm.prank(provider);
        cm.submitCommitment(jobId, commitment);
        uint256 h = block.number + 1; // via-IR: track the height locally
        vm.roll(h);
        vm.prank(provider);
        cm.submitResult(jobId, OUTPUT, abi.encodePacked(commitment, NONCE, OUTPUT));
        assertEq(
            uint256(ComputeVerifier(d.verifier).getResult(jobId)), uint256(ComputeVerifier.VerificationResult.Valid)
        );

        address feeTo = cm.treasury();
        uint256 before = feeTo.balance;
        vm.roll(h + cm.DISPUTE_WINDOW());
        cm.completeJob(jobId);
        assertEq(uint256(cm.getJob(jobId).state), uint256(ComputeMarketplace.JobState.Completed));
        assertEq(feeTo.balance - before, PRICE / 40, "protocol fee paid to the treasury");
        assertTrue(feeTo != SENDER, "fee went to the deployer");
    }

    function _all() internal view returns (address[27] memory) {
        return [
            d.registry, d.wsalt, d.agentRegistry, d.specRegistry, d.ipfs, d.facilitator, d.paywall,
            d.contributions, d.slashing, d.mmAlloc, d.modelMarketplace, d.router,
            d.loraFactory, d.learningPool, d.cycleManager, d.classroom, d.mentorMatcher, d.verifier,
            d.computeMarketplace, d.computePool, d.heartbeat, d.dispute, d.oracle, d.treasury,
            d.gateway, d.farming, d.governor
        ];
    }

    /// LiquidStakingPool is not part of block 0: DeployAll deploys none and
    /// TreasuryGovernor is born with the liquid-staking path disabled.
    function test_liquidStakingPool_isNotDeployed() public view {
        assertEq(d.stakingPool, address(0), "DeployAll deploys no LiquidStakingPool");
        assertEq(address(TreasuryGovernor(payable(d.governor)).stakingPool()), address(0), "governor has no pool");
    }

    function test_verifierHandOver_isClosed() public view {
        assertTrue(ComputeVerifier(d.verifier).marketplaceLocked(), "hand-over window closed after DeployAll");
    }

    /// Sweep every DeployAll contract with the full slot list. Under reroll the
    /// three kept registries are governance-held too; off reroll (this test)
    /// they are the documented deployer-governed exception.
    function test_noDeployedContract_namesTheDeployerInAnySlot() public {
        SlotSweep s = new SlotSweep();
        address[27] memory all = _all();
        for (uint256 i = 0; i < all.length; i++) {
            if (all[i] == d.agentRegistry || all[i] == d.specRegistry || all[i] == d.mmAlloc) continue;
            assertEq(s.problem(all[i], SENDER), "", string.concat("deployer slot on #", vm.toString(i)));
        }
    }

    /// A re-run that names another TREASURY would need a second marketplace
    /// for the same verifier: it fails closed with a clear reason.
    function test_rerunWithAnotherTreasury_failsClosed() public {
        DeployAll a = new DeployAll();
        vm.expectRevert(
            bytes("DeployAll: ComputeVerifier is bound to another ComputeMarketplace (re-run with the same TREASURY)")
        );
        a.deployWith(SENDER, governance, guardian, makeAddr("another-treasury"));
    }

    function test_deployerAsTreasury_isRefused() public {
        DeployAll a = new DeployAll();
        vm.expectRevert(bytes("DeployAll: fee recipient must not be the deployer"));
        a.deployWith(SENDER, governance, guardian, SENDER);
    }

    function test_zeroTreasury_isRefused() public {
        DeployAll a = new DeployAll();
        vm.expectRevert(bytes("DeployAll: zero fee recipient"));
        a.deployWith(SENDER, governance, guardian, address(0));
    }

    /// The P5 gate over a book of everything DeployAll deployed (reroll
    /// registries excluded as above) reports DEPLOYER-ADMIN 0.
    function test_checkDeployedAdmins_overTheDeployAllBook_isClean() public {
        vm.etch(0xc2b78104907F722DABAc4C69f826a522B2754De4, hex"600160005260206000f3");
        address[27] memory all = _all();
        string memory body;
        uint256 n;
        for (uint256 i = 0; i < all.length; i++) {
            if (all[i] == d.agentRegistry || all[i] == d.specRegistry || all[i] == d.mmAlloc) continue;
            body = string.concat(body, n == 0 ? "" : ",", '"C', vm.toString(i), '":"', vm.toString(all[i]), '"');
            n++;
        }
        CheckDeployedAdmins c = new CheckDeployedAdmins();
        c.check(string.concat('{"deployer":"', vm.toString(SENDER), '","contracts":{', body, '},"aaStack":{}}'), true);
        assertEq(c.deployerAdmin(), 0);
        assertEq(c.factoryAdmin(), 0);
    }

    // ---- TREASURY input (ScriptEnv.requiredTreasury) ----

    function test_treasuryInput_set_isUsed() public {
        TreasuryInput r = new TreasuryInput();
        address t = makeAddr("t");
        vm.setEnv("DPS_TREASURY_SET", vm.toString(t));
        assertEq(r.read("DPS_TREASURY_SET", SENDER, governance), t);
    }

    function test_treasuryInput_unset_offChain_isGovernance() public {
        TreasuryInput r = new TreasuryInput();
        assertEq(r.read("DPS_TREASURY_UNSET_A", SENDER, governance), governance);
    }

    function test_treasuryInput_unset_on40204_reverts() public {
        TreasuryInput r = new TreasuryInput();
        vm.chainId(40204);
        vm.expectRevert(bytes("DPS_TREASURY_UNSET_B must be set on 40204"));
        r.read("DPS_TREASURY_UNSET_B", SENDER, governance);
    }

    function test_treasuryInput_deployer_reverts() public {
        TreasuryInput r = new TreasuryInput();
        vm.setEnv("DPS_TREASURY_DEPLOYER", vm.toString(SENDER));
        vm.expectRevert(bytes("DPS_TREASURY_DEPLOYER must not be the deployer"));
        r.read("DPS_TREASURY_DEPLOYER", SENDER, governance);
    }

    function test_treasuryInput_malformed_reverts() public {
        TreasuryInput r = new TreasuryInput();
        vm.setEnv("DPS_TREASURY_BAD", "not-an-address");
        vm.expectRevert(bytes("DPS_TREASURY_BAD is set but is not an address"));
        r.read("DPS_TREASURY_BAD", SENDER, governance);
    }

    function test_treasuryInput_zero_reverts() public {
        TreasuryInput r = new TreasuryInput();
        vm.setEnv("DPS_TREASURY_ZERO", vm.toString(address(0)));
        vm.expectRevert(bytes("DPS_TREASURY_ZERO is the zero address"));
        r.read("DPS_TREASURY_ZERO", SENDER, governance);
    }
}

contract DeployAllExplicitTreasuryTest is Test {
    address constant SENDER = 0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38;
    address governance = makeAddr("governance");
    address guardian = makeAddr("guardian");

    /// An explicit TREASURY is every fee recipient.
    function test_explicitTreasury_isEveryFeeRecipient() public {
        address t = makeAddr("genesis-treasury");
        DeployAll.Deployed memory e = new DeployAll().deployWith(SENDER, governance, guardian, t);
        assertEq(X402Facilitator(e.facilitator).treasury(), t);
        assertEq(ModelMarketplace(payable(e.modelMarketplace)).treasuryAddress(), t);
        assertEq(ComputeMarketplace(payable(e.computeMarketplace)).treasury(), t);
        assertEq(ComputeVerifier(e.verifier).marketplace(), e.computeMarketplace);
    }
}
