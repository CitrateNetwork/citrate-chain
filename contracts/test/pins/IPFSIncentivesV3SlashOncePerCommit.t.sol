// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {IPFSIncentivesV3} from "../../src/IPFSIncentivesV3.sol";
import {KYCRegistry} from "../../src/KYCRegistry.sol";
import {MockVerifier, MockFoldVerifier} from "../IPFSIncentivesV3.t.sol";

/// @notice Pins `slash`'s once-per-commit rule at MAX_MISSED = 1, the value the
///         redeploy script ships. The main V3 suite runs at MAX_MISSED = 0,
///         where the first slash already terminates the pin, so a second slash
///         against the same commit was refused by "Pin not active" and the
///         per-commit check itself was never exercised.
contract IPFSIncentivesV3SlashOncePerCommitTest is Test {
    IPFSIncentivesV3 internal inc;
    KYCRegistry internal kyc;
    MockFoldVerifier internal fold;

    address internal constant VERIFY = 0x0000000000000000000000000000000000000108;
    address internal pinner = address(0xBEEF);
    address internal caller = address(0xF00D);
    address internal modelOwner = address(0x310D);

    uint256 internal constant BOND = 10 ether;
    uint256 internal constant REWARD = 4 ether;
    uint256 internal constant ROUNDS = 4;
    uint256 internal constant MAX_MISSED = 1; // as deployed: two missed windows slash
    uint256 internal constant CHALLENGER_BPS = 5000;
    uint256 internal constant QUORUM = 2;
    uint256 internal constant WINDOW = 10;
    uint256 internal constant REVEAL_DELAY = 32;

    bytes32 internal cid = keccak256("ipfs://model");
    uint256 internal sector = 0;

    function setUp() public {
        kyc = new KYCRegistry(address(0), address(this));
        fold = new MockFoldVerifier();
        inc = new IPFSIncentivesV3(
            kyc,
            BOND,
            REWARD,
            ROUNDS,
            MAX_MISSED,
            CHALLENGER_BPS,
            QUORUM,
            WINDOW,
            32,
            1 ether,
            REVEAL_DELAY,
            5 ether,
            100,
            5000,
            address(fold),
            address(this)
        );
        vm.etch(VERIFY, type(MockVerifier).runtimeCode);
        (bool ok,) = VERIFY.call(abi.encodeWithSignature("setVerdict(uint256)", uint256(1)));
        require(ok, "setVerdict");
        vm.deal(address(this), 10_000 ether);
        inc.fund{value: 5_000 ether}();

        kyc.setVerified(pinner);
        vm.deal(pinner, 1_000 ether);
        vm.deal(modelOwner, 1_000 ether);

        vm.prank(modelOwner);
        inc.registerModel{value: 5 ether}(cid, keccak256("D"), keccak256("data"), keccak256("dc"), "ipfs://x");
        vm.prank(pinner);
        inc.registerPinner();
        vm.prank(pinner);
        inc.sealCommit{value: BOND}(
            cid,
            sector,
            keccak256(abi.encode("rid", pinner)),
            1,
            keccak256("D"),
            keccak256("R"),
            keccak256("C"),
            hex"DEADBEEF"
        );
    }

    function _commitAndLapse() internal {
        inc.commitChallenge(cid, sector);
        vm.roll(block.number + REVEAL_DELAY + WINDOW + 1);
    }

    function _pin() internal view returns (IPFSIncentivesV3.Status st, uint64 missed, uint256 bondHeld) {
        (st,, missed,, bondHeld,) = inc.getPin(pinner, cid, sector);
    }

    /// One lapsed commit counts as one missed window, however often `slash`
    /// is called against it.
    function test_secondSlashAgainstTheSameCommitIsRefused() public {
        _commitAndLapse();

        vm.prank(caller);
        inc.slash(pinner, cid, sector);
        (IPFSIncentivesV3.Status st, uint64 missed, uint256 bondHeld) = _pin();
        assertEq(uint256(st), uint256(IPFSIncentivesV3.Status.Active), "one miss keeps the pin active");
        assertEq(missed, 1);
        assertEq(bondHeld, BOND);

        vm.prank(caller);
        vm.expectRevert("Commit already evaluated");
        inc.slash(pinner, cid, sector);

        (st, missed, bondHeld) = _pin();
        assertEq(uint256(st), uint256(IPFSIncentivesV3.Status.Active), "pin survives the repeat call");
        assertEq(missed, 1, "the repeat call must not count a second miss");
        assertEq(bondHeld, BOND, "bond untouched");
        assertEq(inc.challengerCredit(caller), 0, "no slash reward for re-evaluating one commit");
    }

    /// The rule is per commit, not a permanent lock: a second lapsed commit is
    /// a second miss and does slash at MAX_MISSED = 1.
    function test_aSecondLapsedCommitStillSlashes() public {
        _commitAndLapse();
        inc.slash(pinner, cid, sector);

        _commitAndLapse();
        vm.prank(caller);
        inc.slash(pinner, cid, sector);

        (IPFSIncentivesV3.Status st,, uint256 bondHeld) = _pin();
        assertEq(uint256(st), uint256(IPFSIncentivesV3.Status.Slashed));
        assertEq(bondHeld, 0);
        assertEq(inc.challengerCredit(caller), (BOND * CHALLENGER_BPS) / 10000);
    }
}
