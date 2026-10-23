// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {DeployTeamVesting} from "../../script/DeployTeamVesting.s.sol";
import {CheckDeployedAdmins} from "../../script/CheckDeployedAdmins.s.sol";
import {TeamVestingWallet} from "../../src/genesis/TeamVestingWallet.sol";
import {VestingWalletCliff} from "@openzeppelin/contracts/finance/VestingWalletCliff.sol";
import {InitialAdmin} from "../../src/lib/InitialAdmin.sol";

/// @title DeployTeamVesting.t: native-SALT team vesting through OZ VestingWalletCliff (C2 D2 / G2)
contract DeployTeamVestingTest is Test {
    address constant SENDER = 0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38; // forge default sender
    address constant P256_VERIFIER = 0xc2b78104907F722DABAc4C69f826a522B2754De4;

    uint64 constant START = 1_800_000_000;
    uint64 constant YEAR = 365 days;

    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    function setUp() public {
        vm.deal(SENDER, 1_000_000 ether);
        vm.warp(START - 1 days);
    }

    function _grants() internal view returns (DeployTeamVesting.Grant[] memory g) {
        g = new DeployTeamVesting.Grant[](2);
        g[0] = DeployTeamVesting.Grant({
            label: "team_a", beneficiary: alice, start: START, duration: 4 * YEAR, cliff: YEAR, amount: 4000 ether
        });
        g[1] = DeployTeamVesting.Grant({
            label: "team_b", beneficiary: bob, start: START, duration: 2 * YEAR, cliff: 0, amount: 1000 ether
        });
    }

    function _deploy() internal returns (address[] memory w) {
        DeployTeamVesting s = new DeployTeamVesting();
        w = s.deployWith(SENDER, _grants(), false);
    }

    // ── deploy + funding ────────────────────────────────────────────

    function test_deploys_and_funds_each_wallet_with_native_salt() public {
        address[] memory w = _deploy();
        assertEq(w[0].balance, 4000 ether);
        assertEq(w[1].balance, 1000 ether);
        TeamVestingWallet a = TeamVestingWallet(payable(w[0]));
        assertEq(a.owner(), alice);
        assertEq(a.start(), START);
        assertEq(a.duration(), 4 * YEAR);
        assertEq(a.cliff(), START + YEAR);
        assertEq(a.end(), START + 4 * YEAR);
    }

    function test_rerun_reuses_and_does_not_double_fund() public {
        address[] memory w1 = _deploy();
        address[] memory w2 = _deploy();
        assertEq(w1[0], w2[0]);
        assertEq(w1[1], w2[1]);
        assertEq(w2[0].balance, 4000 ether);
    }

    function test_rerun_after_a_release_tops_up_nothing() public {
        address[] memory w = _deploy();
        vm.warp(START + 2 * YEAR);
        TeamVestingWallet(payable(w[0])).release();
        assertEq(alice.balance, 2000 ether);
        // A re-run after `start` is a past start: refused unless explicitly allowed.
        DeployTeamVesting s = new DeployTeamVesting();
        vm.expectRevert(bytes("team_a: start is in the past (ALLOW_PAST_VESTING_START=1 to allow)"));
        s.deployWith(SENDER, _grants(), false);
        address[] memory again = s.deployWith(SENDER, _grants(), true);
        assertEq(again[0].balance, 2000 ether, "balance + released == amount, no new funding");
    }

    function test_rerun_fails_closed_when_a_wallet_is_overfunded() public {
        address[] memory w = _deploy();
        vm.deal(w[1], w[1].balance + 1);
        DeployTeamVesting s = new DeployTeamVesting();
        vm.expectRevert(bytes("TeamVesting.team_b: already holds more than its amount"));
        s.deployWith(SENDER, _grants(), false);
    }

    // ── vesting schedule (OZ VestingWalletCliff) ────────────────────

    function test_release_nothing_before_cliff() public {
        address[] memory w = _deploy();
        TeamVestingWallet a = TeamVestingWallet(payable(w[0]));
        vm.warp(START + YEAR - 1);
        assertEq(a.releasable(), 0);
        a.release();
        assertEq(alice.balance, 0);
        assertEq(a.released(), 0);
    }

    function test_release_at_cliff_pays_the_linear_share_since_start() public {
        address[] memory w = _deploy();
        TeamVestingWallet a = TeamVestingWallet(payable(w[0]));
        vm.warp(START + YEAR);
        a.release();
        assertEq(alice.balance, 1000 ether, "1 of 4 years vested at the cliff");
    }

    function test_release_linear_after_cliff_and_full_at_end() public {
        address[] memory w = _deploy();
        TeamVestingWallet a = TeamVestingWallet(payable(w[0]));
        vm.warp(START + 3 * YEAR);
        a.release();
        assertEq(alice.balance, 3000 ether);
        vm.warp(START + 4 * YEAR + 1);
        a.release();
        assertEq(alice.balance, 4000 ether);
        assertEq(w[0].balance, 0);
        assertEq(a.released(), 4000 ether);
    }

    function test_no_cliff_wallet_vests_linearly_from_start() public {
        address[] memory w = _deploy();
        TeamVestingWallet b = TeamVestingWallet(payable(w[1]));
        vm.warp(START);
        assertEq(b.releasable(), 0);
        vm.warp(START + YEAR / 2);
        b.release();
        assertEq(bob.balance, 250 ether);
    }

    function test_release_is_permissionless_and_pays_the_owner() public {
        address[] memory w = _deploy();
        vm.warp(START + 2 * YEAR);
        vm.prank(makeAddr("anyone"));
        TeamVestingWallet(payable(w[0])).release();
        assertEq(alice.balance, 2000 ether);
    }

    /// For any time t, released + releasable == the OZ cliff/linear formula.
    function testFuzz_vested_amount_matches_cliff_linear(uint64 dt) public {
        address[] memory w = _deploy();
        TeamVestingWallet a = TeamVestingWallet(payable(w[0]));
        dt = uint64(bound(dt, 0, 6 * YEAR));
        uint64 t = START + dt;
        vm.warp(t);
        uint256 expected;
        if (t < START + YEAR) expected = 0;
        else if (t >= START + 4 * YEAR) expected = 4000 ether;
        else expected = (4000 ether * uint256(t - START)) / (4 * YEAR);
        assertEq(a.vestedAmount(t), expected);
        a.release();
        assertEq(alice.balance, expected);
        assertEq(w[0].balance, 4000 ether - expected);
    }

    // ── validation ──────────────────────────────────────────────────

    function test_rejects_cliff_longer_than_duration() public {
        DeployTeamVesting.Grant[] memory g = _grants();
        g[1].cliff = g[1].duration + 1;
        DeployTeamVesting s = new DeployTeamVesting();
        vm.expectRevert(bytes("team_b: cliff exceeds duration"));
        s.deployWith(SENDER, g, false);
    }

    function test_rejects_zero_amount_duration_start_and_beneficiary() public {
        DeployTeamVesting s = new DeployTeamVesting();
        DeployTeamVesting.Grant[] memory g = _grants();
        g[0].amount = 0;
        vm.expectRevert(bytes("team_a: amount must be > 0"));
        s.deployWith(SENDER, g, false);
        g = _grants();
        g[0].duration = 0;
        g[0].cliff = 0;
        vm.expectRevert(bytes("team_a: duration must be > 0"));
        s.deployWith(SENDER, g, false);
        g = _grants();
        g[0].start = 0;
        vm.expectRevert(bytes("team_a: start must be set"));
        s.deployWith(SENDER, g, false);
        g = _grants();
        g[0].beneficiary = address(0);
        vm.expectRevert(bytes("team_a: zero beneficiary"));
        s.deployWith(SENDER, g, false);
    }

    function test_rejects_start_in_the_past_unless_allowed() public {
        DeployTeamVesting.Grant[] memory g = _grants();
        g[1].start = uint64(block.timestamp - 1);
        DeployTeamVesting s = new DeployTeamVesting();
        uint64 nonceBefore = vm.getNonce(SENDER);
        vm.expectRevert(bytes("team_b: start is in the past (ALLOW_PAST_VESTING_START=1 to allow)"));
        s.deployWith(SENDER, g, false);
        assertEq(vm.getNonce(SENDER), nonceBefore, "nothing broadcast");
        address[] memory w = s.deployWith(SENDER, g, true);
        assertEq(TeamVestingWallet(payable(w[1])).start(), block.timestamp - 1);
    }

    function test_start_at_the_deploy_timestamp_is_accepted() public {
        DeployTeamVesting.Grant[] memory g = _grants();
        g[0].start = uint64(block.timestamp);
        DeployTeamVesting s = new DeployTeamVesting();
        address[] memory w = s.deployWith(SENDER, g, false);
        assertEq(TeamVestingWallet(payable(w[0])).start(), block.timestamp);
    }

    /// Boundary: any start >= now is accepted, any start < now refused without the override.
    function testFuzz_past_start_boundary(uint64 startSeed) public {
        uint64 start = uint64(bound(startSeed, 1, block.timestamp + 10 * YEAR));
        DeployTeamVesting.Grant[] memory g = _grants();
        g[0].start = start;
        g[1].start = uint64(block.timestamp);
        DeployTeamVesting s = new DeployTeamVesting();
        if (start < block.timestamp) {
            vm.expectRevert(bytes("team_a: start is in the past (ALLOW_PAST_VESTING_START=1 to allow)"));
            s.deployWith(SENDER, g, false);
        } else {
            address[] memory w = s.deployWith(SENDER, g, false);
            assertEq(TeamVestingWallet(payable(w[0])).start(), start);
        }
    }

    function test_rejects_cliff_longer_than_duration_and_zero_duration_even_when_past_start_allowed() public {
        DeployTeamVesting s = new DeployTeamVesting();
        DeployTeamVesting.Grant[] memory g = _grants();
        g[0].cliff = g[0].duration + 1;
        vm.expectRevert(bytes("team_a: cliff exceeds duration"));
        s.deployWith(SENDER, g, true);
        g = _grants();
        g[1].duration = 0;
        vm.expectRevert(bytes("team_b: duration must be > 0"));
        s.deployWith(SENDER, g, true);
    }

    function test_rejects_deployer_as_beneficiary_and_duplicate_label() public {
        DeployTeamVesting s = new DeployTeamVesting();
        DeployTeamVesting.Grant[] memory g = _grants();
        g[1].beneficiary = SENDER;
        vm.expectRevert(bytes("team_b: beneficiary is the deployer"));
        s.deployWith(SENDER, g, false);
        g = _grants();
        g[1].label = "team_a";
        vm.expectRevert(bytes("duplicate label team_a"));
        s.deployWith(SENDER, g, false);
    }

    /// Signer-mismatch regression: DEPLOYER_ADDRESS names A but Forge broadcasts as B, and a
    /// grant names B as its beneficiary. The script must revert before deploying or funding.
    function test_reverts_when_broadcaster_is_not_the_configured_deployer() public {
        address configured = makeAddr("configured-deployer-A");
        DeployTeamVesting s = new DeployTeamVesting();
        DeployTeamVesting.Grant[] memory g = _grants();
        g[1].beneficiary = SENDER; // the actual broadcaster (B)
        uint64 nonceBefore = vm.getNonce(SENDER);
        uint256 balanceBefore = SENDER.balance;
        vm.expectRevert(bytes("broadcast sender is not the configured deployer (DEPLOYER_ADDRESS)"));
        s.deployWith(configured, g, false); // broadcasts as SENDER (B)
        assertEq(vm.getNonce(SENDER), nonceBefore, "nothing broadcast");
        assertEq(SENDER.balance, balanceBefore, "nothing funded");
    }

    /// Same mismatch with a schedule that names neither account: still refused, nothing sent.
    function test_reverts_on_signer_mismatch_even_with_a_clean_schedule() public {
        DeployTeamVesting s = new DeployTeamVesting();
        uint64 nonceBefore = vm.getNonce(SENDER);
        uint256 balanceBefore = SENDER.balance;
        vm.expectRevert(bytes("broadcast sender is not the configured deployer (DEPLOYER_ADDRESS)"));
        s.deployWith(makeAddr("configured-deployer-A"), _grants(), false);
        assertEq(vm.getNonce(SENDER), nonceBefore, "nothing broadcast");
        assertEq(SENDER.balance, balanceBefore, "nothing funded");
    }

    function test_wallet_refuses_factory_beneficiary_and_long_cliff() public {
        vm.expectRevert(InitialAdmin.InitialAdmin_Create2Factory.selector);
        new TeamVestingWallet(InitialAdmin.CREATE2_FACTORY, START, YEAR, 0);
        vm.expectRevert(
            abi.encodeWithSelector(VestingWalletCliff.InvalidCliffDuration.selector, uint64(YEAR + 1), uint64(YEAR))
        );
        new TeamVestingWallet(alice, START, YEAR, YEAR + 1);
    }

    // ── run(): JSON schedule in, book out ───────────────────────────

    /// The only test that sets TEAM_VESTING_* (vm.setEnv is process-global).
    function test_run_reads_the_schedule_file_and_writes_a_gated_book() public {
        vm.setEnv("DEPLOYER_ADDRESS", vm.toString(SENDER));
        DeployTeamVesting s = new DeployTeamVesting();
        vm.expectRevert();
        s.run(); // TEAM_VESTING_FILE unset

        vm.createDir("genesis", true);
        string memory input = "genesis/test-team-vesting-in.json";
        string memory out = "genesis/test-team-vesting-out.json";
        vm.writeFile(
            input,
            string.concat(
                '{"wallets":[{"label":"team_a","beneficiary":"',
                vm.toString(alice),
                '","start":1800000000,"duration":126144000,"cliff":31536000,"amount":"4000000000000000000000"},',
                '{"label":"team_b","beneficiary":"',
                vm.toString(bob),
                '","start":1800000000,"duration":63072000,"cliff":0,"amount":"1000000000000000000000"}]}'
            )
        );
        vm.setEnv("TEAM_VESTING_FILE", input);
        vm.expectRevert();
        s.run(); // TEAM_VESTING_OUT unset

        vm.setEnv("TEAM_VESTING_OUT", out);
        address[] memory w = s.run();
        assertEq(w.length, 2);
        assertEq(w[0].balance, 4000 ether);
        assertEq(TeamVestingWallet(payable(w[1])).duration(), 2 * YEAR);

        string memory book = vm.readFile(out);
        assertEq(vm.parseJsonAddress(book, ".contracts.TeamVesting_team_a"), w[0]);

        // After `start`, the same schedule is a past start: refused until ALLOW_PAST_VESTING_START=1.
        uint256 t = block.timestamp;
        vm.warp(1_800_000_001);
        vm.expectRevert(bytes("team_a: start is in the past (ALLOW_PAST_VESTING_START=1 to allow)"));
        s.run();
        vm.setEnv("ALLOW_PAST_VESTING_START", "1");
        address[] memory w2 = s.run();
        assertEq(w2[0], w[0], "re-run reuses the wallet");
        vm.setEnv("ALLOW_PAST_VESTING_START", "0");
        vm.warp(t);
        assertEq(vm.parseJsonString(book, ".params.totalWei"), "5000000000000000000000");

        vm.etch(P256_VERIFIER, hex"600160005260206000f3");
        CheckDeployedAdmins c = new CheckDeployedAdmins();
        c.check(book, true);
        assertEq(c.deployerAdmin(), 0);
        vm.removeFile(input);
        vm.removeFile(out);
    }

    function test_parse_rejects_an_empty_schedule() public {
        DeployTeamVesting s = new DeployTeamVesting();
        vm.expectRevert(bytes("TEAM_VESTING_FILE: no wallets"));
        s.parseGrants('{"wallets":[]}');
    }
}
