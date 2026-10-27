// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {AdminChecks} from "../../script/lib/AdminChecks.sol";

contract GenesisModeHarness is AdminChecks {
    string public allocPath;

    function setAllocPath(string memory p) external {
        allocPath = p;
    }

    function _genesisChainMode(address) internal pure override returns (bool) {
        return true;
    }

    function _genesisAllocPath() internal view override returns (string memory) {
        return allocPath;
    }

    function setKnown(address[] memory known) external {
        delete genesisKnown;
        for (uint256 i = 0; i < known.length; i++) {
            genesisKnown.push(known[i]);
        }
    }

    function holderProblem(address timelock, address council, address[] memory extra) external returns (string memory) {
        return _timelockHolderProblem(timelock, council, extra);
    }
}

/// Genesis-chain mode of the timelock holder check (r1006: contracts in block 0, no role-grant
/// events). The holder sets are proved from state: hasRole for the expected holders and every
/// known account, and every non-zero slot of the block-0 allocation accounted for.
contract AdminChecksGenesisModeTest is Test {
    GenesisModeHarness h;
    TimelockController tl;
    address council = address(0xC0C0);
    address deployer = address(0xD0D0);
    address intruder = address(0xBAD); // in no book, no input: only the alloc can reveal it
    bytes32 constant PROPOSER = keccak256("PROPOSER_ROLE");
    bytes32 constant CANCELLER = keccak256("CANCELLER_ROLE");
    string allocPath;

    function setUp() public {
        h = new GenesisModeHarness();
        address[] memory p = new address[](1);
        p[0] = council;
        tl = new TimelockController(2 days, p, p, address(0));
        address[] memory known = new address[](2);
        (known[0], known[1]) = (deployer, address(tl));
        h.setKnown(known);
    }

    function _roleSlot(bytes32 role, address who) internal pure returns (bytes32) {
        return keccak256(abi.encode(who, keccak256(abi.encode(role, uint256(0)))));
    }

    /// The block-0 allocation of the timelock as the genesis builder writes it: every non-zero
    /// slot the constructor wrote (plus `extra`, slots injected into the state).
    function _writeAlloc(string memory label, bytes32[] memory extra) internal {
        // One file per test (the suite runs its tests in parallel).
        allocPath = string.concat("genesis/test-genesis-mode-alloc-", label, ".json");
        h.setAllocPath(allocPath);
        bytes32[] memory slots = new bytes32[](4 + extra.length);
        slots[0] = bytes32(uint256(2)); // _minDelay
        slots[1] = _roleSlot(bytes32(0), address(tl));
        slots[2] = _roleSlot(PROPOSER, council);
        slots[3] = _roleSlot(keccak256("EXECUTOR_ROLE"), council);
        for (uint256 i = 0; i < extra.length; i++) {
            slots[4 + i] = extra[i];
        }
        string memory st = "{";
        for (uint256 i = 0; i < slots.length; i++) {
            st = string.concat(
                st, i == 0 ? "" : ",", '"', vm.toString(slots[i]), '":"', vm.toString(vm.load(address(tl), slots[i])), '"'
            );
        }
        // The canceller slot the constructor writes for the proposer.
        st = string.concat(
            st, ',"', vm.toString(_roleSlot(CANCELLER, council)), '":"',
            vm.toString(vm.load(address(tl), _roleSlot(CANCELLER, council))), '"}'
        );
        string memory json = string.concat(
            '{"alloc":{"', vm.toLowercase(vm.toString(address(tl))), '":{"storage":', st, "}}}"
        );
        vm.writeFile(allocPath, json);
    }

    function test_the_clean_genesis_state_passes() public {
        _writeAlloc("clean", new bytes32[](0));
        assertEq(h.holderProblem(address(tl), council, new address[](0)), "");
    }

    function test_an_extra_holder_outside_every_book_fails_through_the_alloc() public {
        // An unknown account given PROPOSER in the block-0 state: no book or input names it, so
        // only the allocation's storage can reveal it.
        bytes32 s = _roleSlot(PROPOSER, intruder);
        vm.store(address(tl), s, bytes32(uint256(1)));
        bytes32[] memory extra = new bytes32[](1);
        extra[0] = s;
        _writeAlloc("intruder", extra);
        assertEq(
            h.holderProblem(address(tl), council, new address[](0)),
            "an unaccounted storage slot (a role holder outside the expected set, a changed role admin, or a scheduled operation)"
        );
    }

    function test_a_known_account_holding_a_role_fails_even_with_a_stale_alloc() public {
        _writeAlloc("stale", new bytes32[](0)); // the alloc does not show it
        vm.store(address(tl), _roleSlot(CANCELLER, deployer), bytes32(uint256(1)));
        assertEq(
            h.holderProblem(address(tl), council, new address[](0)),
            "CANCELLER_ROLE is held by an account other than the expected set"
        );
    }

    function test_an_alloc_that_is_not_this_chain_state_fails() public {
        _writeAlloc("notstate", new bytes32[](0));
        vm.store(address(tl), bytes32(uint256(2)), bytes32(uint256(1 days))); // state moved under the alloc
        assertEq(
            h.holderProblem(address(tl), council, new address[](0)),
            "GENESIS_ALLOC disagrees with the chain's state of the timelock"
        );
    }

    function test_a_missing_expected_holder_fails() public {
        _writeAlloc("missing", new bytes32[](0));
        vm.store(address(tl), _roleSlot(keccak256("EXECUTOR_ROLE"), council), bytes32(0));
        assertEq(
            h.holderProblem(address(tl), council, new address[](0)), "EXECUTOR_ROLE: an expected holder does not hold it"
        );
    }

    function test_genesis_mode_without_the_alloc_fails_closed() public {
        h.setAllocPath("");
        assertEq(
            h.holderProblem(address(tl), council, new address[](0)),
            "genesis-chain mode needs GENESIS_ALLOC (the block-0 allocation) to prove the holder sets complete"
        );
    }

    function test_the_allowed_extra_canceller_is_accounted_for() public {
        address guardianCanceller = address(0x6C6C);
        bytes32 s = _roleSlot(CANCELLER, guardianCanceller);
        vm.store(address(tl), s, bytes32(uint256(1)));
        bytes32[] memory extra = new bytes32[](1);
        extra[0] = s;
        _writeAlloc("canceller", extra);
        address[] memory allowed = new address[](1);
        allowed[0] = guardianCanceller;
        assertEq(h.holderProblem(address(tl), council, allowed), "");
        // ...and is an unexpected canceller when it is not the allowed one.
        assertTrue(bytes(h.holderProblem(address(tl), council, new address[](0))).length != 0);
    }
}
