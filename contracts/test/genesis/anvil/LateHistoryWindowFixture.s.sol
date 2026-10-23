// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {MultisigProposer} from "../../../src/genesis/MultisigProposer.sol";
import {Salts} from "../../../script/Salts.sol";

/// @notice One transaction that emits the pair a TimelockController constructor ends with:
///         `RoleGranted(DEFAULT_ADMIN_ROLE, timelock, …)` and `MinDelayChange(0, d)`. Needs
///         DEFAULT_ADMIN, PROPOSER and EXECUTOR on a timelock whose delay is 0 and which no
///         longer administers itself.
contract ConstructionPairEmitter {
    function emitPair(TimelockController tl, uint256 newDelay) external {
        tl.grantRole(tl.DEFAULT_ADMIN_ROLE(), address(tl));
        bytes memory call = abi.encodeCall(TimelockController.updateDelay, (newDelay));
        tl.schedule(address(tl), 0, call, bytes32(0), bytes32(0), 0);
        tl.execute(address(tl), 0, call, bytes32(0), bytes32(0));
    }

    function renounceAll(TimelockController tl) external {
        tl.renounceRole(tl.DEFAULT_ADMIN_ROLE(), address(this));
        tl.renounceRole(tl.PROPOSER_ROLE(), address(this));
        tl.renounceRole(tl.EXECUTOR_ROLE(), address(this));
    }
}

/// @title LateHistoryWindowFixture: CI fixture for scripts/ci/genesis-pipeline-anvil.sh (chain#320)
/// @notice Builds, on a throwaway anvil chain, a GOVERNANCE timelock that a role-history window
///         starting after its construction would mistake for a clean one:
///           1. TimelockController(0, [], [], admin = FIXTURE_ADMIN) through the CREATE2 factory under
///              the ceremony salt, and its CREATE2-correct 3-of-5 MultisigProposer;
///           2. an extra account (ROGUE) gets PROPOSER and EXECUTOR   <- the hidden seat
///           3. the timelock stops administering itself (prepares the pair);
///           --- LATE_FROM_BLOCK: everything below lies inside a window that starts here ---
///           4. one transaction emits RoleGranted(DEFAULT_ADMIN, timelock) + MinDelayChange(0, 48 h)
///           5. the council gets PROPOSER / EXECUTOR / CANCELLER, the helper and the admin renounce.
///         Steps 1-3 and 4-5 are two separate broadcasts (`stage` 1 and 2), so the pipeline can read
///         the block between them. The end state passes every check except the complete holder
///         sets: 48 h, 3-of-5, self-administered, no deploy-account seat, but ROGUE still proposes
///         and executes. Not a production path; anvil public test keys only.
///         Env: FIXTURE_ADMIN (the broadcaster), FIXTURE_OUT (JSON written after stage 1),
///         FIXTURE_STAGE (1 or 2), GOV_OWNERS (the council owners), FIXTURE_ROGUE.
contract LateHistoryWindowFixture is Script {
    uint256 internal constant DELAY = 48 hours;

    function run() external {
        uint256 stage = vm.envUint("FIXTURE_STAGE");
        address admin = vm.envAddress("FIXTURE_ADMIN");
        address rogue = vm.envAddress("FIXTURE_ROGUE");
        address[] memory owners = vm.envAddress("GOV_OWNERS", ",");
        address[] memory none = new address[](0);
        bytes memory tlInit = abi.encodePacked(type(TimelockController).creationCode, abi.encode(0, none, none, admin));
        TimelockController tl = TimelockController(payable(_create2(Salts.salt("Genesis.GovernanceTimelock"), tlInit)));
        bytes memory msInit =
            abi.encodePacked(type(MultisigProposer).creationCode, abi.encode(address(tl), owners, uint256(3)));
        address ms = _create2(Salts.salt("Genesis.GovernanceMultisig"), msInit);

        if (stage == 1) {
            vm.startBroadcast(admin);
            new TimelockController{salt: Salts.salt("Genesis.GovernanceTimelock")}(0, none, none, admin);
            new MultisigProposer{salt: Salts.salt("Genesis.GovernanceMultisig")}(address(tl), owners, 3);
            tl.grantRole(tl.PROPOSER_ROLE(), rogue);
            tl.grantRole(tl.EXECUTOR_ROLE(), rogue);
            ConstructionPairEmitter helper = new ConstructionPairEmitter();
            tl.grantRole(tl.DEFAULT_ADMIN_ROLE(), address(helper));
            tl.grantRole(tl.PROPOSER_ROLE(), address(helper));
            tl.grantRole(tl.EXECUTOR_ROLE(), address(helper));
            tl.revokeRole(tl.DEFAULT_ADMIN_ROLE(), address(tl));
            vm.stopBroadcast();
            vm.writeFile(
                vm.envString("FIXTURE_OUT"),
                string.concat(
                    '{"timelock":"',
                    vm.toString(address(tl)),
                    '","multisig":"',
                    vm.toString(ms),
                    '","helper":"',
                    vm.toString(address(helper)),
                    '"}'
                )
            );
            return;
        }
        require(stage == 2, "FIXTURE_STAGE must be 1 or 2");
        ConstructionPairEmitter h = ConstructionPairEmitter(vm.envAddress("FIXTURE_HELPER"));
        vm.startBroadcast(admin);
        h.emitPair(tl, DELAY);
        tl.grantRole(tl.PROPOSER_ROLE(), ms);
        tl.grantRole(tl.EXECUTOR_ROLE(), ms);
        tl.grantRole(tl.CANCELLER_ROLE(), ms);
        h.renounceAll(tl);
        tl.renounceRole(tl.DEFAULT_ADMIN_ROLE(), admin);
        vm.stopBroadcast();
    }

    function _create2(bytes32 salt, bytes memory init) internal pure returns (address) {
        return address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            bytes1(0xff), 0x4e59b44847b379578588920cA78FbF26c0B4956C, salt, keccak256(init)
                        )
                    )
                )
            )
        );
    }
}
