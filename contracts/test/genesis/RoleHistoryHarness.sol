// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Vm} from "forge-std/Vm.sol";
import {AdminChecks} from "../../script/lib/AdminChecks.sol";
import {DeployDormantLedgers} from "../../script/DeployDormantLedgers.s.sol";
import {CheckDeployedAdmins} from "../../script/CheckDeployedAdmins.s.sol";

/// @title Node stand-in for the timelock role history (AdminChecks `_timelockRoleHistory`)
/// @notice `forge test` has no node, so the real `_timelockRoleHistory` (paged eth_getLogs)
///         fails closed there. These harnesses replace only that read with the logs the test
///         itself emitted: the test calls `vm.recordLogs()` before it deploys anything, and
///         `RoleLogArchive` accumulates them (`vm.getRecordedLogs` drains the buffer, so every
///         harness in a test shares one archive). Each log is decoded by the production
///         `_decodeHistoryLog`, and the replay / live re-read / sole-holder rules are the
///         production code. Recorded logs carry no transaction hash, so the "constructor
///         MinDelayChange in the creation transaction" check sees one zero hash for all of them.
contract RoleLogArchive {
    Vm internal constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    struct Raw {
        address emitter;
        bytes32[] topics;
        bytes data;
    }

    Raw[] internal raws;

    /// @notice Move every log recorded since the last call into the archive.
    function absorb() public {
        Vm.Log[] memory logs = VM.getRecordedLogs();
        for (uint256 i = 0; i < logs.length; i++) {
            Raw storage r = raws.push();
            r.emitter = logs[i].emitter;
            r.data = logs[i].data;
            for (uint256 t = 0; t < logs[i].topics.length; t++) {
                r.topics.push(logs[i].topics[t]);
            }
        }
    }

    function logsOf(address emitter) external returns (bytes32[][] memory topics, bytes[] memory data) {
        absorb();
        uint256 n;
        for (uint256 i = 0; i < raws.length; i++) {
            if (raws[i].emitter == emitter) n++;
        }
        (topics, data) = (new bytes32[][](n), new bytes[](n));
        n = 0;
        for (uint256 i = 0; i < raws.length; i++) {
            if (raws[i].emitter != emitter) continue;
            (topics[n], data[n]) = (raws[i].topics, raws[i].data);
            n++;
        }
    }
}

abstract contract RecordedRoleHistory is AdminChecks {
    RoleLogArchive internal archive;

    /// @notice Point at the test's archive. Never called = no history (fails closed).
    function useArchive(RoleLogArchive a) external {
        archive = a;
    }

    function _timelockRoleHistory(address timelock)
        internal
        virtual
        override
        returns (bool ok, string memory why, RoleEvent[] memory events)
    {
        if (address(archive) == address(0)) return (false, "role history unavailable: no archive", events);
        (bytes32[][] memory topics, bytes[] memory data) = archive.logsOf(timelock);
        for (uint256 i = 0; i < topics.length; i++) {
            (bool keep, RoleEvent memory e) = _decodeHistoryLog(topics[i], data[i], bytes32(0));
            if (keep) events = _pushRoleEvent(events, e);
        }
        return (true, "", events);
    }
}

contract DormantWithHistory is DeployDormantLedgers, RecordedRoleHistory {
    function _timelockRoleHistory(address timelock)
        internal
        override(AdminChecks, RecordedRoleHistory)
        returns (bool, string memory, RoleEvent[] memory)
    {
        return RecordedRoleHistory._timelockRoleHistory(timelock);
    }
}

contract GateWithHistory is CheckDeployedAdmins, RecordedRoleHistory {
    function _timelockRoleHistory(address timelock)
        internal
        override(AdminChecks, RecordedRoleHistory)
        returns (bool, string memory, RoleEvent[] memory)
    {
        return RecordedRoleHistory._timelockRoleHistory(timelock);
    }
}

/// Direct access to the holder check, for the regression cases.
contract HolderChecksWithHistory is RecordedRoleHistory {
    function problem(address timelock, address council, address[] memory extraCancellers)
        external
        returns (string memory)
    {
        return _timelockHolderProblem(timelock, council, extraCancellers);
    }
}

/// The production history source (no override): in `forge test` there is no node behind it.
contract HolderChecksLive is AdminChecks {
    function problem(address timelock, address council) external returns (string memory) {
        return _timelockHolderProblem(timelock, council, new address[](0));
    }
}
