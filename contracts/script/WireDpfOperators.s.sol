// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";

/// @notice Minimal interfaces: the setters this sweep calls and the governance getter each target has.
interface IDpfGoverned {
    function governance() external view returns (address);
}
interface IClassificationRegistry {
    function addOracleSigner(address signer) external;
}
interface IAgentDecisionRegistryV2 {
    function setRecorder(address recorder, bool authorized) external;
}
interface IContradictionLedger {
    function setResolver(address resolver, bool authorized) external;
}
interface IPartProvenanceRegistry {
    function setRecorder(address recorder, bool authorized) external;
    function setContradictionLedger(address ledger) external;
}
interface ISupplierRegistry {
    function setRecorder(address recorder, bool authorized) external;
}
interface IMoqRegistry {
    function setRecorder(address recorder, bool authorized) external;
}
interface IDefensePrimeFLScopeIndex {
    function setRecorder(address recorder, bool authorized) external;
}

/// @title WireDpfOperators: the DPF operator wiring (REDEPLOY D3) as one GOVERNANCE timelock batch
/// @notice Authorizes the DPF operator as recorder, resolver or oracle signer on the DPF-08 stage 1-4
///         contracts, and points PartProvenanceRegistry at the ContradictionLedger. Eight calls:
///           ClassificationRegistry.addOracleSigner(op)
///           AgentDecisionRegistryV2.setRecorder(op, true)
///           ContradictionLedger.setResolver(op, true)
///           PartProvenanceRegistry.setRecorder(op, true)
///           PartProvenanceRegistry.setContradictionLedger(ContradictionLedger)
///           SupplierRegistry.setRecorder(op, true)
///           MoqRegistry.setRecorder(op, true)
///           DefensePrimeFLScopeIndex.setRecorder(op, true)
///
///         Addresses come from the address books, never from constants: a reroll moves them, and
///         the constants this script used to pin were the 2026-05/07 deploys, dead after the
///         rerolls. BLOCK0_BOOK is the r1007 block-0 book (contracts/addresses/r1007/40204.json,
///         AgentDecisionRegistryV2); POSTGENESIS_BOOK is the r1007 post-genesis book
///         (contracts/addresses/r1007/40204.postgenesis.json, the other six). Each target must
///         have code and report `governance()` = GOVERNANCE_TIMELOCK.
///
///         On r1007 every target is administered by the GovernanceTimelock (48 h, 3 of 5), so the
///         sweep is a timelock batch, not a direct send. `proposal()` (read-only, no key) prints
///         the GovernanceMultisig `propose` payloads for `scheduleBatch` and, after the delay,
///         `executeBatch`, plus the operation id. Nothing here broadcasts.
///
///         Inputs (env): BLOCK0_BOOK, POSTGENESIS_BOOK, GOVERNANCE_TIMELOCK, DPF_OPERATOR (required:
///         no fallback to msg.sender, which would authorize whoever ran the script).
///         Optional DPF_SALT_LABEL (default "r1007.d3.dpf-operators.v1"), hashed into the salt.
contract WireDpfOperators is Script {
    struct Targets {
        address classificationRegistry;
        address agentDecisionRegistryV2;
        address contradictionLedger;
        address partProvenanceRegistry;
        address supplierRegistry;
        address moqRegistry;
        address defensePrimeFLScopeIndex;
    }

    function _book(string memory path, string memory name) internal view returns (address a) {
        string memory json = vm.readFile(path);
        string memory key = string.concat(".contracts.", name);
        require(vm.keyExistsJson(json, key), string.concat(name, " is not in ", path));
        a = vm.parseJsonAddress(json, key);
    }

    function targetsFromBooks(string memory block0, string memory postGenesis) public view returns (Targets memory t) {
        t.agentDecisionRegistryV2 = _book(block0, "AgentDecisionRegistryV2");
        t.classificationRegistry = _book(postGenesis, "ClassificationRegistry");
        t.contradictionLedger = _book(postGenesis, "ContradictionLedger");
        t.partProvenanceRegistry = _book(postGenesis, "PartProvenanceRegistry");
        t.supplierRegistry = _book(postGenesis, "SupplierRegistry");
        t.moqRegistry = _book(postGenesis, "MoqRegistry");
        t.defensePrimeFLScopeIndex = _book(postGenesis, "DefensePrimeFLScopeIndex");
    }

    /// The batch: eight calls, every target checked for code and for the GOVERNANCE timelock as
    /// its governance before any calldata is returned.
    function batch(Targets memory t, address governanceTimelock, address operator)
        public
        view
        returns (address[] memory targets, uint256[] memory values, bytes[] memory payloads)
    {
        require(operator != address(0), "DPF_OPERATOR must be set");
        require(operator != governanceTimelock, "DPF_OPERATOR is the GOVERNANCE timelock");
        targets = new address[](8);
        values = new uint256[](8);
        payloads = new bytes[](8);
        (targets[0], payloads[0]) =
            (t.classificationRegistry, abi.encodeCall(IClassificationRegistry.addOracleSigner, (operator)));
        (targets[1], payloads[1]) =
            (t.agentDecisionRegistryV2, abi.encodeCall(IAgentDecisionRegistryV2.setRecorder, (operator, true)));
        (targets[2], payloads[2]) =
            (t.contradictionLedger, abi.encodeCall(IContradictionLedger.setResolver, (operator, true)));
        (targets[3], payloads[3]) =
            (t.partProvenanceRegistry, abi.encodeCall(IPartProvenanceRegistry.setRecorder, (operator, true)));
        (targets[4], payloads[4]) = (
            t.partProvenanceRegistry,
            abi.encodeCall(IPartProvenanceRegistry.setContradictionLedger, (t.contradictionLedger))
        );
        (targets[5], payloads[5]) = (t.supplierRegistry, abi.encodeCall(ISupplierRegistry.setRecorder, (operator, true)));
        (targets[6], payloads[6]) = (t.moqRegistry, abi.encodeCall(IMoqRegistry.setRecorder, (operator, true)));
        (targets[7], payloads[7]) =
            (t.defensePrimeFLScopeIndex, abi.encodeCall(IDefensePrimeFLScopeIndex.setRecorder, (operator, true)));
        for (uint256 n = 0; n < 8; n++) {
            require(targets[n].code.length != 0, "a DPF target has no code on this chain");
            require(
                IDpfGoverned(targets[n]).governance() == governanceTimelock,
                "a DPF target is not governed by GOVERNANCE_TIMELOCK"
            );
        }
    }

    function buildProposal(Targets memory t, address governanceTimelock, address operator, bytes32 salt)
        public
        view
        returns (bytes memory scheduleData, bytes memory executeData, bytes32 opId)
    {
        (address[] memory targets, uint256[] memory values, bytes[] memory payloads) =
            batch(t, governanceTimelock, operator);
        TimelockController g = TimelockController(payable(governanceTimelock));
        scheduleData = abi.encodeCall(g.scheduleBatch, (targets, values, payloads, bytes32(0), salt, g.getMinDelay()));
        executeData = abi.encodeCall(g.executeBatch, (targets, values, payloads, bytes32(0), salt));
        opId = g.hashOperationBatch(targets, values, payloads, bytes32(0), salt);
    }

    function proposal() external view {
        Targets memory t = targetsFromBooks(vm.envString("BLOCK0_BOOK"), vm.envString("POSTGENESIS_BOOK"));
        address gt = vm.envAddress("GOVERNANCE_TIMELOCK");
        address op = vm.envAddress("DPF_OPERATOR");
        bytes32 salt = keccak256(bytes(vm.envOr("DPF_SALT_LABEL", string("r1007.d3.dpf-operators.v1"))));
        (bytes memory s, bytes memory e, bytes32 id) = buildProposal(t, gt, op, salt);
        console2.log("DPF operator:", op);
        console2.log("timelock operation id:");
        console2.logBytes32(id);
        console2.log("step A, GovernanceMultisig.propose(<this>):");
        console2.logBytes(abi.encodeWithSignature("propose(bytes)", s));
        console2.log("step B, after the delay, GovernanceMultisig.propose(<this>):");
        console2.logBytes(abi.encodeWithSignature("propose(bytes)", e));
    }

    /// The old direct-send sweep is gone: on 40204 the targets' governance is the timelock, so a
    /// direct send from any EOA reverts. Use `--sig "proposal()"`.
    function run() external pure {
        revert("WireDpfOperators: the D3 wiring is a GOVERNANCE timelock batch; run with --sig \"proposal()\"");
    }
}
