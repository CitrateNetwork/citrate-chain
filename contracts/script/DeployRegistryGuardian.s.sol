// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {EnvSigner} from "./lib/EnvSigner.sol";
import {Salts} from "./Salts.sol";
import {RegistryGuardian2of3, IProviderRegistryGuardianActions} from "../src/amc/RegistryGuardian2of3.sol";
import {ProviderRegistry} from "../src/amc/ProviderRegistry.sol";

/// @title DeployRegistryGuardian: the RegistryGuardian2of3 seat for the r1007 ProviderRegistry
///        and its GOVERNANCE `setGuardian` proposal (GEN-GUARD-ROTATE; owner 2026-11-15)
/// @notice Two steps, both refused until the canceller swap (fed #561 §3.1) has executed, so the
///         GUARDIAN council can no longer cancel the rotation through GuardianCanceller v1 (Q21):
///
///   1. `run()` deploys RegistryGuardian2of3(registry, REG_GUARDIAN_1..3) by CREATE2 under the salt
///      "r1007.RegistryGuardian2of3", from the r1007 V060_DEPLOYER (env-held key, EnvSigner). The
///      address is fixed by the registry and the three owners, so the proposal below can be built
///      and reviewed before the deploy. The deployer holds no role: the contract has no admin.
///   2. `proposal()` (read-only) prints the GovernanceMultisig `propose` payloads for
///      `GovernanceTimelock.schedule(registry, 0, setGuardian(seat), 0, salt, delay)` and, after the
///      delay, the matching `execute`, plus the operation id. It refuses unless the seat has this
///      build's code at its predicted address and the registry's guardian is not already the seat.
///
///   Inputs (env): PROVIDER_REGISTRY, GOVERNANCE_TIMELOCK, GUARDIAN_CANCELLER_V1,
///   GUARDIAN_CANCELLER_V2, REG_GUARDIAN_1, REG_GUARDIAN_2, REG_GUARDIAN_3; for `run` also
///   PRIVATE_KEY (op run), EXPECTED_SENDER and DEPLOYER_ADDRESS (the V060_DEPLOYER), with forge
///   `--sender` the same address.
contract DeployRegistryGuardian is EnvSigner {
    string internal constant SEAT_SALT = "r1007.RegistryGuardian2of3";
    /// keccak256("r1007.v060.d2c.registry-guardian") is the timelock salt of the setGuardian call.
    bytes32 public constant SET_GUARDIAN_SALT = keccak256("r1007.v060.d2c.registry-guardian");
    address internal constant FACTORY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    struct Inputs {
        address registry;
        address governanceTimelock;
        address cancellerV1;
        address cancellerV2;
        address owner0;
        address owner1;
        address owner2;
    }

    function inputsFromEnv() public view returns (Inputs memory i) {
        i.registry = vm.envAddress("PROVIDER_REGISTRY");
        i.governanceTimelock = vm.envAddress("GOVERNANCE_TIMELOCK");
        i.cancellerV1 = vm.envAddress("GUARDIAN_CANCELLER_V1");
        i.cancellerV2 = vm.envAddress("GUARDIAN_CANCELLER_V2");
        i.owner0 = vm.envAddress("REG_GUARDIAN_1");
        i.owner1 = vm.envAddress("REG_GUARDIAN_2");
        i.owner2 = vm.envAddress("REG_GUARDIAN_3");
    }

    function seatInit(Inputs memory i) public pure returns (bytes memory) {
        return abi.encodePacked(
            type(RegistryGuardian2of3).creationCode,
            abi.encode(IProviderRegistryGuardianActions(i.registry), i.owner0, i.owner1, i.owner2)
        );
    }

    function predictSeat(Inputs memory i) public pure returns (address) {
        return address(
            uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), FACTORY, Salts.salt(SEAT_SALT), keccak256(seatInit(i))))))
        );
    }

    /// The preconditions both steps share: a real registry governed by the GOVERNANCE timelock,
    /// and the canceller swap executed (v2 holds CANCELLER, v1 does not).
    function checkPreconditions(Inputs memory i) public view {
        require(i.registry.code.length != 0, "PROVIDER_REGISTRY has no code");
        require(ProviderRegistry(i.registry).governance() == i.governanceTimelock, "ProviderRegistry: governance is not GOVERNANCE_TIMELOCK");
        TimelockController g = TimelockController(payable(i.governanceTimelock));
        bytes32 role = g.CANCELLER_ROLE();
        require(
            g.hasRole(role, i.cancellerV2) && !g.hasRole(role, i.cancellerV1),
            "the canceller swap has not executed: v2 must hold CANCELLER and v1 must not"
        );
        require(
            i.owner0 != i.governanceTimelock && i.owner1 != i.governanceTimelock && i.owner2 != i.governanceTimelock,
            "a guardian owner is the GOVERNANCE timelock"
        );
    }

    function run() external returns (address seat) {
        Inputs memory i = inputsFromEnv();
        address deployer = vm.envAddress("DEPLOYER_ADDRESS");
        require(_envSignerKey() != 0, "signs only from an env-held key: set PRIVATE_KEY (op run) and EXPECTED_SENDER");
        require(deployer != i.owner0 && deployer != i.owner1 && deployer != i.owner2, "the deployer is a guardian owner");
        checkPreconditions(i);
        address predicted = predictSeat(i);
        if (predicted.code.length == 0) {
            _startBroadcastEnv(deployer);
            seat = address(
                new RegistryGuardian2of3{salt: Salts.salt(SEAT_SALT)}(
                    IProviderRegistryGuardianActions(i.registry), i.owner0, i.owner1, i.owner2
                )
            );
            vm.stopBroadcast();
        } else {
            seat = predicted;
        }
        require(seat == predicted, "RegistryGuardian2of3 is not at its predicted address");
        verifySeat(i, seat);
        console.log("RegistryGuardian2of3:", seat);
    }

    function verifySeat(Inputs memory i, address seat) public view {
        require(seat.code.length != 0, "RegistryGuardian2of3: no code");
        RegistryGuardian2of3 g = RegistryGuardian2of3(seat);
        require(address(g.registry()) == i.registry, "RegistryGuardian2of3: registry");
        require(g.owner0() == i.owner0 && g.owner1() == i.owner1 && g.owner2() == i.owner2, "RegistryGuardian2of3: owners");
    }

    /// The GovernanceMultisig `propose` payloads for the rotation, and the timelock operation id.
    function buildProposal(Inputs memory i)
        public
        view
        returns (bytes memory scheduleData, bytes memory executeData, bytes32 opId)
    {
        checkPreconditions(i);
        address seat = predictSeat(i);
        verifySeat(i, seat);
        require(ProviderRegistry(i.registry).guardian() != seat, "the registry's guardian is already the seat");
        TimelockController g = TimelockController(payable(i.governanceTimelock));
        bytes memory call = abi.encodeCall(ProviderRegistry.setGuardian, (seat));
        uint256 delay = g.getMinDelay();
        scheduleData = abi.encodeCall(g.schedule, (i.registry, 0, call, bytes32(0), SET_GUARDIAN_SALT, delay));
        executeData = abi.encodeCall(g.execute, (i.registry, 0, call, bytes32(0), SET_GUARDIAN_SALT));
        opId = g.hashOperation(i.registry, 0, call, bytes32(0), SET_GUARDIAN_SALT);
    }

    function proposal() external view {
        Inputs memory i = inputsFromEnv();
        (bytes memory s, bytes memory e, bytes32 id) = buildProposal(i);
        console.log("RegistryGuardian2of3 seat:", predictSeat(i));
        console.log("timelock operation id:");
        console.logBytes32(id);
        console.log("step A, GovernanceMultisig.propose(<this>):");
        console.logBytes(abi.encodeWithSignature("propose(bytes)", s));
        console.log("step B, after the delay, GovernanceMultisig.propose(<this>):");
        console.logBytes(abi.encodeWithSignature("propose(bytes)", e));
    }
}
