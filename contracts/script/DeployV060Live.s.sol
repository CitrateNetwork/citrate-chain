// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import {DeployV060Genesis} from "./DeployV060Genesis.s.sol";
import {V060GovernanceSpec} from "./lib/V060GovernanceSpec.sol";

/// @title DeployV060Live: the 0.6.0 contracts post-genesis on r1007 (fed #561, D2c)
/// @notice The live mode of DeployV060Genesis from the environment. No ceremony phase runs it:
///         it is the D2c step on r1007 (REDEPLOY_AND_REPIN), after D2b, from the r1007
///         V060_DEPLOYER (lead decision on fed #561), funded with 2 SALT from TREASURY at D2c.
///
///         Signing: env-held key only (EnvSigner; the same rule as env-key-signing-2). There is no
///         CLI-wallet path:
///           op run --env-file=<(printf 'PRIVATE_KEY=op://citrate-chain-ops/r1007 V060_DEPLOYER/password\n') -- \
///             env EXPECTED_SENDER=<V060_DEPLOYER> DEPLOYER_ADDRESS=<V060_DEPLOYER> ... \
///             forge script script/DeployV060Live.s.sol --rpc-url <r1007> --sender <V060_DEPLOYER> --broadcast --slow
///         The key's address must equal EXPECTED_SENDER, forge's --sender and the deployer.
///
///         Inputs:
///           V060_INPUT_BOOK        the r1007 block-0 book (GovernanceTimelock, GovernanceMultisig,
///                                  GuardianTimelock, GuardianMultisig, GuardianCanceller = v1,
///                                  FederatedRoundLedger, OrganizationSBT, AgentSBT;
///                                  GuardianRecoveryModule under contracts or aaStack)
///           V060_GENESIS_OUT       book-shaped output (under ./genesis)
///           WORKMARKET_MIN_COORDINATOR_BOND, WORKMARKET_DEFAULT_COORDINATOR_BOND
///           GENESIS_KEY_INVENTORY  (with the deployer tagged V060_DEPLOYER), GENESIS_RETIRED_KEYS,
///           GENESIS_GUARDIAN_VETO_MARGIN
///           R1006_GOV_OWNERS, R1006_GRD_OWNERS  the councils' constructor owners, in order
///                                  (scripts/genesis/r1006/inputs.r1006.env)
///           GOV_OWNERS, GRD_OWNERS the rotated r1007 owners, in order (scripts/genesis/r1007/inputs.r1007.env)
///           GENESIS_CHAIN=1, GENESIS_ALLOC  the block-0 state the timelock holder sets are proved from
///           CEREMONY_DEPLOYER_ADDRESS or DEPLOYER_ADDRESS (must be the forge signer)
///
///         Then `--sig "swapProposalFromBook()"` prints the canceller-swap proposal, only once v2
///         has this build's code at its predicted address (fed #561 review).
contract DeployV060Live is DeployV060Genesis {
    /// @notice Live mode from the environment: as `run`, with the r1007 block-0 book as
    ///         V060_INPUT_BOOK and a deployer the inventory tags V060_DEPLOYER.
    function run() external override returns (Deployed memory d) {
        (uint128 minBond, uint128 defaultBond) = _bondsFromEnv();
        V060GovernanceSpec.KeyParams memory k = _keysFromEnv();
        address deployer = deployerAddress();
        Inputs memory i = _inputsFromBook(vm.readFile(vm.envString("V060_INPUT_BOOK")), minBond, defaultBond, k);
        require(bytes(vm.envString("V060_GENESIS_OUT")).length != 0, "V060_GENESIS_OUT must name an output path");
        Rotation memory rot = Rotation({
            fromGov: vm.envAddress("R1006_GOV_OWNERS", ","),
            fromGrd: vm.envAddress("R1006_GRD_OWNERS", ","),
            toGov: vm.envAddress("GOV_OWNERS", ","),
            toGrd: vm.envAddress("GRD_OWNERS", ",")
        });
        d = deployLive(deployer, i, rot);
        _writeBook("V060_GENESIS_OUT", bookJson(deployer, d, i));
    }


    /// @notice The canceller-swap proposal for the inputs in the environment (read-only): the
    ///         GovernanceMultisig `propose` payloads, printed only once v2 has code (fed #561).
    function swapProposalFromBook() external {
        (uint128 minBond, uint128 defaultBond) = _bondsFromEnv();
        V060GovernanceSpec.KeyParams memory k = _keysFromEnv();
        Inputs memory i = _inputsFromBook(vm.readFile(vm.envString("V060_INPUT_BOOK")), minBond, defaultBond, k);
        (bytes memory scheduleData, bytes memory executeData, bytes32 opId) = swapProposal(i);
        console.log("operation id:");
        console.logBytes32(opId);
        console.log("step A, GovernanceMultisig.propose(<this>):");
        console.logBytes(scheduleData);
        console.log("step B, after the delay, GovernanceMultisig.propose(<this>):");
        console.logBytes(executeData);
    }
}
