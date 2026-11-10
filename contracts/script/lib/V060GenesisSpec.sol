// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {ProviderRegistry} from "../../src/amc/ProviderRegistry.sol";
import {UsageReceipts} from "../../src/amc/UsageReceipts.sol";
import {OrgBudgets, IOrganizationSBT} from "../../src/amc/OrgBudgets.sol";
import {WorkAttestations, IAgentSBT} from "../../src/amc/WorkAttestations.sol";
import {GuardianCancellerV2} from "../../src/genesis/GuardianCancellerV2.sol";
import {WorkMarket} from "../../src/work/WorkMarket.sol";
import {FLRoundVerifier, IFederatedRoundLedgerReads} from "../../src/work/FLRoundVerifier.sol";
import {TaskVerifier} from "../../src/work/TaskVerifier.sol";
import {DatasetRegistry} from "../../src/data/DatasetRegistry.sol";
import {GuardianRecoveryModuleV2, IGuardianRecoveryModuleV1} from "../../src/aa/recovery/GuardianRecoveryModuleV2.sol";

/// @title V060GenesisSpec: the 0.6.0 ceremony-genesis contracts, their salts and their init code
/// @notice One source for the deploy scripts (DeployGenesisGovernance in its v2-canceller mode,
///         DeployV060Genesis) of what each 0.6.0 genesis contract is built from. The ceremony
///         deploys every one with `new X{salt: Salts.salt(NAME)}(args)` through the Arachnid
///         factory, so its block-0 address is
///
///           CREATE2(0x4e59…956C, Salts.salt(NAME), keccak256(creationCode ‖ abi.encode(args)))
///
///         and depends only on this build's creation code and the arguments below. The
///         arguments come from the ceremony's own books (the GOVERNANCE and GUARDIAN timelocks of
///         P1, the AA stack of P2, the HUP registries of P3L, the FederatedRoundLedger of P4),
///         except for the fixed values here and the coordinator bonds.
///
///         Fixed values (owner decisions in the V60-S0 sprint file, GEN-PARAMS):
///           TaskVerifier review window      72 h (Q7)
///           ProviderRegistry veto window    24 h (chain #400 deploy profile)
///           UsageReceipts max backfill      90 days (chain #400 deploy profile)
///           WorkMarket slashSink            the GOVERNANCE timelock (owner 2026-11-09)
///           guardian seats at block 0       the GUARDIAN timelock, i.e. the guardian council (Q9 a)
///
///         Pending: the WorkMarket coordinator bonds (`minCoordinatorBond_`,
///         `defaultCoordinatorBond_`) wait on the tokenomics decision. There is no default here:
///         DeployV060Genesis refuses to build without both (`PENDING_COORDINATOR_BONDS`), and
///         WorkMarket's address is unknown until they are fixed, because they are in its init code.
library V060GenesisSpec {
    // CREATE2 salt names (Salts.salt(name)). The "Genesis." prefix is the P1 convention.
    string internal constant PROVIDER_REGISTRY = "Genesis.ProviderRegistry";
    string internal constant GUARDIAN_CANCELLER_V2 = "Genesis.GuardianCancellerV2";
    string internal constant FL_ROUND_VERIFIER = "Genesis.FLRoundVerifier";
    string internal constant TASK_VERIFIER = "Genesis.TaskVerifier";
    string internal constant WORK_MARKET = "Genesis.WorkMarket";
    string internal constant DATASET_REGISTRY = "Genesis.DatasetRegistry";
    string internal constant GUARDIAN_RECOVERY_V2 = "Genesis.GuardianRecoveryModuleV2";
    string internal constant USAGE_RECEIPTS = "Genesis.UsageReceipts";
    string internal constant ORG_BUDGETS = "Genesis.OrgBudgets";
    string internal constant WORK_ATTESTATIONS = "Genesis.WorkAttestations";

    uint64 internal constant TASK_REVIEW_WINDOW = 72 hours;
    uint64 internal constant PROVIDER_VETO_WINDOW = 24 hours;
    uint32 internal constant USAGE_MAX_BACKFILL_DAYS = 90;

    /// The governance book records which canceller generation holds GOVERNANCE's CANCELLER seat.
    uint256 internal constant CANCELLER_V2 = 2;

    string internal constant PENDING_COORDINATOR_BONDS =
        "PENDING PARAMETER: the WorkMarket coordinator bonds wait on the tokenomics decision; set WORKMARKET_MIN_COORDINATOR_BOND and WORKMARKET_DEFAULT_COORDINATOR_BOND (SALT wei, min > 0, default >= min)";

    function providerRegistryInit(address governanceTimelock, address guardianTimelock)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            type(ProviderRegistry).creationCode, abi.encode(governanceTimelock, guardianTimelock, PROVIDER_VETO_WINDOW)
        );
    }

    function guardianCancellerV2Init(address governanceTimelock, address guardianTimelock, address registry)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            type(GuardianCancellerV2).creationCode, abi.encode(governanceTimelock, guardianTimelock, registry)
        );
    }

    function flRoundVerifierInit(address federatedRoundLedger) internal pure returns (bytes memory) {
        return abi.encodePacked(
            type(FLRoundVerifier).creationCode, abi.encode(IFederatedRoundLedgerReads(federatedRoundLedger))
        );
    }

    function taskVerifierInit() internal pure returns (bytes memory) {
        return abi.encodePacked(type(TaskVerifier).creationCode, abi.encode(TASK_REVIEW_WINDOW));
    }

    /// @notice WorkMarket's allowlist at block 0 is exactly [FLRoundVerifier, TaskVerifier].
    function initialVerifiers(address flRoundVerifier, address taskVerifier)
        internal
        pure
        returns (address[] memory v)
    {
        v = new address[](2);
        (v[0], v[1]) = (flRoundVerifier, taskVerifier);
    }

    function workMarketInit(
        address governanceTimelock,
        address guardianTimelock,
        uint128 defaultCoordinatorBond,
        uint128 minCoordinatorBond,
        address flRoundVerifier,
        address taskVerifier
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            type(WorkMarket).creationCode,
            abi.encode(
                governanceTimelock,
                guardianTimelock,
                governanceTimelock, // slashSink = the GOVERNANCE timelock (the treasury)
                defaultCoordinatorBond,
                minCoordinatorBond,
                initialVerifiers(flRoundVerifier, taskVerifier)
            )
        );
    }

    function datasetRegistryInit(address governanceTimelock) internal pure returns (bytes memory) {
        return abi.encodePacked(type(DatasetRegistry).creationCode, abi.encode(governanceTimelock));
    }

    function guardianRecoveryV2Init(address v1) internal pure returns (bytes memory) {
        return abi.encodePacked(
            type(GuardianRecoveryModuleV2).creationCode, abi.encode(IGuardianRecoveryModuleV1(v1))
        );
    }

    function usageReceiptsInit() internal pure returns (bytes memory) {
        return abi.encodePacked(type(UsageReceipts).creationCode, abi.encode(USAGE_MAX_BACKFILL_DAYS));
    }

    function orgBudgetsInit(address governanceTimelock, address organizationSbt) internal pure returns (bytes memory) {
        return abi.encodePacked(
            type(OrgBudgets).creationCode, abi.encode(governanceTimelock, IOrganizationSBT(organizationSbt))
        );
    }

    function workAttestationsInit(address agentSbt) internal pure returns (bytes memory) {
        return abi.encodePacked(type(WorkAttestations).creationCode, abi.encode(IAgentSBT(agentSbt)));
    }
}
