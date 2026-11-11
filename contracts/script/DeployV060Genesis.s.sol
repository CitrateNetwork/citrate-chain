// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";
import "./Salts.sol";
import "./lib/Create2Deploy.sol";
import "./lib/GenesisBook.sol";
import "./lib/GenesisProfile.sol";
import {V060GenesisSpec} from "./lib/V060GenesisSpec.sol";
import {V060GovernanceSpec} from "./lib/V060GovernanceSpec.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {GuardianCanceller} from "../src/genesis/GuardianCanceller.sol";
import {MultisigProposer} from "../src/genesis/MultisigProposer.sol";
import {GuardianCancellerV2} from "../src/genesis/GuardianCancellerV2.sol";
import {ProviderRegistry} from "../src/amc/ProviderRegistry.sol";
import {UsageReceipts} from "../src/amc/UsageReceipts.sol";
import {OrgBudgets, IOrganizationSBT} from "../src/amc/OrgBudgets.sol";
import {WorkAttestations, IAgentSBT} from "../src/amc/WorkAttestations.sol";
import {WorkMarket} from "../src/work/WorkMarket.sol";
import {FLRoundVerifier, IFederatedRoundLedgerReads} from "../src/work/FLRoundVerifier.sol";
import {TaskVerifier} from "../src/work/TaskVerifier.sol";
import {DatasetRegistry} from "../src/data/DatasetRegistry.sol";
import {GuardianRecoveryModuleV2, IGuardianRecoveryModuleV1} from "../src/aa/recovery/GuardianRecoveryModuleV2.sol";
import {GuardianRecoveryModule} from "../src/aa/recovery/GuardianRecoveryModule.sol";
import {FederatedRoundLedger} from "../src/FederatedRoundLedger.sol";

/// @title DeployV060Genesis: the 0.6.0 contracts of the ceremony genesis (V60-GEN)
/// @notice The ceremony step that adds the 0.6.0 contract set to the ceremony state, after P4
///         (it reads P4's FederatedRoundLedger) and before P5's admin gate. It deploys, each by
///         CREATE2 under its V060GenesisSpec salt and reused when already live:
///
///           FLRoundVerifier(FederatedRoundLedger)
///           TaskVerifier(72 h)
///           WorkMarket(GOVERNANCE, guardian council, slashSink = GOVERNANCE, default bond,
///                      min bond, [FLRoundVerifier, TaskVerifier])
///           DatasetRegistry(GOVERNANCE)
///           GuardianRecoveryModuleV2(V1 GuardianRecoveryModule)
///           UsageReceipts(90 days)
///           OrgBudgets(GOVERNANCE, OrganizationSBT)
///           WorkAttestations(AgentSBT)
///
///         GOVERNANCE is the GOVERNANCE timelock and the guardian council is the GUARDIAN
///         timelock, both from P1. ProviderRegistry and GuardianCancellerV2 are not deployed
///         here: P1 deploys them in its 0.6.0 mode (GENESIS_V060=1), because the
///         GOVERNANCE timelock's CANCELLER seat can only be granted while P1 still administers
///         it. This step refuses to run unless that is what P1 did: the registry is live at its
///         CREATE2 address, the governance book's canceller seat is v2 for that registry and
///         holds CANCELLER, and v1's CREATE2 address holds none.
///
///         Every input is checked before anything is broadcast, on the genesis profile (the node
///         must report chain id 40204 or the profile is forced; GenesisProfile):
///           - the two councils pass the governance-book provenance checks: genesis floors,
///             GovernanceMultisig is the ceremony's MultisigProposer for its timelock, the
///             GOVERNANCE timelock's complete holder sets are its council plus the v2 seat, and
///             the v2 seat, its registry and the GUARDIAN council verify as in
///             GenesisProfile `_bookGuardianCanceller`;
///           - the FederatedRoundLedger and the V1 GuardianRecoveryModule are this build's
///             instances at their own CREATE2 addresses ("FederatedRoundLedger",
///             "GuardianRecoveryModule"), not only "some code";
///           - OrganizationSBT and AgentSBT are owned by GOVERNANCE and AgentSBT reads that
///             OrganizationSBT;
///           - the GUARDIAN delay plus the owner's veto margin fits in the registry's window.
///         After the broadcast, `verify` re-reads every contract on chain; it is also a
///         standalone step (`--sig "verifyBook()"`) over the step's own output book.
///
///         PENDING PARAMETER: the WorkMarket coordinator bonds wait on the tokenomics decision.
///         They have no default anywhere. Without WORKMARKET_MIN_COORDINATOR_BOND and
///         WORKMARKET_DEFAULT_COORDINATOR_BOND (SALT wei; min > 0, default >= min) the step
///         refuses before reading anything else. They are in WorkMarket's init code, so its
///         address is unknown until they are decided.
///
///         Keys (fed #467 section 0.6; D-K3): GENESIS_KEY_INVENTORY (role-tagged allowlist, JSON
///         {address: [roles]}; a council owner needs its council's role, GOV_OWNERS/GRD_OWNERS),
///         GENESIS_RETIRED_KEYS (denylist) and GENESIS_GUARDIAN_VETO_MARGIN, none with a default
///         (V060GovernanceSpec.KeyParams). Every owner of both councils, read on chain, must be on
///         the inventory and off the retired list; the deployer off the retired list.
///
///         Inputs:
///           WORKMARKET_MIN_COORDINATOR_BOND, WORKMARKET_DEFAULT_COORDINATOR_BOND  (pending, above)
///           GENESIS_KEY_INVENTORY, GENESIS_RETIRED_KEYS, GENESIS_GUARDIAN_VETO_MARGIN  (above)
///           V060_INPUT_BOOK    the merged ceremony book so far (P1-P4): GovernanceTimelock,
///                              GovernanceMultisig, GuardianTimelock, GuardianMultisig,
///                              GuardianCanceller, FederatedRoundLedger,
///                              OrganizationSBT, AgentSBT under `contracts`, and
///                              GuardianRecoveryModule under `contracts` or `aaStack`
///           V060_GENESIS_OUT   book-shaped output (under ./genesis)
///           CEREMONY_DEPLOYER_ADDRESS or DEPLOYER_ADDRESS   (must be the forge signer)
///         The deployer gets no role: every contract here names GOVERNANCE or no admin at all.
contract DeployV060Genesis is ScriptEnv, AdminChecks, Create2Deploy, GenesisBook, GenesisProfile {
    string internal constant BOND_MIN_KEY = "WORKMARKET_MIN_COORDINATOR_BOND";
    string internal constant BOND_DEFAULT_KEY = "WORKMARKET_DEFAULT_COORDINATOR_BOND";

    struct Inputs {
        address governanceTimelock;
        address governanceMultisig;
        address guardianTimelock;
        address guardianMultisig;
        /// the GOVERNANCE timelock's CANCELLER seat in the governance book
        address guardianCanceller;
        address federatedRoundLedger;
        /// the V1 GuardianRecoveryModule (P2 AA stack)
        address guardianRecoveryModule;
        address organizationSbt;
        address agentSbt;
        uint128 minCoordinatorBond;
        uint128 defaultCoordinatorBond;
        /// the key inventory, the retired keys and the veto margin (fed #467 section 0.6; D-K3)
        V060GovernanceSpec.KeyParams keys;
    }

    struct Deployed {
        address providerRegistry;
        address guardianCancellerV2;
        address flRoundVerifier;
        address taskVerifier;
        address workMarket;
        address datasetRegistry;
        address guardianRecoveryModuleV2;
        address usageReceipts;
        address orgBudgets;
        address workAttestations;
    }

    function run() external returns (Deployed memory d) {
        // The pending parameter first: nothing else is read, checked or sent without it.
        (uint128 minBond, uint128 defaultBond) = _bondsFromEnv();
        V060GovernanceSpec.KeyParams memory k = _keysFromEnv();
        address deployer = deployerAddress();
        string memory json = vm.readFile(vm.envString("V060_INPUT_BOOK"));
        // Resolve the output path before broadcasting, so a missing one fails first.
        require(bytes(vm.envString("V060_GENESIS_OUT")).length != 0, "V060_GENESIS_OUT must name an output path");
        Inputs memory i = Inputs({
            governanceTimelock: _bookAddr(json, "GovernanceTimelock"),
            governanceMultisig: _bookAddr(json, "GovernanceMultisig"),
            guardianTimelock: _bookAddr(json, "GuardianTimelock"),
            guardianMultisig: _bookAddr(json, "GuardianMultisig"),
            guardianCanceller: _bookAddr(json, "GuardianCanceller"),
            federatedRoundLedger: _bookAddr(json, "FederatedRoundLedger"),
            guardianRecoveryModule: _bookAddr(json, "GuardianRecoveryModule"),
            organizationSbt: _bookAddr(json, "OrganizationSBT"),
            agentSbt: _bookAddr(json, "AgentSBT"),
            minCoordinatorBond: minBond,
            defaultCoordinatorBond: defaultBond,
            keys: k
        });
        d = deployWith(deployer, i);
        _writeBook("V060_GENESIS_OUT", bookJson(deployer, d, i));
    }

    /// @notice The standalone on-chain verify step: re-reads the deployed 0.6.0 set named by the
    ///         step's own output book (V060_GENESIS_OUT) against the inputs (V060_INPUT_BOOK and
    ///         the bond and key parameters), without broadcasting anything.
    function verifyBook() external {
        (uint128 minBond, uint128 defaultBond) = _bondsFromEnv();
        V060GovernanceSpec.KeyParams memory k = _keysFromEnv();
        string memory json = vm.readFile(vm.envString("V060_INPUT_BOOK"));
        string memory out = vm.readFile(vm.envString("V060_GENESIS_OUT"));
        Inputs memory i = Inputs({
            governanceTimelock: _bookAddr(json, "GovernanceTimelock"),
            governanceMultisig: _bookAddr(json, "GovernanceMultisig"),
            guardianTimelock: _bookAddr(json, "GuardianTimelock"),
            guardianMultisig: _bookAddr(json, "GuardianMultisig"),
            guardianCanceller: _bookAddr(json, "GuardianCanceller"),
            federatedRoundLedger: _bookAddr(json, "FederatedRoundLedger"),
            guardianRecoveryModule: _bookAddr(json, "GuardianRecoveryModule"),
            organizationSbt: _bookAddr(json, "OrganizationSBT"),
            agentSbt: _bookAddr(json, "AgentSBT"),
            minCoordinatorBond: minBond,
            defaultCoordinatorBond: defaultBond,
            keys: k
        });
        Deployed memory p = predict(i);
        string[8] memory names = [
            "FLRoundVerifier",
            "TaskVerifier",
            "WorkMarket",
            "DatasetRegistry",
            "GuardianRecoveryModuleV2",
            "UsageReceipts",
            "OrgBudgets",
            "WorkAttestations"
        ];
        address[8] memory want = [
            p.flRoundVerifier,
            p.taskVerifier,
            p.workMarket,
            p.datasetRegistry,
            p.guardianRecoveryModuleV2,
            p.usageReceipts,
            p.orgBudgets,
            p.workAttestations
        ];
        for (uint256 n = 0; n < 8; n++) {
            require(
                _bookAddr(out, names[n]) == want[n],
                string.concat(names[n], ": the output book is not where this build puts it")
            );
        }
        verify(i, p);
        console.log("V060 verify PASS: every 0.6.0 genesis contract re-read on chain");
    }

    /// @notice Where every 0.6.0 genesis contract lands for `i` (nothing is deployed). The
    ///         genesis spec publishes these before the ceremony.
    function predict(Inputs memory i) public pure returns (Deployed memory d) {
        _requireBonds(i);
        address gt = i.governanceTimelock;
        address rt = i.guardianTimelock;
        d.providerRegistry =
            _create2Address(V060GovernanceSpec.PROVIDER_REGISTRY, V060GovernanceSpec.providerRegistryInit(gt, rt));
        d.guardianCancellerV2 = _create2Address(
            V060GovernanceSpec.GUARDIAN_CANCELLER_V2, V060GovernanceSpec.guardianCancellerV2Init(gt, rt, d.providerRegistry)
        );
        d.flRoundVerifier = _create2Address(
            V060GenesisSpec.FL_ROUND_VERIFIER, V060GenesisSpec.flRoundVerifierInit(i.federatedRoundLedger)
        );
        d.taskVerifier = _create2Address(V060GenesisSpec.TASK_VERIFIER, V060GenesisSpec.taskVerifierInit());
        d.workMarket = _create2Address(V060GenesisSpec.WORK_MARKET, _workMarketInit(i, d));
        d.datasetRegistry =
            _create2Address(V060GenesisSpec.DATASET_REGISTRY, V060GenesisSpec.datasetRegistryInit(gt));
        d.guardianRecoveryModuleV2 = _create2Address(
            V060GenesisSpec.GUARDIAN_RECOVERY_V2, V060GenesisSpec.guardianRecoveryV2Init(i.guardianRecoveryModule)
        );
        d.usageReceipts = _create2Address(V060GenesisSpec.USAGE_RECEIPTS, V060GenesisSpec.usageReceiptsInit());
        d.orgBudgets =
            _create2Address(V060GenesisSpec.ORG_BUDGETS, V060GenesisSpec.orgBudgetsInit(gt, i.organizationSbt));
        d.workAttestations =
            _create2Address(V060GenesisSpec.WORK_ATTESTATIONS, V060GenesisSpec.workAttestationsInit(i.agentSbt));
    }

    /// @notice The step with explicit inputs (no env reads), for tests and callers.
    function deployWith(address deployer, Inputs memory i) public returns (Deployed memory d) {
        require(deployer != address(0), "deployer must be set");
        V060GovernanceSpec.requireKeyParams(i.keys);
        Deployed memory p = predict(i);
        // The 0.6.0 genesis always runs the genesis profile; the node must agree on the chain id.
        _resolveChainProfile(true);
        _checkKeys(deployer, i);
        _checkInputs(i, p);

        console.log("=== 0.6.0 ceremony genesis contracts (V60-GEN) ===");
        console.log("Deployer:", deployer);
        console.log("Chain ID:", block.chainid);

        _startBroadcastAsDeployer(deployer);
        d.providerRegistry = p.providerRegistry;
        d.guardianCancellerV2 = p.guardianCancellerV2;
        d.flRoundVerifier = _deployFlRoundVerifier(i);
        d.taskVerifier = _deployTaskVerifier();
        d.workMarket = _deployWorkMarket(i, d);
        d.datasetRegistry = _deployDatasetRegistry(i);
        d.guardianRecoveryModuleV2 = _deployGuardianRecoveryV2(i);
        d.usageReceipts = _deployUsageReceipts();
        d.orgBudgets = _deployOrgBudgets(i);
        d.workAttestations = _deployWorkAttestations(i);
        vm.stopBroadcast();

        require(keccak256(abi.encode(d)) == keccak256(abi.encode(p)), "a 0.6.0 genesis contract is not at its predicted address");
        verify(i, d);

        console.log("FLRoundVerifier          :", d.flRoundVerifier);
        console.log("TaskVerifier             :", d.taskVerifier);
        console.log("WorkMarket               :", d.workMarket);
        console.log("DatasetRegistry          :", d.datasetRegistry);
        console.log("GuardianRecoveryModuleV2 :", d.guardianRecoveryModuleV2);
        console.log("UsageReceipts            :", d.usageReceipts);
        console.log("OrgBudgets               :", d.orgBudgets);
        console.log("WorkAttestations         :", d.workAttestations);
    }

    /// @notice The book this step writes: the eight contracts it deploys (ProviderRegistry and the
    ///         canceller seat are in P1's governance book, not repeated here) and its parameters.
    function bookJson(address deployer, Deployed memory d, Inputs memory i) public view returns (string memory) {
        string[] memory names = new string[](8);
        address[] memory addrs = new address[](8);
        (names[0], addrs[0]) = ("FLRoundVerifier", d.flRoundVerifier);
        (names[1], addrs[1]) = ("TaskVerifier", d.taskVerifier);
        (names[2], addrs[2]) = ("WorkMarket", d.workMarket);
        (names[3], addrs[3]) = ("DatasetRegistry", d.datasetRegistry);
        (names[4], addrs[4]) = ("GuardianRecoveryModuleV2", d.guardianRecoveryModuleV2);
        (names[5], addrs[5]) = ("UsageReceipts", d.usageReceipts);
        (names[6], addrs[6]) = ("OrgBudgets", d.orgBudgets);
        (names[7], addrs[7]) = ("WorkAttestations", d.workAttestations);
        string memory params = string.concat(
            '"v060":{"minCoordinatorBond":"',
            vm.toString(uint256(i.minCoordinatorBond)),
            '","defaultCoordinatorBond":"',
            vm.toString(uint256(i.defaultCoordinatorBond)),
            '","taskReviewWindow":',
            vm.toString(uint256(V060GenesisSpec.TASK_REVIEW_WINDOW)),
            ',"usageMaxBackfillDays":',
            vm.toString(uint256(V060GenesisSpec.USAGE_MAX_BACKFILL_DAYS)),
            ',"slashSink":"',
            vm.toString(i.governanceTimelock),
            '","guardian":"',
            vm.toString(i.guardianTimelock),
            '","providerRegistry":"',
            vm.toString(d.providerRegistry),
            '","guardianCancellerV2":"',
            vm.toString(d.guardianCancellerV2),
            '"}'
        );
        return _bookJson(deployer, names, addrs, params);
    }

    // ------------------------------------------------------------------ inputs

    function _requireBonds(Inputs memory i) internal pure {
        require(
            i.minCoordinatorBond != 0 && i.defaultCoordinatorBond >= i.minCoordinatorBond,
            V060GenesisSpec.PENDING_COORDINATOR_BONDS
        );
    }

    function _keysFromEnv() internal view returns (V060GovernanceSpec.KeyParams memory k) {
        (k.governanceOwners, k.guardianOwners) = inventoryRoles(vm.envOr("GENESIS_KEY_INVENTORY", string("")));
        k.retiredKeys = vm.envOr("GENESIS_RETIRED_KEYS", ",", new address[](0));
        k.guardianVetoMargin = vm.envOr("GENESIS_GUARDIAN_VETO_MARGIN", uint256(0));
        V060GovernanceSpec.requireKeyParams(k);
    }

    function _bondsFromEnv() internal view returns (uint128 minBond, uint128 defaultBond) {
        require(vm.envExists(BOND_MIN_KEY) && vm.envExists(BOND_DEFAULT_KEY), V060GenesisSpec.PENDING_COORDINATOR_BONDS);
        uint256 m = vm.envUint(BOND_MIN_KEY);
        uint256 dflt = vm.envUint(BOND_DEFAULT_KEY);
        require(m <= type(uint128).max && dflt <= type(uint128).max, "coordinator bond exceeds uint128");
        (minBond, defaultBond) = (uint128(m), uint128(dflt));
    }

    /// @notice `name` from the book's `contracts`, else its `aaStack`; reverts when absent.
    function _bookAddr(string memory json, string memory name) internal view returns (address) {
        string memory c = string.concat(".contracts.", name);
        if (vm.keyExistsJson(json, c)) return vm.parseJsonAddress(json, c);
        string memory aa = string.concat(".aaStack.", name);
        if (vm.keyExistsJson(json, aa)) return vm.parseJsonAddress(json, aa);
        revert(string.concat(name, " is missing from V060_INPUT_BOOK"));
    }


    /// @notice Keys (fed #467 section 0.6; D-K3): the deployer is off the retired list, and every
    ///         owner of both councils (read on chain from the multisigs that front the timelocks)
    ///         is on the key inventory and off the retired list.
    function _checkKeys(address deployer, Inputs memory i) internal view {
        V060GovernanceSpec.requireKeyParams(i.keys);
        V060GovernanceSpec.requireNotRetired("deployer", deployer, i.keys.retiredKeys);
        _checkCouncilKeys("GOVERNANCE", "GOV_OWNERS", i.governanceMultisig, i.governanceTimelock, i.keys.governanceOwners, i.keys);
        _checkCouncilKeys("GUARDIAN", "GRD_OWNERS", i.guardianMultisig, i.guardianTimelock, i.keys.guardianOwners, i.keys);
    }

    function _checkCouncilKeys(
        string memory name,
        string memory tag,
        address multisig,
        address timelock,
        address[] memory allowed,
        V060GovernanceSpec.KeyParams memory k
    ) internal view {
        require(multisig.code.length != 0, string.concat(name, " multisig: no code"));
        (bool okT, address fronted) = _readAddress(multisig, abi.encodeWithSignature("timelock()"));
        require(okT && fronted == timelock, string.concat(name, " multisig does not front its timelock"));
        address[] memory owners = MultisigProposer(multisig).owners();
        require(owners.length != 0, string.concat(name, " multisig: no owners"));
        for (uint256 n = 0; n < owners.length; n++) {
            V060GovernanceSpec.requireKnownKey(string.concat(name, " owner"), tag, owners[n], allowed, k);
        }
    }

    /// @notice The governance-book provenance checks on the two councils this step reads.
    function _checkGovernance(Inputs memory i, Deployed memory p) internal {
        _requireCouncilFloor("GOVERNANCE", i.governanceTimelock, i.governanceMultisig, true);
        _requireCouncilFloor("GUARDIAN", i.guardianTimelock, i.guardianMultisig, false);
        string memory ms = _multisigProposerProblem(
            i.governanceMultisig, i.governanceTimelock, string.concat(GENESIS_SALT_PREFIX, "GovernanceMultisig")
        );
        require(bytes(ms).length == 0, string.concat("GovernanceMultisig: ", ms));
        // The v2 seat, its registry and the GUARDIAN council, exactly as a 0.6.0 governance book.
        (string memory seat, address canceller) = _bookGuardianCanceller(_governanceBook(i, p), i.governanceTimelock);
        require(bytes(seat).length == 0, string.concat("governance book: ", seat));
        address[] memory extra = new address[](1);
        extra[0] = canceller;
        string memory holders = _timelockHolderProblem(i.governanceTimelock, i.governanceMultisig, extra);
        require(bytes(holders).length == 0, string.concat("GOVERNANCE timelock: ", holders));
    }

    /// @notice The governance book P1 writes in its 0.6.0 mode, for these inputs.
    function _governanceBook(Inputs memory i, Deployed memory p) internal pure returns (string memory) {
        return string.concat(
            '{"contracts":{"GovernanceTimelock":"',
            vm.toString(i.governanceTimelock),
            '","GovernanceMultisig":"',
            vm.toString(i.governanceMultisig),
            '","GuardianTimelock":"',
            vm.toString(i.guardianTimelock),
            '","GuardianMultisig":"',
            vm.toString(i.guardianMultisig),
            '","GuardianCanceller":"',
            vm.toString(i.guardianCanceller),
            '","ProviderRegistry":"',
            vm.toString(p.providerRegistry),
            '"},"params":{"guardianCancellerVersion":2}}'
        );
    }

    function _checkInputs(Inputs memory i, Deployed memory p) internal {
        require(i.governanceTimelock.code.length != 0, "GOVERNANCE timelock: no code");
        require(i.guardianTimelock.code.length != 0, "GUARDIAN timelock: no code");

        // P1 in its v2-canceller mode: the registry and v2 are live where this build puts them.
        require(
            p.providerRegistry.code.length != 0,
            "ProviderRegistry: not live at its CREATE2 address for (GOVERNANCE, GUARDIAN); run P1 with GENESIS_V060=1"
        );
        require(
            i.guardianCanceller == p.guardianCancellerV2 && p.guardianCancellerV2.code.length != 0,
            "GuardianCanceller: the governance book's seat is not GuardianCancellerV2 for this ProviderRegistry"
        );
        TimelockController gt = TimelockController(payable(i.governanceTimelock));
        bytes32 canceller = gt.CANCELLER_ROLE();
        require(gt.hasRole(canceller, p.guardianCancellerV2), "GuardianCancellerV2 lacks CANCELLER on GOVERNANCE");
        address v1 = _create2Address(
            "Genesis.GuardianCanceller",
            abi.encodePacked(
                type(GuardianCanceller).creationCode, abi.encode(i.governanceTimelock, i.guardianTimelock)
            )
        );
        require(!gt.hasRole(canceller, v1), "GuardianCanceller v1 holds CANCELLER on GOVERNANCE");
        V060GovernanceSpec.requireVetoMargin(
            TimelockController(payable(i.guardianTimelock)).getMinDelay(), i.keys.guardianVetoMargin
        );
        _checkGovernance(i, p);

        require(i.federatedRoundLedger.code.length != 0, "FederatedRoundLedger: no code");
        require(i.guardianRecoveryModule.code.length != 0, "GuardianRecoveryModule (V1): no code");
        // Identity, not only code: this build's instance at the address its phase deploys it to.
        require(
            i.federatedRoundLedger == _create2Address("FederatedRoundLedger", type(FederatedRoundLedger).creationCode)
                && i.federatedRoundLedger.codehash == address(new FederatedRoundLedger()).codehash,
            "FederatedRoundLedger: not this build's ledger at its CREATE2 address"
        );
        require(
            i.guardianRecoveryModule
                == _create2Address("GuardianRecoveryModule", type(GuardianRecoveryModule).creationCode)
                && i.guardianRecoveryModule.codehash == address(new GuardianRecoveryModule()).codehash,
            "GuardianRecoveryModule (V1): not this build's module at its CREATE2 address"
        );
        require(i.organizationSbt.code.length != 0, "OrganizationSBT: no code");
        require(i.agentSbt.code.length != 0, "AgentSBT: no code");
        (bool okO, address orgOwner) = _readAddress(i.organizationSbt, abi.encodeWithSignature("owner()"));
        require(okO && orgOwner == i.governanceTimelock, "OrganizationSBT: owner is not the GOVERNANCE timelock");
        (bool okA, address agentOwner) = _readAddress(i.agentSbt, abi.encodeWithSignature("owner()"));
        require(okA && agentOwner == i.governanceTimelock, "AgentSBT: owner is not the GOVERNANCE timelock");
        (bool okR, address agentOrgs) = _readAddress(i.agentSbt, abi.encodeWithSignature("orgContract()"));
        require(okR && agentOrgs == i.organizationSbt, "AgentSBT: reads another OrganizationSBT");
    }

    // ------------------------------------------------------------------ deploys (reuse when live)

    function _workMarketInit(Inputs memory i, Deployed memory d) internal pure returns (bytes memory) {
        return V060GenesisSpec.workMarketInit(
            i.governanceTimelock,
            i.guardianTimelock,
            i.defaultCoordinatorBond,
            i.minCoordinatorBond,
            d.flRoundVerifier,
            d.taskVerifier
        );
    }

    function _deployFlRoundVerifier(Inputs memory i) internal returns (address) {
        string memory n = V060GenesisSpec.FL_ROUND_VERIFIER;
        bytes memory init = V060GenesisSpec.flRoundVerifierInit(i.federatedRoundLedger);
        if (_isLive(n, init)) return _create2Address(n, init);
        return address(new FLRoundVerifier{salt: Salts.salt(n)}(IFederatedRoundLedgerReads(i.federatedRoundLedger)));
    }

    function _deployTaskVerifier() internal returns (address) {
        string memory n = V060GenesisSpec.TASK_VERIFIER;
        bytes memory init = V060GenesisSpec.taskVerifierInit();
        if (_isLive(n, init)) return _create2Address(n, init);
        return address(new TaskVerifier{salt: Salts.salt(n)}(V060GenesisSpec.TASK_REVIEW_WINDOW));
    }

    function _deployWorkMarket(Inputs memory i, Deployed memory d) internal returns (address) {
        string memory n = V060GenesisSpec.WORK_MARKET;
        bytes memory init = _workMarketInit(i, d);
        if (_isLive(n, init)) return _create2Address(n, init);
        return address(
            new WorkMarket{salt: Salts.salt(n)}(
                i.governanceTimelock,
                i.guardianTimelock,
                i.governanceTimelock,
                i.defaultCoordinatorBond,
                i.minCoordinatorBond,
                V060GenesisSpec.initialVerifiers(d.flRoundVerifier, d.taskVerifier)
            )
        );
    }

    function _deployDatasetRegistry(Inputs memory i) internal returns (address) {
        string memory n = V060GenesisSpec.DATASET_REGISTRY;
        bytes memory init = V060GenesisSpec.datasetRegistryInit(i.governanceTimelock);
        if (_isLive(n, init)) return _create2Address(n, init);
        return address(new DatasetRegistry{salt: Salts.salt(n)}(i.governanceTimelock));
    }

    function _deployGuardianRecoveryV2(Inputs memory i) internal returns (address) {
        string memory n = V060GenesisSpec.GUARDIAN_RECOVERY_V2;
        bytes memory init = V060GenesisSpec.guardianRecoveryV2Init(i.guardianRecoveryModule);
        if (_isLive(n, init)) return _create2Address(n, init);
        return address(
            new GuardianRecoveryModuleV2{salt: Salts.salt(n)}(IGuardianRecoveryModuleV1(i.guardianRecoveryModule))
        );
    }

    function _deployUsageReceipts() internal returns (address) {
        string memory n = V060GenesisSpec.USAGE_RECEIPTS;
        bytes memory init = V060GenesisSpec.usageReceiptsInit();
        if (_isLive(n, init)) return _create2Address(n, init);
        return address(new UsageReceipts{salt: Salts.salt(n)}(V060GenesisSpec.USAGE_MAX_BACKFILL_DAYS));
    }

    function _deployOrgBudgets(Inputs memory i) internal returns (address) {
        string memory n = V060GenesisSpec.ORG_BUDGETS;
        bytes memory init = V060GenesisSpec.orgBudgetsInit(i.governanceTimelock, i.organizationSbt);
        if (_isLive(n, init)) return _create2Address(n, init);
        return address(new OrgBudgets{salt: Salts.salt(n)}(i.governanceTimelock, IOrganizationSBT(i.organizationSbt)));
    }

    function _deployWorkAttestations(Inputs memory i) internal returns (address) {
        string memory n = V060GenesisSpec.WORK_ATTESTATIONS;
        bytes memory init = V060GenesisSpec.workAttestationsInit(i.agentSbt);
        if (_isLive(n, init)) return _create2Address(n, init);
        return address(new WorkAttestations{salt: Salts.salt(n)}(IAgentSBT(i.agentSbt)));
    }

    // ------------------------------------------------------------------ postconditions

    /// @notice The on-chain verify step: re-reads every 0.6.0 genesis contract and its wiring
    ///         (slashSink, verifier allowlist, bonds, time windows, governance and guardian seats,
    ///         CANCELLER on GOVERNANCE held by v2 and not v1). Reverts on the first difference.
    function verify(Inputs memory i, Deployed memory d) public view {
        for (uint256 n = 0; n < 10; n++) {
            require(_at(d, n).code.length != 0, "a 0.6.0 genesis contract has no code");
        }
        address gt = i.governanceTimelock;
        address rt = i.guardianTimelock;
        require(address(FLRoundVerifier(d.flRoundVerifier).frl()) == i.federatedRoundLedger, "FLRoundVerifier: ledger");
        require(TaskVerifier(d.taskVerifier).reviewWindow() == V060GenesisSpec.TASK_REVIEW_WINDOW, "TaskVerifier: window");
        WorkMarket m = WorkMarket(payable(d.workMarket));
        require(m.governance() == gt, "WorkMarket: governance is not the GOVERNANCE timelock");
        require(m.guardian() == rt, "WorkMarket: guardian is not the guardian council");
        require(m.slashSink() == gt, "WorkMarket: slashSink is not the GOVERNANCE timelock");
        require(
            m.minCoordinatorBond() == i.minCoordinatorBond && m.defaultCoordinatorBond() == i.defaultCoordinatorBond,
            "WorkMarket: coordinator bonds"
        );
        require(
            m.verifierAllowed(d.flRoundVerifier) && m.verifierAllowed(d.taskVerifier), "WorkMarket: verifier allowlist"
        );
        require(DatasetRegistry(d.datasetRegistry).governance() == gt, "DatasetRegistry: governance");
        require(
            address(GuardianRecoveryModuleV2(d.guardianRecoveryModuleV2).v1()) == i.guardianRecoveryModule,
            "GuardianRecoveryModuleV2: v1"
        );
        require(
            UsageReceipts(d.usageReceipts).maxBackfillDays() == V060GenesisSpec.USAGE_MAX_BACKFILL_DAYS,
            "UsageReceipts: backfill"
        );
        require(OrgBudgets(d.orgBudgets).governance() == gt, "OrgBudgets: governance");
        require(address(OrgBudgets(d.orgBudgets).orgs()) == i.organizationSbt, "OrgBudgets: orgs");
        require(address(WorkAttestations(d.workAttestations).agents()) == i.agentSbt, "WorkAttestations: agents");
        ProviderRegistry reg = ProviderRegistry(d.providerRegistry);
        require(reg.governance() == gt && reg.guardian() == rt, "ProviderRegistry: governance or guardian");
        require(reg.vetoWindow() == V060GovernanceSpec.PROVIDER_VETO_WINDOW, "ProviderRegistry: veto window");
        GuardianCancellerV2 c = GuardianCancellerV2(d.guardianCancellerV2);
        require(
            c.governanceTimelock() == gt && c.guardian() == rt && c.providerRegistry() == d.providerRegistry,
            "GuardianCancellerV2: wiring"
        );
        TimelockController g = TimelockController(payable(gt));
        bytes32 cancellerRole = g.CANCELLER_ROLE();
        require(g.hasRole(cancellerRole, d.guardianCancellerV2), "GuardianCancellerV2 lacks CANCELLER on GOVERNANCE");
        address v1 = _create2Address(
            "Genesis.GuardianCanceller", abi.encodePacked(type(GuardianCanceller).creationCode, abi.encode(gt, rt))
        );
        require(!g.hasRole(cancellerRole, v1), "GuardianCanceller v1 holds CANCELLER on GOVERNANCE");
    }

    function _at(Deployed memory d, uint256 n) internal pure returns (address) {
        address[10] memory all = [
            d.providerRegistry,
            d.guardianCancellerV2,
            d.flRoundVerifier,
            d.taskVerifier,
            d.workMarket,
            d.datasetRegistry,
            d.guardianRecoveryModuleV2,
            d.usageReceipts,
            d.orgBudgets,
            d.workAttestations
        ];
        return all[n];
    }
}
