// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";
import "./Salts.sol";
import "./lib/AdminChecks.sol";
import "./lib/Create2Deploy.sol";
import "./lib/GenesisBook.sol";
import {FederatedRoundLedger} from "../src/FederatedRoundLedger.sol";
import {PatronageLedger} from "../src/coop/PatronageLedger.sol";
import {MultisigProposer} from "../src/genesis/MultisigProposer.sol";

/// @title DeployDormantLedgers: FederatedRoundLedger + PatronageLedger, dormant (C2 D9 / C4)
/// @notice "Dormant" = deployed with no operator wired: nothing reads or writes them until
///         GOVERNANCE turns them on with a timelocked operation.
///
///         FederatedRoundLedger: CREATE2 (`Salts.salt("FederatedRoundLedger")`, keep-live).
///           It has NO admin, governance or owner slot and takes no constructor arguments:
///           cluster registration is permissionless, it holds no value and calls only the
///           0x0110 precompile. So there is nothing to hand to GOVERNANCE; it is dormant
///           because settlement (citrate-settlement `fl` gate, PatronageLedger.commitRound)
///           does not read it until wired.
///
///         PatronageLedger (vendored from citrate-coop, src/coop/): plain CREATE from the
///           deployer, NOT CREATE2. Its `Auth` constructor takes the initial DEFAULT_ADMIN
///           explicitly (it never reads `msg.sender`), and the script passes
///           GOVERNANCE_TIMELOCK directly, so there is no deployer-held admin and no
///           hand-over step: the broadcaster never holds any role, even transiently. No
///           SETTLER / COOP / LEDGER_YEAR_KEEPER role is granted to anyone. Its address
///           depends on the deployer nonce, and every run deploys a new instance: take the
///           address from DORMANT_LEDGERS_OUT, do not re-run to "reuse".
///
///         Governance is checked before anything is sent, not only taken on trust: the
///           GOVERNANCE_TIMELOCK must be an OZ TimelockController that administers itself,
///           whose PROPOSER / EXECUTOR / CANCELLER is GOVERNANCE_MULTISIG (a MultisigProposer
///           fronting that timelock), with execution not open to everyone, and on which none
///           of {configured deployer, actual broadcaster, CREATE2 factory, this script} holds
///           DEFAULT_ADMIN or a timelock role. Neither may they be multisig owners. Floors:
///             genesis profile (chain 40204, owner decision): delay >= 48 h AND the council
///               is at least 3-of-5. Selected by chain id; there is no override.
///             rehearsal (any other chain): delay >= 1 h (DeployGenesisGovernance's floor).
///           Complete holder sets, not only named accounts: the timelock must run this
///           build's OZ TimelockController code, be its own SOLE DEFAULT_ADMIN, and have the
///           council as SOLE PROPOSER, EXECUTOR and CANCELLER. OZ AccessControl is not
///           enumerable, so the sets are rebuilt from the timelock's RoleGranted / RoleRevoked
///           logs (AdminChecks `_timelockRoleHistory`: eth_getLogs paged <= 1000 blocks from
///           TIMELOCK_HISTORY_FROM_BLOCK, default 0) and every account found is re-read with
///           hasRole. No node, a failed page, or a history that does not start at the
///           timelock's construction fails closed.
///           The timelock and multisig are written to the book's `contracts`, so the
///           CheckDeployedAdmins gate re-checks them too.
///
///         Fail closed on signer mismatch: the account Forge actually broadcasts as must be
///           the configured deployer (CEREMONY_DEPLOYER_ADDRESS / DEPLOYER_ADDRESS), or the
///           script reverts before sending anything. Postconditions then check, on the live
///           ledger, that GOVERNANCE_TIMELOCK is admin and that none of {configured deployer,
///           actual broadcaster, CREATE2 factory, this script} holds DEFAULT_ADMIN_ROLE.
///
///         Required env: GOVERNANCE_TIMELOCK (an OZ TimelockController, e.g. the
///         GovernanceTimelock from DeployGenesisGovernance), GOVERNANCE_MULTISIG (its
///         GovernanceMultisig), PATRONAGE_KYC_REGISTRY and
///         PATRONAGE_MEMBERSHIP (the KYC registry and membership contract PatronageLedger
///         reads; both immutable, both must have code), DORMANT_LEDGERS_OUT, and
///         CEREMONY_DEPLOYER_ADDRESS or DEPLOYER_ADDRESS (must equal the forge
///         broadcast signer; enforced). Needs --rpc-url (the role history comes from the
///         node). Optional: TIMELOCK_HISTORY_FROM_BLOCK (a block at or before the timelock's
///         creation; a later one fails the construction check), TIMELOCK_HISTORY_WINDOW (1..1000).
contract DeployDormantLedgers is ScriptEnv, AdminChecks, Create2Deploy, GenesisBook {
    string internal constant FRL = "FederatedRoundLedger";

    /// Genesis profile: the 40204 GOVERNANCE council is at least 3-of-5 behind a 48 h delay.
    uint256 public constant GENESIS_CHAIN_ID = 40204;
    uint256 public constant GENESIS_GOV_MIN_DELAY = 48 hours;
    uint256 public constant GENESIS_GOV_MIN_THRESHOLD = 3;
    uint256 public constant GENESIS_GOV_MIN_OWNERS = 5;
    /// Rehearsal chains: same floor as DeployGenesisGovernance.MIN_DELAY_FLOOR.
    uint256 public constant REHEARSAL_GOV_MIN_DELAY = 1 hours;

    struct Deployed {
        address federatedRoundLedger;
        address patronageLedger;
    }

    function run() external returns (Deployed memory d) {
        address deployer = deployerAddress();
        address governance = vm.envAddress("GOVERNANCE_TIMELOCK");
        address council = vm.envAddress("GOVERNANCE_MULTISIG");
        address kyc = vm.envAddress("PATRONAGE_KYC_REGISTRY");
        address membership = vm.envAddress("PATRONAGE_MEMBERSHIP");
        vm.envString("DORMANT_LEDGERS_OUT"); // resolve before broadcasting: a missing path fails first
        d = deployWith(deployer, governance, council, kyc, membership);
        _writeBook("DORMANT_LEDGERS_OUT", bookJson(deployer, governance, council, d));
    }

    /// @notice The ceremony with explicit inputs (no env reads), for tests and callers.
    function deployWith(address deployer, address governance, address council, address kyc, address membership)
        public
        returns (Deployed memory d)
    {
        require(deployer != address(0), "deployer must be set");
        require(governance != deployer, "GOVERNANCE_TIMELOCK cannot be the deployer");
        require(_isTimelock(governance), "GOVERNANCE_TIMELOCK is not a TimelockController");
        address[] memory accounts = new address[](2);
        (accounts[0], accounts[1]) = (deployer, address(this));
        _assertGovernanceCouncil(governance, council, accounts);
        require(kyc.code.length != 0, "PATRONAGE_KYC_REGISTRY has no code on this chain");
        require(membership.code.length != 0, "PATRONAGE_MEMBERSHIP has no code on this chain");

        console.log("=== Dormant ledgers (C2 D9) ===");
        console.log("Deployer:", deployer);
        console.log("Governance timelock:", governance);
        console.log("Governance multisig:", council);

        // Refuses to send anything unless the forge signer is the configured deployer.
        address broadcaster = _startBroadcastAsDeployer(deployer);
        bytes memory frlInit = type(FederatedRoundLedger).creationCode;
        d.federatedRoundLedger = _isLive(FRL, frlInit)
            ? _create2Address(FRL, frlInit)
            : address(new FederatedRoundLedger{salt: Salts.salt(FRL)}());

        // GOVERNANCE_TIMELOCK is the explicit initial admin: nothing to hand over or revoke.
        d.patronageLedger = address(new PatronageLedger(kyc, membership, governance));
        vm.stopBroadcast();

        _assertDormant(d, deployer, broadcaster, governance, kyc, membership);
        address[] memory deployAccounts = new address[](3);
        (deployAccounts[0], deployAccounts[1], deployAccounts[2]) = (deployer, broadcaster, address(this));
        _assertGovernanceCouncil(governance, council, deployAccounts);
        console.log("FederatedRoundLedger:", d.federatedRoundLedger);
        console.log("PatronageLedger     :", d.patronageLedger);
    }

    function bookJson(address deployer, address governance, address council, Deployed memory d)
        public
        view
        returns (string memory)
    {
        string[] memory names = new string[](4);
        address[] memory addrs = new address[](4);
        (names[0], addrs[0]) = ("FederatedRoundLedger", d.federatedRoundLedger);
        (names[1], addrs[1]) = ("PatronageLedger", d.patronageLedger);
        (names[2], addrs[2]) = ("GovernanceTimelock", governance);
        (names[3], addrs[3]) = ("GovernanceMultisig", council);
        return _bookJson(deployer, names, addrs, string.concat('"governance":"', vm.toString(governance), '"'));
    }

    function _isTimelock(address a) internal view returns (bool) {
        if (a.code.length == 0) return false;
        (bool ok, bytes memory ret) = a.staticcall(abi.encodeWithSignature("getMinDelay()"));
        return ok && ret.length == 32;
    }

    /// @notice Revert unless `governance` is a self-administered timelock run only by `council`
    ///         (a MultisigProposer fronting it), at or above this profile's floors, on which no
    ///         address in `accounts` (the deploy accounts) holds an admin slot or governing seat.
    function _assertGovernanceCouncil(address governance, address council, address[] memory accounts) internal {
        string memory tl = "GOVERNANCE_TIMELOCK";
        string memory ms = "GOVERNANCE_MULTISIG";
        require(council.code.length != 0, "GOVERNANCE_MULTISIG has no code on this chain");
        _assertTimelockSeats(tl, governance, council, accounts[0]);
        _assertNoFactoryAdmin(ms, council);
        for (uint256 i = 0; i < accounts.length; i++) {
            require(accounts[i] != council, "GOVERNANCE_MULTISIG cannot be a deploy account");
            _assertNoDeployerAdmin(tl, governance, accounts[i]);
            _assertNoDeployerAdmin(ms, council, accounts[i]);
        }

        bool genesis = block.chainid == GENESIS_CHAIN_ID;
        uint256 delay = _timelockMinDelay(governance);
        require(
            delay >= (genesis ? GENESIS_GOV_MIN_DELAY : REHEARSAL_GOV_MIN_DELAY),
            genesis
                ? "GOVERNANCE_TIMELOCK: minDelay below the 48 h genesis floor"
                : "GOVERNANCE_TIMELOCK: minDelay below the 1 h rehearsal floor"
        );

        (bool ok, address fronted) = _readAddress(council, abi.encodeWithSignature("timelock()"));
        require(ok && fronted == governance, "GOVERNANCE_MULTISIG does not front GOVERNANCE_TIMELOCK");
        if (genesis) {
            MultisigProposer m = MultisigProposer(council);
            require(
                m.threshold() >= GENESIS_GOV_MIN_THRESHOLD && m.owners().length >= GENESIS_GOV_MIN_OWNERS,
                "GOVERNANCE_MULTISIG: below the 3-of-5 genesis floor"
            );
        }
        // Complete holder sets (chain#320 P1): the timelock is its SOLE admin and the council its
        // SOLE proposer, executor and canceller, established from the timelock's role history.
        _assertTimelockSoleHolders(tl, governance, council, new address[](0));
    }

    function _assertDormant(
        Deployed memory d,
        address deployer,
        address broadcaster,
        address governance,
        address kyc,
        address membership
    ) internal view {
        require(d.federatedRoundLedger.code.length != 0, "FederatedRoundLedger: no code");
        _assertNoFactoryAdmin("FederatedRoundLedger", d.federatedRoundLedger);
        _assertNoDeployerAdmin("FederatedRoundLedger", d.federatedRoundLedger, deployer);

        PatronageLedger ledger = PatronageLedger(d.patronageLedger);
        address[] memory notAdmin = new address[](4);
        (notAdmin[0], notAdmin[1], notAdmin[2], notAdmin[3]) = (deployer, broadcaster, ARACHNID_FACTORY, address(this));
        _assertSoleAdminAmong("PatronageLedger", d.patronageLedger, governance, notAdmin);
        _assertNoDeployerAdmin("PatronageLedger", d.patronageLedger, deployer);
        _assertNoDeployerAdmin("PatronageLedger", d.patronageLedger, broadcaster);
        require(address(ledger.kyc()) == kyc, "PatronageLedger: kyc mismatch");
        require(address(ledger.membership()) == membership, "PatronageLedger: membership mismatch");
        bytes32[3] memory ops = [ledger.SETTLER_ROLE(), ledger.COOP_ROLE(), ledger.YEAR_KEEPER_ROLE()];
        for (uint256 i = 0; i < 3; i++) {
            require(
                !ledger.hasRole(ops[i], deployer) && !ledger.hasRole(ops[i], broadcaster)
                    && !ledger.hasRole(ops[i], governance),
                "PatronageLedger: an operational role is wired (not dormant)"
            );
        }
        require(ledger.totalUnits() == 0, "PatronageLedger: not empty");
    }
}
