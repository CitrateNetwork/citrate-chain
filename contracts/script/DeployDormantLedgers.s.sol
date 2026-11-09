// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";
import "./Salts.sol";
import "./lib/AdminChecks.sol";
import "./lib/Create2Deploy.sol";
import "./lib/GenesisBook.sol";
import "./lib/GenesisProfile.sol";
import {FederatedRoundLedger} from "../src/FederatedRoundLedger.sol";
import {PatronageLedger} from "../src/coop/PatronageLedger.sol";

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
///           of {configured deployer, actual broadcaster, CREATE2 factory} holds
///           DEFAULT_ADMIN or a timelock role. Neither may they be multisig owners. Floors:
///             genesis profile (chain 40204, owner decision): the GenesisProfile floors, read
///               from chain: delay >= 48 h, council at least 3-of-5 with a majority threshold,
///               proposal TTL fixed at 14 days. There is no override.
///             rehearsal (any other chain): delay >= 1 h (DeployGenesisGovernance's floor).
///           Complete holder sets, not only named accounts: the timelock must run this
///           build's OZ TimelockController code, be its own SOLE DEFAULT_ADMIN, and have the
///           council as SOLE PROPOSER, EXECUTOR and CANCELLER. The only other CANCELLER
///           allowed is the governance book's GuardianCanceller, verified on chain
///           (GenesisProfile `_bookGuardianCanceller`), so a timelock that carries one needs
///           GENESIS_GOVERNANCE_BOOK. OZ AccessControl is not enumerable, so the sets are rebuilt from the timelock's RoleGranted / RoleRevoked
///           logs (AdminChecks `_timelockRoleHistory`: eth_getLogs paged <= 1000 blocks from
///           TIMELOCK_HISTORY_FROM_BLOCK, default 0) and every account found is re-read with
///           hasRole. No node, a failed page, or a history that does not start at the
///           timelock's construction fails closed.
///           The council is authenticated before any of its getters is read: its address
///           must be the CREATE2 address DeployGenesisGovernance gives a MultisigProposer for
///           (this timelock, its reported owners, threshold and proposalTtl) under the salt
///           "Genesis.GovernanceMultisig" (AdminChecks `_multisigProposerProblem`). That proves
///           the code and the values; a contract that only answers the same getters is refused.
///           The profile is chosen by the chain id the NODE reports (eth_chainId), which must
///           equal forge's simulated id, so --chain-id / --chain / FOUNDRY_CHAIN_ID cannot
///           select the rehearsal floors against a 40204 node; without a node the genesis
///           profile fails closed. The book records the profile and the node id.
///           The timelock and multisig are written to the book's `contracts`, so the
///           CheckDeployedAdmins gate re-checks them too.
///
///         Fail closed on signer mismatch: the account Forge actually broadcasts as must be
///           the configured deployer (CEREMONY_DEPLOYER_ADDRESS / DEPLOYER_ADDRESS), or the
///           script reverts before sending anything. Postconditions then check, on the live
///           ledger, that GOVERNANCE_TIMELOCK is admin and that none of {configured deployer,
///           actual broadcaster, CREATE2 factory} holds DEFAULT_ADMIN_ROLE.
///
///         Required env: GOVERNANCE_TIMELOCK (an OZ TimelockController, e.g. the
///         GovernanceTimelock from DeployGenesisGovernance), GOVERNANCE_MULTISIG (its
///         GovernanceMultisig), PATRONAGE_KYC_REGISTRY and
///         PATRONAGE_MEMBERSHIP (the KYC registry and membership contract PatronageLedger
///         reads; both immutable, both must have code), DORMANT_LEDGERS_OUT, and
///         CEREMONY_DEPLOYER_ADDRESS or DEPLOYER_ADDRESS (must equal the forge
///         broadcast signer; enforced). Needs --rpc-url (the role history comes from the
///         node). Optional: TIMELOCK_HISTORY_FROM_BLOCK (a speed-up only: a block at or before the
///         timelock's creation; a later one fails closed, because the first event replayed must be
///         the factory-made construction, AdminChecks `_timelockCreationProblem`),
///         TIMELOCK_HISTORY_WINDOW (1..1000).
///
///         Optional: GENESIS_GOVERNANCE_BOOK (the GENESIS_GOVERNANCE_OUT file written by
///         DeployGenesisGovernance). When set, the run refuses to start unless that book is
///         for this chain and its `contracts.GovernanceTimelock` equals GOVERNANCE_TIMELOCK,
///         and its GuardianCanceller (verified on chain) is the timelock's one permitted extra
///         CANCELLER. The dormant book does not repeat the canceller: run CheckDeployedAdmins
///         with the governance book alongside it (main or EXTRA_ADDRESS_BOOKS).
contract DeployDormantLedgers is ScriptEnv, AdminChecks, Create2Deploy, GenesisBook, GenesisProfile {
    string internal constant FRL = "FederatedRoundLedger";

    /// Rehearsal chains: same floor as DeployGenesisGovernance.MIN_DELAY_FLOOR.
    uint256 public constant REHEARSAL_GOV_MIN_DELAY = 1 hours;

    /// @notice The profile the last `deployWith` resolved; written into the book.
    ChainProfile public chainProfile;

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
        string memory govBook = vm.envOr("GENESIS_GOVERNANCE_BOOK", string(""));
        // Node chain id vs simulated chain id first, so a --chain-id / --chain / FOUNDRY_CHAIN_ID
        // mismatch is reported as such before the book's chainId is compared (deployWith
        // resolves the profile again for its own callers).
        _resolveChainProfile(false);
        string memory govJson = bytes(govBook).length != 0 ? vm.readFile(govBook) : "";
        if (bytes(govJson).length != 0) checkGovernanceBook(govJson, governance);
        d = deployWith(deployer, governance, council, kyc, membership, govJson);
        _writeBook("DORMANT_LEDGERS_OUT", bookJson(deployer, governance, council, d));
    }

    /// @notice The ceremony with explicit inputs (no env reads), for tests and callers, with no
    ///         governance book: the timelock may then carry no CANCELLER but `council`.
    function deployWith(address deployer, address governance, address council, address kyc, address membership)
        public
        returns (Deployed memory d)
    {
        return deployWith(deployer, governance, council, kyc, membership, "");
    }

    /// @notice As above; `governanceBook` (DeployGenesisGovernance's book JSON, or "") supplies
    ///         the GuardianCanceller the timelock may carry as its only extra CANCELLER.
    function deployWith(
        address deployer,
        address governance,
        address council,
        address kyc,
        address membership,
        string memory governanceBook
    ) public returns (Deployed memory d) {
        require(deployer != address(0), "deployer must be set");
        require(governance != deployer, "GOVERNANCE_TIMELOCK cannot be the deployer");
        require(_isTimelock(governance), "GOVERNANCE_TIMELOCK is not a TimelockController");
        // Node chain id vs simulated chain id, before anything else (GenesisProfile).
        ChainProfile memory cp = _resolveChainProfile(false);
        chainProfile = cp;
        // Script-contract addresses are simulation-only (forge refuses `address(this)` on a
        // script run path), so the deploy accounts are the configured deployer and, below, the
        // actual broadcaster.
        address[] memory accounts = new address[](1);
        accounts[0] = deployer;
        _assertGovernanceCouncil(governance, council, accounts, cp.genesis, governanceBook);
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
        address[] memory deployAccounts = new address[](2);
        (deployAccounts[0], deployAccounts[1]) = (deployer, broadcaster);
        _assertGovernanceCouncil(governance, council, deployAccounts, cp.genesis, governanceBook);
        console.log("FederatedRoundLedger:", d.federatedRoundLedger);
        console.log("PatronageLedger     :", d.patronageLedger);
    }

    /// @notice Revert unless the governance book `json` is for this chain and names
    ///         `governance` as its GovernanceTimelock.
    function checkGovernanceBook(string memory json, address governance) public view {
        require(
            vm.keyExistsJson(json, ".contracts.GovernanceTimelock"),
            "GENESIS_GOVERNANCE_BOOK: no contracts.GovernanceTimelock"
        );
        require(
            vm.keyExistsJson(json, ".chainId") && vm.parseJsonUint(json, ".chainId") == block.chainid,
            "GENESIS_GOVERNANCE_BOOK: book is for another chain"
        );
        require(
            vm.parseJsonAddress(json, ".contracts.GovernanceTimelock") == governance,
            "GOVERNANCE_TIMELOCK does not match GENESIS_GOVERNANCE_BOOK"
        );
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
        ChainProfile memory p = chainProfile;
        string memory params = string.concat(
            '"governance":"',
            vm.toString(governance),
            '","genesisProfile":',
            vm.toString(p.genesis),
            ',"nodeChainIdChecked":',
            vm.toString(p.nodeChecked),
            ',"nodeChainId":',
            vm.toString(p.nodeChainId),
            ',"overrides":{},"overrideUsed":false'
        );
        return _bookJson(deployer, names, addrs, params);
    }

    function _isTimelock(address a) internal view returns (bool) {
        if (a.code.length == 0) return false;
        (bool ok, bytes memory ret) = a.staticcall(abi.encodeWithSignature("getMinDelay()"));
        return ok && ret.length == 32;
    }

    /// @notice Revert unless `governance` is a self-administered timelock run only by `council`
    ///         (a MultisigProposer fronting it), at or above this profile's floors, on which no
    ///         address in `accounts` (the deploy accounts) holds an admin slot or governing seat.
    function _assertGovernanceCouncil(
        address governance,
        address council,
        address[] memory accounts,
        bool genesis,
        string memory governanceBook
    ) internal {
        string memory tl = "GOVERNANCE_TIMELOCK";
        string memory ms = "GOVERNANCE_MULTISIG";
        require(council.code.length != 0, "GOVERNANCE_MULTISIG has no code on this chain");
        _assertTimelockSeats(tl, governance, council, accounts[0]);
        // Authenticate the council before trusting any of its getters (chain#320 P1): it must be
        // the MultisigProposer DeployGenesisGovernance deploys for this timelock (CREATE2
        // provenance), so timelock(), threshold(), owners() and isOwner() below are its real state.
        _assertMultisigProposer(ms, council, governance, string.concat(GENESIS_SALT_PREFIX, "GovernanceMultisig"));
        _assertNoFactoryAdmin(ms, council);
        for (uint256 i = 0; i < accounts.length; i++) {
            require(accounts[i] != council, "GOVERNANCE_MULTISIG cannot be a deploy account");
            _assertNoDeployerAdmin(tl, governance, accounts[i]);
            _assertNoDeployerAdmin(ms, council, accounts[i]);
        }

        (bool ok, address fronted) = _readAddress(council, abi.encodeWithSignature("timelock()"));
        require(ok && fronted == governance, "GOVERNANCE_MULTISIG does not front GOVERNANCE_TIMELOCK");
        if (genesis) {
            // GenesisProfile's floors, shared with DeployGenesisGovernance and CheckDeployedAdmins.
            _requireCouncilFloor("GOVERNANCE", governance, council, true);
        } else {
            require(
                _timelockMinDelay(governance) >= REHEARSAL_GOV_MIN_DELAY,
                "GOVERNANCE_TIMELOCK: minDelay below the 1 h rehearsal floor"
            );
        }
        // Complete holder sets (chain#320 P1): the timelock is its SOLE admin and the council its
        // SOLE proposer, executor and canceller, established from the timelock's role history.
        // The one extra CANCELLER allowed is the governance book's verified GuardianCanceller.
        _assertTimelockSoleHolders(tl, governance, council, _extraCancellers(governance, governanceBook));
    }

    /// @notice `[GuardianCanceller]` from governance book `json` (verified on chain), or none
    ///         when no book is given. A book whose canceller does not verify reverts.
    function _extraCancellers(address governance, string memory json) internal returns (address[] memory extra) {
        if (bytes(json).length == 0) return new address[](0);
        (string memory problem, address canceller) = _bookGuardianCanceller(json, governance);
        require(bytes(problem).length == 0, string.concat("GENESIS_GOVERNANCE_BOOK: ", problem));
        extra = new address[](1);
        extra[0] = canceller;
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
        address[] memory notAdmin = new address[](3);
        (notAdmin[0], notAdmin[1], notAdmin[2]) = (deployer, broadcaster, ARACHNID_FACTORY);
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
