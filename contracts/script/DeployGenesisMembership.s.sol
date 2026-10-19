// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "./ScriptEnv.sol";
import "./Salts.sol";
import "./lib/AdminChecks.sol";
import "./lib/Create2Deploy.sol";
import "./lib/GenesisBook.sol";
import "./lib/GenesisProfile.sol";
import {CitrateMemberSBT} from "../src/core_membership/CitrateMemberSBT.sol";
import {MemberBond} from "../src/core_membership/MemberBond.sol";
import {MembershipStakeVault} from "../src/core_membership/MembershipStakeVault.sol";
import {ValidatorRegistry} from "../src/ValidatorRegistry.sol";
import {MultisigProposer} from "../src/genesis/MultisigProposer.sol";

/// @title DeployGenesisMembership: the Track M money path in the genesis contract set (C2 D9 / C4)
/// @notice Deploys the membership grant path for the betanet genesis: the 32,000-SALT grant
///         lands in a per-member `MemberBond` clone, locked for 364 days (height OR wall-clock
///         leg) behind a KYC gate, and bonds into `ValidatorRegistry` when the member
///         activates. Track M was settled by citrate-chain #139 (M-1: consensus does not
///         change; the per-member bond is the registry staker) and built by #141 (M-2.0 to
///         M-2.3). This script adds what genesis needs on top: governance holds upgrade
///         authority, the grant signer holds only the grant role.
///
///         Contracts (salted CREATE2 through the Arachnid factory, keep-live on a re-run):
///           CitrateMemberSBT(owner = GRANTOR)        the grant signer mints and attests KYC
///           MemberBond()                             the clone master copy
///           MembershipStakeVault()                   the UUPS implementation
///           ERC1967Proxy(impl, initialize(DEPLOYER)) THE vault address to pin
///
///         Hand-over, in the same broadcast as the deploy:
///           1. deployer -> vault.initializeGovernance(GOVERNANCE_TIMELOCK)  (upgrade authority)
///           2. deployer -> vault.transferOwnership(GRANTOR)                 (grant / lapse / renew)
///         The deployer is the vault owner only between the proxy's creation and step 2, and
///         nothing else can reach the proxy in between. The SBT is born owned by GRANTOR, so it
///         has nothing to hand over.
///
///         Fail closed before anything is sent:
///           - GOVERNANCE_TIMELOCK is an OZ TimelockController that administers itself, with
///             execution not open to everyone, run by GOVERNANCE_MULTISIG, on which neither the
///             configured deployer nor the CREATE2 factory holds an admin slot or governing
///             seat (and neither is a council owner). Floors: the genesis profile (chain 40204
///             as the NODE reports it: eth_chainId must equal forge's simulated id, so
///             --chain-id / --chain / FOUNDRY_CHAIN_ID cannot select another profile;
///             GenesisProfile `_resolveChainProfile`, no override) needs the GenesisProfile
///             floors read from chain (`_councilFloorProblem`: minDelay >= 48 h, a council of at
///             least 3-of-5 with a majority threshold, proposal TTL fixed at 14 days); any other
///             chain (rehearsal) needs minDelay >= 1 h.
///           - GOVERNANCE_MULTISIG is authenticated before any of its getters is read: its
///             address must be the CREATE2 address DeployGenesisGovernance gives a
///             MultisigProposer for (this timelock, its reported owners, its reported
///             threshold) under the salt "Genesis.GovernanceMultisig" (AdminChecks
///             `_assertMultisigProposer`). A contract that only answers the same getters is
///             refused.
///           - Complete holder sets, not only named accounts: the timelock runs this build's
///             OZ TimelockController code, is its own SOLE DEFAULT_ADMIN, and has the council
///             as SOLE PROPOSER, EXECUTOR and CANCELLER (the only other CANCELLER allowed is the
///             GuardianCanceller from GENESIS_GOVERNANCE_BOOK, verified on chain), rebuilt from the timelock's
///             RoleGranted / RoleRevoked logs (AdminChecks `_assertTimelockSoleHolders`; needs
///             --rpc-url, see DeployDormantLedgers for TIMELOCK_HISTORY_FROM_BLOCK / _WINDOW).
///             No node, a failed page, or a history that does not start at the timelock's
///             construction fails closed.
///           - GRANTOR is nonzero and is not the deployer, the governance timelock, the
///             governance multisig or the CREATE2 factory.
///           - VALIDATOR_REGISTRY has code and its `minStake()` is at most the 32,000 SALT a
///             grant carries, otherwise no granted member could ever activate.
///           - the forge broadcaster is the configured deployer.
///         Postconditions on the live contracts: vault owner == GRANTOR, vault governance ==
///         GOVERNANCE_TIMELOCK, no pending governance, no treasury and no pending treasury
///         (unactivated principal returns to a treasury only GOVERNANCE sets, two-step), SBT owner == GRANTOR, the vault holds
///         no SALT, and neither the deployer, the actual broadcaster nor the CREATE2 factory
///         holds any admin slot on the SBT or the vault; the governance checks are re-run
///         with the broadcaster added to the deploy accounts. The script contract's own address
///         is never an account here: it exists only in simulation (forge refuses
///         `address(this)` on a script run path), so the deploy accounts are the configured
///         deployer and the broadcaster.
///
///         Required env: GOVERNANCE_TIMELOCK, GOVERNANCE_MULTISIG (its GovernanceMultisig from
///         DeployGenesisGovernance), MEMBERSHIP_GRANTOR (the treasury-signer address
///         that places grants), VALIDATOR_REGISTRY, GENESIS_MEMBERSHIP_OUT, and
///         CEREMONY_DEPLOYER_ADDRESS or DEPLOYER_ADDRESS (must equal the forge broadcast
///         signer; enforced). Optional: GENESIS_GOVERNANCE_BOOK (DeployGenesisGovernance's
///         book; required in practice on genesis, where the GOVERNANCE timelock carries the
///         GuardianCanceller). Output: a book-shaped JSON at GENESIS_MEMBERSHIP_OUT, which
///         `CheckDeployedAdmins` reads through EXTRA_ADDRESS_BOOKS; it lists GovernanceTimelock
///         with its paired GovernanceMultisig, so the gate's TIMELOCK-HOLDERS check re-runs. Nothing touches
///         `addresses/40204.json`.
///
///         NOTE: chain 40204 rejects EIP-1559 transactions; broadcast with `--legacy` and an
///         explicit gas limit.
contract DeployGenesisMembership is ScriptEnv, AdminChecks, Create2Deploy, GenesisBook, GenesisProfile {
    string internal constant SBT = "CitrateMemberSBT";
    string internal constant BOND = "MemberBond";
    string internal constant VAULT_IMPL = "MembershipStakeVault.impl";
    string internal constant VAULT = "MembershipStakeVault";

    /// Rehearsal chains: DeployGenesisGovernance.MIN_DELAY_FLOOR. The genesis floors are
    /// GenesisProfile's (shared with DeployGenesisGovernance, DeployDormantLedgers and the gate).
    uint256 public constant REHEARSAL_GOV_MIN_DELAY = 1 hours;

    /// @notice The profile the last `deployWith` resolved; written into the book.
    ChainProfile public chainProfile;

    struct Deployed {
        address sbt;
        address bondImplementation;
        address vaultImplementation;
        address vault;
    }

    function run() external returns (Deployed memory d) {
        address deployer = deployerAddress();
        address governance = vm.envAddress("GOVERNANCE_TIMELOCK");
        address council = vm.envAddress("GOVERNANCE_MULTISIG");
        address grantor = vm.envAddress("MEMBERSHIP_GRANTOR");
        address registry = vm.envAddress("VALIDATOR_REGISTRY");
        vm.envString("GENESIS_MEMBERSHIP_OUT"); // resolve before broadcasting: a missing path fails first
        string memory govBook = vm.envOr("GENESIS_GOVERNANCE_BOOK", string(""));
        // Node chain id vs simulated chain id first (GenesisProfile), before the book's chainId.
        _resolveChainProfile(false);
        string memory govJson = bytes(govBook).length != 0 ? vm.readFile(govBook) : "";
        if (bytes(govJson).length != 0) checkGovernanceBook(govJson, governance);
        d = deployWith(deployer, governance, council, grantor, registry, govJson);
        _writeBook("GENESIS_MEMBERSHIP_OUT", bookJson(deployer, governance, council, grantor, registry, d));
    }

    /// @notice The ceremony with explicit inputs (no env reads), for tests and callers, with no
    ///         governance book: the timelock may then carry no CANCELLER but `council`.
    function deployWith(address deployer, address governance, address council, address grantor, address registry)
        public
        returns (Deployed memory d)
    {
        return deployWith(deployer, governance, council, grantor, registry, "");
    }

    /// @notice As above; `governanceBook` (DeployGenesisGovernance's book JSON, or "") supplies
    ///         the verified GuardianCanceller the timelock may carry as its only extra CANCELLER.
    function deployWith(
        address deployer,
        address governance,
        address council,
        address grantor,
        address registry,
        string memory governanceBook
    ) public returns (Deployed memory d) {
        // Node chain id vs simulated chain id, before anything else (GenesisProfile).
        ChainProfile memory cp = _resolveChainProfile(false);
        chainProfile = cp;
        address[] memory extraCancellers = _governanceExtraCancellers(governance, governanceBook);
        _assertInputs(deployer, governance, council, grantor, registry, cp.genesis, extraCancellers);

        console.log("=== Genesis membership (Track M) ===");
        console.log("Deployer           :", deployer);
        console.log("Governance timelock:", governance);
        console.log("Governance multisig:", council);
        console.log("Grantor            :", grantor);
        console.log("ValidatorRegistry  :", registry);

        bytes memory sbtInit = abi.encodePacked(type(CitrateMemberSBT).creationCode, abi.encode(grantor));
        bytes memory bondInit = type(MemberBond).creationCode;
        bytes memory implInit = type(MembershipStakeVault).creationCode;

        // Refuses to send anything unless the forge signer is the configured deployer.
        address broadcaster = _startBroadcastAsDeployer(deployer);

        d.sbt = _isLive(SBT, sbtInit)
            ? _create2Address(SBT, sbtInit)
            : address(new CitrateMemberSBT{salt: Salts.salt(SBT)}(grantor));
        d.bondImplementation = _isLive(BOND, bondInit)
            ? _create2Address(BOND, bondInit)
            : address(new MemberBond{salt: Salts.salt(BOND)}());
        d.vaultImplementation = _isLive(VAULT_IMPL, implInit)
            ? _create2Address(VAULT_IMPL, implInit)
            : address(new MembershipStakeVault{salt: Salts.salt(VAULT_IMPL)}());

        bytes memory initCall = abi.encodeCall(
            MembershipStakeVault.initialize,
            (deployer, ValidatorRegistry(payable(registry)), CitrateMemberSBT(d.sbt), d.bondImplementation)
        );
        bytes memory proxyInit =
            abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(d.vaultImplementation, initCall));
        d.vault = _isLive(VAULT, proxyInit)
            ? _create2Address(VAULT, proxyInit)
            : address(new ERC1967Proxy{salt: Salts.salt(VAULT)}(d.vaultImplementation, initCall));

        // Hand-over. A keep-live re-run finds it already done and sends nothing more.
        MembershipStakeVault vault = MembershipStakeVault(payable(d.vault));
        if (vault.governance() == address(0)) vault.initializeGovernance(governance);
        if (vault.owner() == deployer) vault.transferOwnership(grantor);
        vm.stopBroadcast();

        _assertHandedOver(d, deployer, broadcaster, governance, grantor, registry);
        address[] memory deployAccounts = new address[](2);
        (deployAccounts[0], deployAccounts[1]) = (deployer, broadcaster);
        _assertGovernanceCouncil(governance, council, deployAccounts, cp.genesis, extraCancellers);
        console.log("CitrateMemberSBT          :", d.sbt);
        console.log("MemberBond (impl)         :", d.bondImplementation);
        console.log("MembershipStakeVault impl :", d.vaultImplementation);
        console.log("MembershipStakeVault      :", d.vault);
    }

    function bookJson(
        address deployer,
        address governance,
        address council,
        address grantor,
        address registry,
        Deployed memory d
    ) public view returns (string memory) {
        string[] memory names = new string[](6);
        address[] memory addrs = new address[](6);
        (names[0], addrs[0]) = ("CitrateMemberSBT", d.sbt);
        (names[1], addrs[1]) = ("MemberBond", d.bondImplementation);
        (names[2], addrs[2]) = ("MembershipStakeVaultImpl", d.vaultImplementation);
        (names[3], addrs[3]) = ("MembershipStakeVault", d.vault);
        (names[4], addrs[4]) = ("GovernanceTimelock", governance);
        (names[5], addrs[5]) = ("GovernanceMultisig", council);
        string memory params = string.concat(
            '"governance":"',
            vm.toString(governance),
            '","grantor":"',
            vm.toString(grantor),
            '","validatorRegistry":"',
            vm.toString(registry),
            '","lockSeconds":',
            vm.toString(MemberBond(payable(d.bondImplementation)).LOCK_SECONDS()),
            ',"lockBlocks":',
            vm.toString(MemberBond(payable(d.bondImplementation)).LOCK_BLOCKS()),
            _profileParams()
        );
        return _bookJson(deployer, names, addrs, params);
    }

    function _profileParams() internal view returns (string memory) {
        ChainProfile memory p = chainProfile;
        return string.concat(
            ',"genesisProfile":',
            vm.toString(p.genesis),
            ',"nodeChainIdChecked":',
            vm.toString(p.nodeChecked),
            ',"nodeChainId":',
            vm.toString(p.nodeChainId),
            ',"overrides":{},"overrideUsed":false'
        );
    }

    /// @notice GENESIS_GOVERNANCE_BOOK must be for this chain and name GOVERNANCE_TIMELOCK.
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

    function _assertInputs(
        address deployer,
        address governance,
        address council,
        address grantor,
        address registry,
        bool genesis,
        address[] memory extraCancellers
    ) internal {
        require(deployer != address(0), "deployer must be set");
        require(governance != deployer, "GOVERNANCE_TIMELOCK cannot be the deployer");
        require(_isTimelock(governance), "GOVERNANCE_TIMELOCK is not a TimelockController");
        // Before broadcasting the only known deploy account is the configured deployer; the
        // broadcaster is added after `_startBroadcastAsDeployer` proves it (deployWith).
        address[] memory accounts = new address[](1);
        accounts[0] = deployer;
        _assertGovernanceCouncil(governance, council, accounts, genesis, extraCancellers);

        require(grantor != address(0), "MEMBERSHIP_GRANTOR must be set");
        require(grantor != deployer, "MEMBERSHIP_GRANTOR cannot be the deployer");
        require(grantor != governance, "MEMBERSHIP_GRANTOR cannot be the governance timelock");
        require(grantor != council, "MEMBERSHIP_GRANTOR cannot be the governance multisig");
        require(grantor != ARACHNID_FACTORY, "MEMBERSHIP_GRANTOR cannot be the CREATE2 factory");

        require(registry.code.length != 0, "VALIDATOR_REGISTRY has no code on this chain");
        uint256 grantPrincipal = 32_000 ether; // MembershipStakeVault.VALIDATOR_STAKE_REQUIREMENT
        require(
            ValidatorRegistry(payable(registry)).minStake() <= grantPrincipal,
            "VALIDATOR_REGISTRY minStake exceeds the 32,000 SALT grant: members could never activate"
        );
    }

    /// @notice Accounts other than the council that may hold CANCELLER_ROLE on
    ///         GOVERNANCE_TIMELOCK: the GuardianCanceller that governance book `json` lists
    ///         beside it, verified on chain (GenesisProfile `_bookGuardianCanceller`: CREATE2
    ///         address, runtime code, wiring, and the guardian council's own holder sets), or
    ///         none when no book is given. A listed canceller that does not verify reverts. One
    ///         list, shared by the pre-broadcast check and the postcondition.
    function _governanceExtraCancellers(address governance, string memory json)
        internal
        returns (address[] memory extra)
    {
        if (bytes(json).length == 0) return new address[](0);
        (string memory problem, address canceller) = _bookGuardianCanceller(json, governance);
        require(bytes(problem).length == 0, string.concat("GENESIS_GOVERNANCE_BOOK: ", problem));
        extra = new address[](1);
        extra[0] = canceller;
    }

    /// @notice Revert unless `governance` is a self-administered timelock run only by `council`
    ///         (the ceremony's MultisigProposer fronting it), at or above this profile's floors,
    ///         on which no address in `accounts` (the deploy accounts) holds an admin slot or
    ///         governing seat. `extraCancellers` may hold CANCELLER_ROLE besides the council.
    ///         Same checks, in the same order, as DeployDormantLedgers (chain#320).
    function _assertGovernanceCouncil(
        address governance,
        address council,
        address[] memory accounts,
        bool genesis,
        address[] memory extraCancellers
    ) internal {
        string memory tl = "GOVERNANCE_TIMELOCK";
        string memory ms = "GOVERNANCE_MULTISIG";
        require(council.code.length != 0, "GOVERNANCE_MULTISIG has no code on this chain");
        _assertTimelockSeats(tl, governance, council, accounts[0]);
        // Authenticate the council before trusting any of its getters: it must be the
        // MultisigProposer DeployGenesisGovernance deploys for this timelock (CREATE2 provenance).
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
            // GenesisProfile's floors (48 h, >= 3-of-5 majority, fixed 14-day proposal TTL),
            // shared with DeployGenesisGovernance, DeployDormantLedgers and CheckDeployedAdmins.
            _requireCouncilFloor("GOVERNANCE", governance, council, true);
        } else {
            require(
                _timelockMinDelay(governance) >= REHEARSAL_GOV_MIN_DELAY,
                "GOVERNANCE_TIMELOCK: minDelay below the 1 h rehearsal floor"
            );
        }
        // Complete holder sets: the timelock is its SOLE admin and the council its SOLE proposer
        // and executor (and canceller, besides `extraCancellers`), from the role history.
        _assertTimelockSoleHolders(tl, governance, council, extraCancellers);
    }

    function _assertHandedOver(
        Deployed memory d,
        address deployer,
        address broadcaster,
        address governance,
        address grantor,
        address registry
    ) internal view {
        MembershipStakeVault vault = MembershipStakeVault(payable(d.vault));
        CitrateMemberSBT sbt = CitrateMemberSBT(d.sbt);

        _assertOwner("MembershipStakeVault", d.vault, grantor);
        _assertGovernance("MembershipStakeVault", d.vault, governance);
        require(vault.pendingGovernance() == address(0), "MembershipStakeVault: a governance transfer is pending");
        // The treasury (unactivated principal returns there) is GOVERNANCE's to set, two-step; the
        // ceremony never sets it.
        require(
            vault.treasury() == address(0) && vault.pendingTreasury() == address(0),
            "MembershipStakeVault: treasury set outside governance"
        );
        require(address(vault.registry()) == registry, "MembershipStakeVault: registry mismatch");
        require(address(vault.sbt()) == d.sbt, "MembershipStakeVault: sbt mismatch");
        require(
            vault.bondImplementation() == d.bondImplementation, "MembershipStakeVault: bond implementation mismatch"
        );
        require(d.vault.balance == 0, "MembershipStakeVault: the vault must hold no SALT");
        _assertOwner("CitrateMemberSBT", d.sbt, grantor);
        require(sbt.owner() == grantor, "CitrateMemberSBT: owner is not the grantor");

        // Deploy accounts: the configured deployer and the actual broadcaster (no script-contract
        // address: it exists only in simulation). The factory has its own check.
        address[2] memory accounts = [deployer, broadcaster];
        string[4] memory names = ["MembershipStakeVault", "CitrateMemberSBT", "MemberBond", "MembershipStakeVault.impl"];
        address[4] memory targets = [d.vault, d.sbt, d.bondImplementation, d.vaultImplementation];
        for (uint256 t = 0; t < targets.length; t++) {
            _assertNoFactoryAdmin(names[t], targets[t]);
            for (uint256 a = 0; a < accounts.length; a++) {
                _assertNoDeployerAdmin(names[t], targets[t], accounts[a]);
            }
        }
    }

    function _isTimelock(address a) internal view returns (bool) {
        if (a.code.length == 0) return false;
        (bool ok, bytes memory ret) = a.staticcall(abi.encodeWithSignature("getMinDelay()"));
        return ok && ret.length == 32;
    }
}
