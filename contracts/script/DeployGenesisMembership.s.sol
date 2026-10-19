// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "./ScriptEnv.sol";
import "./Salts.sol";
import "./lib/AdminChecks.sol";
import "./lib/Create2Deploy.sol";
import "./lib/GenesisBook.sol";
import {CitrateMemberSBT} from "../src/core_membership/CitrateMemberSBT.sol";
import {MemberBond} from "../src/core_membership/MemberBond.sol";
import {MembershipStakeVault} from "../src/core_membership/MembershipStakeVault.sol";
import {ValidatorRegistry} from "../src/ValidatorRegistry.sol";

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
///             execution not open to everyone, on which neither the configured deployer nor
///             this script holds an admin slot or governing seat. Floors: chain 40204 (the
///             genesis profile, selected by chain id, no override) needs minDelay >= 48 h;
///             any other chain (rehearsal) >= 1 h.
///           - GRANTOR is nonzero and is not the deployer, the governance timelock or the
///             CREATE2 factory.
///           - VALIDATOR_REGISTRY has code and its `minStake()` is at most the 32,000 SALT a
///             grant carries, otherwise no granted member could ever activate.
///           - the forge broadcaster is the configured deployer.
///         Postconditions on the live contracts: vault owner == GRANTOR, vault governance ==
///         GOVERNANCE_TIMELOCK, no pending governance, SBT owner == GRANTOR, the vault holds
///         no SALT, and neither the deployer, the broadcaster, this script nor the CREATE2
///         factory holds any admin slot on the SBT or the vault.
///
///         Required env: GOVERNANCE_TIMELOCK, MEMBERSHIP_GRANTOR (the treasury-signer address
///         that places grants), VALIDATOR_REGISTRY, GENESIS_MEMBERSHIP_OUT, and
///         CEREMONY_DEPLOYER_ADDRESS or DEPLOYER_ADDRESS (must equal the forge broadcast
///         signer; enforced). Output: a book-shaped JSON at GENESIS_MEMBERSHIP_OUT, which
///         `CheckDeployedAdmins` reads through EXTRA_ADDRESS_BOOKS. Nothing touches
///         `addresses/40204.json`.
///
///         NOTE: chain 40204 rejects EIP-1559 transactions; broadcast with `--legacy` and an
///         explicit gas limit.
contract DeployGenesisMembership is ScriptEnv, AdminChecks, Create2Deploy, GenesisBook {
    string internal constant SBT = "CitrateMemberSBT";
    string internal constant BOND = "MemberBond";
    string internal constant VAULT_IMPL = "MembershipStakeVault.impl";
    string internal constant VAULT = "MembershipStakeVault";

    uint256 public constant GENESIS_CHAIN_ID = 40204;
    /// Genesis profile: GOVERNANCE runs behind a 48 h delay (C2 D5, owner decision 2026-10-19).
    uint256 public constant GENESIS_GOV_MIN_DELAY = 48 hours;
    /// Rehearsal chains: DeployGenesisGovernance.MIN_DELAY_FLOOR.
    uint256 public constant REHEARSAL_GOV_MIN_DELAY = 1 hours;

    struct Deployed {
        address sbt;
        address bondImplementation;
        address vaultImplementation;
        address vault;
    }

    function run() external returns (Deployed memory d) {
        address deployer = deployerAddress();
        address governance = vm.envAddress("GOVERNANCE_TIMELOCK");
        address grantor = vm.envAddress("MEMBERSHIP_GRANTOR");
        address registry = vm.envAddress("VALIDATOR_REGISTRY");
        vm.envString("GENESIS_MEMBERSHIP_OUT"); // resolve before broadcasting: a missing path fails first
        d = deployWith(deployer, governance, grantor, registry);
        _writeBook("GENESIS_MEMBERSHIP_OUT", bookJson(deployer, governance, grantor, registry, d));
    }

    /// @notice The ceremony with explicit inputs (no env reads), for tests and callers.
    function deployWith(address deployer, address governance, address grantor, address registry)
        public
        returns (Deployed memory d)
    {
        _assertInputs(deployer, governance, grantor, registry);

        console.log("=== Genesis membership (Track M) ===");
        console.log("Deployer           :", deployer);
        console.log("Governance timelock:", governance);
        console.log("Grantor            :", grantor);
        console.log("ValidatorRegistry  :", registry);

        bytes memory sbtInit = abi.encodePacked(type(CitrateMemberSBT).creationCode, abi.encode(grantor));
        bytes memory bondInit = type(MemberBond).creationCode;
        bytes memory implInit = type(MembershipStakeVault).creationCode;

        // Refuses to send anything unless the forge signer is the configured deployer.
        address broadcaster = _startBroadcastAsDeployer(deployer);

        d.sbt = _isLive(SBT, sbtInit) ? _create2Address(SBT, sbtInit) : address(new CitrateMemberSBT{salt: Salts.salt(SBT)}(grantor));
        d.bondImplementation =
            _isLive(BOND, bondInit) ? _create2Address(BOND, bondInit) : address(new MemberBond{salt: Salts.salt(BOND)}());
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
        console.log("CitrateMemberSBT          :", d.sbt);
        console.log("MemberBond (impl)         :", d.bondImplementation);
        console.log("MembershipStakeVault impl :", d.vaultImplementation);
        console.log("MembershipStakeVault      :", d.vault);
    }

    function bookJson(address deployer, address governance, address grantor, address registry, Deployed memory d)
        public
        view
        returns (string memory)
    {
        string[] memory names = new string[](5);
        address[] memory addrs = new address[](5);
        (names[0], addrs[0]) = ("CitrateMemberSBT", d.sbt);
        (names[1], addrs[1]) = ("MemberBond", d.bondImplementation);
        (names[2], addrs[2]) = ("MembershipStakeVaultImpl", d.vaultImplementation);
        (names[3], addrs[3]) = ("MembershipStakeVault", d.vault);
        (names[4], addrs[4]) = ("GovernanceTimelock", governance);
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
            vm.toString(MemberBond(payable(d.bondImplementation)).LOCK_BLOCKS())
        );
        return _bookJson(deployer, names, addrs, params);
    }

    function _assertInputs(address deployer, address governance, address grantor, address registry)
        internal
        view
    {
        require(deployer != address(0), "deployer must be set");
        require(governance != deployer, "GOVERNANCE_TIMELOCK cannot be the deployer");
        require(_isTimelock(governance), "GOVERNANCE_TIMELOCK is not a TimelockController");
        _assertTimelockShape(governance, deployer);
        uint256 delay = _timelockMinDelay(governance);
        bool genesis = block.chainid == GENESIS_CHAIN_ID;
        require(
            delay >= (genesis ? GENESIS_GOV_MIN_DELAY : REHEARSAL_GOV_MIN_DELAY),
            genesis
                ? "GOVERNANCE_TIMELOCK: minDelay below the 48 h genesis floor"
                : "GOVERNANCE_TIMELOCK: minDelay below the 1 h rehearsal floor"
        );

        require(grantor != address(0), "MEMBERSHIP_GRANTOR must be set");
        require(grantor != deployer, "MEMBERSHIP_GRANTOR cannot be the deployer");
        require(grantor != governance, "MEMBERSHIP_GRANTOR cannot be the governance timelock");
        require(grantor != ARACHNID_FACTORY, "MEMBERSHIP_GRANTOR cannot be the CREATE2 factory");

        require(registry.code.length != 0, "VALIDATOR_REGISTRY has no code on this chain");
        uint256 grantPrincipal = 32_000 ether; // MembershipStakeVault.VALIDATOR_STAKE_REQUIREMENT
        require(
            ValidatorRegistry(payable(registry)).minStake() <= grantPrincipal,
            "VALIDATOR_REGISTRY minStake exceeds the 32,000 SALT grant: members could never activate"
        );
    }

    /// @notice The timelock administers itself, execution is not open to everyone, and neither
    ///         the deployer nor this script holds an admin slot or governing seat on it.
    function _assertTimelockShape(address governance, address deployer) internal view {
        string memory tl = "GOVERNANCE_TIMELOCK";
        _assertNoFactoryAdmin(tl, governance);
        _assertNoDeployerAdmin(tl, governance, deployer);
        _assertNoDeployerAdmin(tl, governance, address(this));
        (bool okOpen, bool open) = _readBool(
            governance, abi.encodeWithSignature("hasRole(bytes32,address)", TIMELOCK_EXECUTOR_ROLE, address(0))
        );
        require(okOpen && !open, "GOVERNANCE_TIMELOCK: execution is open to anyone");
        (bool okSelf, bool self) =
            _readBool(governance, abi.encodeWithSignature("hasRole(bytes32,address)", DEFAULT_ADMIN_ROLE, governance));
        require(okSelf && self, "GOVERNANCE_TIMELOCK: timelock does not administer itself");
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
        require(address(vault.registry()) == registry, "MembershipStakeVault: registry mismatch");
        require(address(vault.sbt()) == d.sbt, "MembershipStakeVault: sbt mismatch");
        require(vault.bondImplementation() == d.bondImplementation, "MembershipStakeVault: bond implementation mismatch");
        require(d.vault.balance == 0, "MembershipStakeVault: the vault must hold no SALT");
        _assertOwner("CitrateMemberSBT", d.sbt, grantor);
        require(sbt.owner() == grantor, "CitrateMemberSBT: owner is not the grantor");

        address[4] memory accounts = [deployer, broadcaster, address(this), ARACHNID_FACTORY];
        string[4] memory names = ["MembershipStakeVault", "CitrateMemberSBT", "MemberBond", "MembershipStakeVault.impl"];
        address[4] memory targets = [d.vault, d.sbt, d.bondImplementation, d.vaultImplementation];
        for (uint256 t = 0; t < targets.length; t++) {
            _assertNoFactoryAdmin(names[t], targets[t]);
            for (uint256 a = 0; a < 3; a++) {
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
