// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";
import "./Salts.sol";
import "./lib/AdminChecks.sol";
import "./lib/Create2Deploy.sol";
import "./lib/GenesisBook.sol";
import "./lib/GenesisProfile.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {MultisigProposer} from "../src/genesis/MultisigProposer.sol";

/// @title DeployGenesisGovernance: GOVERNANCE and GUARDIAN for the betanet genesis (C2 D5 / G3)
/// @notice For each council: an OZ v5.7.0 `TimelockController` (the delay) fronted by a
///         `MultisigProposer` (m-of-n, the only PROPOSER / EXECUTOR / CANCELLER).
///
///         Order, per council, inside one broadcast:
///           1. TimelockController{salt}(minDelay, [], [], admin = deployer)
///           2. MultisigProposer{salt}(timelock, owners, threshold)
///           3. deployer grants PROPOSER, EXECUTOR, CANCELLER to the multisig, then
///              renounces DEFAULT_ADMIN_ROLE. The timelock keeps DEFAULT_ADMIN_ROLE for
///              itself (OZ default), so later role changes are timelocked operations.
///         The deployer is admin only between steps 1 and 3 of the same ceremony run; the
///         post-run assertion (`_assertTimelockHandover`) fails the run unless it holds nothing.
///
///         Deterministic: CREATE2 through the Arachnid factory (Salts), keep-live on re-run
///         (`_isLive`). The timelock's address depends on (deployer, minDelay); the
///         multisig's on (timelock, owners, threshold). A re-run with the same inputs
///         reuses both and skips the already-done hand-over.
///
///         Every input is REQUIRED (vm.env* reverts when unset); nothing defaults:
///           GOV_OWNERS=0xA,0xB,…   GOV_THRESHOLD=3   GOV_MIN_DELAY=172800
///           GRD_OWNERS=0xC,0xD,…   GRD_THRESHOLD=2   GRD_MIN_DELAY=3600
///           GENESIS_GOVERNANCE_OUT=genesis/governance.json   (book-shaped output)
///           CEREMONY_DEPLOYER_ADDRESS or DEPLOYER_ADDRESS     (must be the forge signer; enforced:
///                                                              the run reverts before deploying
///                                                              anything if the broadcaster differs)
///         Optional: ALLOW_SHARED_HOLDERS=1 lets one address sit on both councils (C2 D5
///         requires the owner's written approval for that; off unless set).
///
///         Checks before broadcasting: 1 <= m <= n <= 10, owners distinct and nonzero (the
///         contract re-checks), minDelay >= 1 hour, the deployer is no owner, and the two
///         councils share no owner (unless ALLOW_SHARED_HOLDERS=1).
///
///         Chain id (GenesisProfile): the node's eth_chainId must equal forge's simulated
///         chain id, or the run reverts before broadcasting; on 40204 a node is required.
///
///         Genesis floors (chain 40204 as the node reports it): GOVERNANCE m >= 3 of n >= 5 and
///         minDelay >= 48 h, refused before broadcasting (`_requireGenesisGovernance`) and
///         re-read from chain after it (`_requireCouncilFloor`, the same check the
///         CheckDeployedAdmins GENESIS-FLOOR class applies). Rehearsal chains keep the minimums above.
///
///         Dry run:  forge script script/DeployGenesisGovernance.s.sol --rpc-url <rpc>
///         Then:     ADDRESS_BOOK=genesis/governance.json forge script script/CheckDeployedAdmins.s.sol --rpc-url <rpc>
contract DeployGenesisGovernance is ScriptEnv, AdminChecks, Create2Deploy, GenesisBook, GenesisProfile {
    /// Same floor as MultisigTimelock2of3.MIN_DELAY_FLOOR (C044(a)); D5 uses it for GUARDIAN.
    uint256 public constant MIN_DELAY_FLOOR = 1 hours;

    string internal constant GOV_TIMELOCK = "Genesis.GovernanceTimelock";
    string internal constant GOV_MULTISIG = "Genesis.GovernanceMultisig";
    string internal constant GRD_TIMELOCK = "Genesis.GuardianTimelock";
    string internal constant GRD_MULTISIG = "Genesis.GuardianMultisig";

    struct Council {
        address[] owners;
        uint256 threshold;
        uint256 minDelay;
    }

    struct Deployed {
        address governanceTimelock;
        address governanceMultisig;
        address guardianTimelock;
        address guardianMultisig;
    }

    function run() external returns (Deployed memory d) {
        address deployer = deployerAddress();
        Council memory gov = _councilFromEnv("GOV");
        Council memory grd = _councilFromEnv("GRD");
        bool allowShared = envUintOr("ALLOW_SHARED_HOLDERS", 0) == 1;
        // Resolve the output path before broadcasting, so a missing one fails first.
        vm.envString("GENESIS_GOVERNANCE_OUT");
        d = deployWith(deployer, gov, grd, allowShared);
        _writeBook("GENESIS_GOVERNANCE_OUT", bookJson(deployer, d, gov, grd));
    }

    /// @notice The ceremony with explicit inputs (no env reads), for tests and callers.
    function deployWith(address deployer, Council memory gov, Council memory grd, bool allowShared)
        public
        returns (Deployed memory d)
    {
        require(deployer != address(0), "deployer must be set");
        // Node chain id vs simulated chain id, before anything else (GenesisProfile): the book
        // records block.chainid, so a --chain-id / --chain / FOUNDRY_CHAIN_ID override is refused.
        bool genesis = _resolveChainProfile(false).genesis;
        _validate("GOVERNANCE", gov, deployer);
        _validate("GUARDIAN", grd, deployer);
        if (genesis) _requireGenesisGovernance(gov);
        if (!allowShared) {
            for (uint256 i = 0; i < gov.owners.length; i++) {
                for (uint256 j = 0; j < grd.owners.length; j++) {
                    require(gov.owners[i] != grd.owners[j], "owner sits on both GOVERNANCE and GUARDIAN");
                }
            }
        }

        console.log("=== Genesis governance (C2 D5) ===");
        console.log("Deployer:", deployer);
        console.log("Chain ID:", block.chainid);

        // Refuses to deploy anything unless the forge signer is the configured deployer.
        address broadcaster = _startBroadcastAsDeployer(deployer);
        _requireNotOwner("GOVERNANCE", gov, broadcaster);
        _requireNotOwner("GUARDIAN", grd, broadcaster);
        (d.governanceTimelock, d.governanceMultisig) = _deployCouncil(GOV_TIMELOCK, GOV_MULTISIG, gov, deployer);
        (d.guardianTimelock, d.guardianMultisig) = _deployCouncil(GRD_TIMELOCK, GRD_MULTISIG, grd, deployer);
        vm.stopBroadcast();

        _assertCouncil("GOVERNANCE", d.governanceTimelock, d.governanceMultisig, gov, deployer);
        _assertCouncil("GUARDIAN", d.guardianTimelock, d.guardianMultisig, grd, deployer);
        if (genesis) {
            // The same on-chain floors CheckDeployedAdmins applies on 40204 (GENESIS-FLOOR).
            _requireCouncilFloor("GOVERNANCE", d.governanceTimelock, d.governanceMultisig, true);
            _requireCouncilFloor("GUARDIAN", d.guardianTimelock, d.guardianMultisig, false);
        }
        _assertNoDeployerAdmin("GOVERNANCE", d.governanceTimelock, broadcaster);
        _assertNoDeployerAdmin("GOVERNANCE", d.governanceMultisig, broadcaster);
        _assertNoDeployerAdmin("GUARDIAN", d.guardianTimelock, broadcaster);
        _assertNoDeployerAdmin("GUARDIAN", d.guardianMultisig, broadcaster);

        console.log("GovernanceTimelock :", d.governanceTimelock);
        console.log("GovernanceMultisig :", d.governanceMultisig);
        console.log("GuardianTimelock   :", d.guardianTimelock);
        console.log("GuardianMultisig   :", d.guardianMultisig);
    }

    function bookJson(address deployer, Deployed memory d, Council memory gov, Council memory grd)
        public
        view
        returns (string memory)
    {
        string[] memory names = new string[](4);
        address[] memory addrs = new address[](4);
        (names[0], addrs[0]) = ("GovernanceTimelock", d.governanceTimelock);
        (names[1], addrs[1]) = ("GovernanceMultisig", d.governanceMultisig);
        (names[2], addrs[2]) = ("GuardianTimelock", d.guardianTimelock);
        (names[3], addrs[3]) = ("GuardianMultisig", d.guardianMultisig);
        string memory params = string.concat(
            '"governance":{"threshold":',
            vm.toString(gov.threshold),
            ',"owners":',
            vm.toString(gov.owners.length),
            ',"minDelay":',
            vm.toString(gov.minDelay),
            '},"guardian":{"threshold":',
            vm.toString(grd.threshold),
            ',"owners":',
            vm.toString(grd.owners.length),
            ',"minDelay":',
            vm.toString(grd.minDelay),
            "}"
        );
        return _bookJson(deployer, names, addrs, params);
    }

    function _councilFromEnv(string memory prefix) internal view returns (Council memory c) {
        c.owners = vm.envAddress(string.concat(prefix, "_OWNERS"), ",");
        c.threshold = vm.envUint(string.concat(prefix, "_THRESHOLD"));
        c.minDelay = vm.envUint(string.concat(prefix, "_MIN_DELAY"));
    }

    function _validate(string memory name, Council memory c, address deployer) internal pure {
        uint256 n = c.owners.length;
        require(n >= 1 && n <= 10, string.concat(name, ": owner count must be 1..10"));
        require(c.threshold >= 1 && c.threshold <= n, string.concat(name, ": threshold must be 1..owners"));
        require(c.minDelay >= MIN_DELAY_FLOOR, string.concat(name, ": minDelay below the 1 hour floor"));
        for (uint256 i = 0; i < n; i++) {
            require(c.owners[i] != address(0), string.concat(name, ": zero owner"));
            require(c.owners[i] != deployer, string.concat(name, ": the deployer cannot be an owner"));
            for (uint256 j = i + 1; j < n; j++) {
                require(c.owners[i] != c.owners[j], string.concat(name, ": duplicate owner"));
            }
        }
    }

    /// @notice Genesis profile (chain 40204 as the node reports it): GOVERNANCE must meet the
    ///         genesis floors before anything is broadcast: m >= 3 of n >= 5, minDelay >= 48 h.
    ///         GUARDIAN keeps the 1 h floor `_validate` applies on every profile.
    function _requireGenesisGovernance(Council memory gov) internal pure {
        require(
            gov.threshold >= GENESIS_GOV_MIN_THRESHOLD && gov.owners.length >= GENESIS_GOV_MIN_OWNERS,
            "GOVERNANCE: multisig below the 3-of-5 genesis floor"
        );
        require(gov.minDelay >= GENESIS_GOV_MIN_DELAY, "GOVERNANCE: minDelay below the 48 h genesis floor");
    }

    function _requireNotOwner(string memory name, Council memory c, address broadcaster) internal pure {
        for (uint256 i = 0; i < c.owners.length; i++) {
            require(c.owners[i] != broadcaster, string.concat(name, ": the broadcaster cannot be an owner"));
        }
    }

    function _deployCouncil(string memory tlName, string memory msName, Council memory c, address deployer)
        internal
        returns (address tl, address ms)
    {
        address[] memory none = new address[](0);
        bytes memory tlInit =
            abi.encodePacked(type(TimelockController).creationCode, abi.encode(c.minDelay, none, none, deployer));
        TimelockController timelock = _isLive(tlName, tlInit)
            ? TimelockController(payable(_create2Address(tlName, tlInit)))
            : new TimelockController{salt: Salts.salt(tlName)}(c.minDelay, none, none, deployer);

        bytes memory msInit =
            abi.encodePacked(type(MultisigProposer).creationCode, abi.encode(address(timelock), c.owners, c.threshold));
        MultisigProposer multisig = _isLive(msName, msInit)
            ? MultisigProposer(_create2Address(msName, msInit))
            : new MultisigProposer{salt: Salts.salt(msName)}(address(timelock), c.owners, c.threshold);

        // Hand-over, only while the deployer still administers the timelock. On a re-run
        // after hand-over this is skipped and `_assertCouncil` re-proves the end state.
        if (timelock.hasRole(timelock.DEFAULT_ADMIN_ROLE(), deployer)) {
            timelock.grantRole(timelock.PROPOSER_ROLE(), address(multisig));
            timelock.grantRole(timelock.EXECUTOR_ROLE(), address(multisig));
            timelock.grantRole(timelock.CANCELLER_ROLE(), address(multisig));
            timelock.renounceRole(timelock.DEFAULT_ADMIN_ROLE(), deployer);
        }
        return (address(timelock), address(multisig));
    }

    function _assertCouncil(string memory name, address tl, address ms, Council memory c, address deployer)
        internal
        view
    {
        _assertTimelockHandover(name, tl, ms, deployer, c.minDelay);
        _assertNoFactoryAdmin(name, ms);
        _assertNoDeployerAdmin(name, ms, deployer);
        MultisigProposer m = MultisigProposer(ms);
        require(m.timelock() == tl, string.concat(name, ": multisig fronts another timelock"));
        require(m.threshold() == c.threshold, string.concat(name, ": multisig threshold mismatch"));
        address[] memory o = m.owners();
        require(o.length == c.owners.length, string.concat(name, ": multisig owner count mismatch"));
        for (uint256 i = 0; i < o.length; i++) {
            require(o[i] == c.owners[i], string.concat(name, ": multisig owner mismatch"));
        }
    }
}
