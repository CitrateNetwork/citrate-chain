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
import {GuardianCanceller} from "../src/genesis/GuardianCanceller.sol";

/// @title DeployGenesisGovernance: GOVERNANCE and GUARDIAN for the betanet genesis (C2 D5 / G3)
/// @notice For each council: an OZ v5.7.0 `TimelockController` (the delay) fronted by a
///         `MultisigProposer` (m-of-n, the only PROPOSER / EXECUTOR / CANCELLER).
///
///         Order, inside one broadcast:
///           1. per council: TimelockController{salt}(minDelay, [], [], admin = deployer)
///           2. per council: MultisigProposer{salt}(timelock, owners, threshold, proposalTtl)
///           3. GuardianCanceller{salt}(GOVERNANCE timelock, guardian = GUARDIAN timelock)
///           4. GOVERNANCE timelock: deployer grants PROPOSER, EXECUTOR, CANCELLER to the
///              GOVERNANCE multisig and CANCELLER (only) to the GuardianCanceller, then
///              renounces DEFAULT_ADMIN_ROLE.
///           5. GUARDIAN timelock: deployer grants PROPOSER, EXECUTOR, CANCELLER to the
///              GUARDIAN multisig, then renounces DEFAULT_ADMIN_ROLE.
///         Each timelock keeps DEFAULT_ADMIN_ROLE for itself (OZ default), so later role
///         changes are timelocked operations. The deployer is admin only between steps 1 and
///         5 of the same ceremony run; the post-run assertions (`_assertTimelockHandover`,
///         `_assertGuardianVeto`) fail the run unless it holds nothing.
///
///         Guardian veto (owner decision 2026-10-19, fed#331): the GUARDIAN council can cancel
///         a queued GOVERNANCE operation, except one that only removes or replaces the guardian
///         itself, so governance can always retire a compromised guardian after its delay. The
///         CANCELLER seat is held by `GuardianCanceller`, which enforces that exception: GUARDIAN
///         m-of-n schedules `GuardianCanceller.cancel(preimage)` (or `cancelBatch`) on its own
///         timelock, waits its (shorter) delay and executes. Neither the GUARDIAN timelock nor
///         its multisig holds any seat on GOVERNANCE, so the guardian can veto but never act.
///
///         Runbook (retiring or replacing the guardian): schedule the GOVERNANCE operation in
///         the canonical form only, every call with value 0 and nothing else in the batch:
///         `revokeRole(CANCELLER_ROLE, GuardianCanceller)` and / or
///         `GuardianCanceller.setGuardian(successor)` (successor != the current guardian),
///         optionally with `grantRole(CANCELLER_ROLE, successor canceller)`. A call with a
///         nonzero value, any other call in the batch, `setGuardian(current guardian)`, or a
///         re-grant of CANCELLER to the GuardianCanceller makes the operation an ordinary one
///         that the guardian can cancel (GuardianCanceller `_classify`).
///
///         Deterministic: CREATE2 through the Arachnid factory (Salts), keep-live on re-run
///         (`_isLive`). The timelock's address depends on (deployer, minDelay); the
///         multisig's on (timelock, owners, threshold). A re-run with the same inputs
///         reuses both and skips the already-done hand-over.
///
///         Required inputs (vm.env* reverts when unset):
///           GOV_OWNERS=0xA,0xB,…   GOV_THRESHOLD=3   GOV_MIN_DELAY=172800
///           GRD_OWNERS=0xC,0xD,…   GRD_THRESHOLD=2   GRD_MIN_DELAY=3600
///           GENESIS_GOVERNANCE_OUT=genesis/governance.json   (book-shaped output)
///           CEREMONY_DEPLOYER_ADDRESS or DEPLOYER_ADDRESS     (must be the forge signer; enforced:
///                                                              the run reverts before deploying
///                                                              anything if the broadcaster differs)
///         Optional: GOV_PROPOSAL_TTL / GRD_PROPOSAL_TTL, seconds a multisig proposal stays
///         open; default 14 days (1209600) when unset. Genesis profile: FIXED at 1209600, any
///         other value is refused (owner decision 2026-10-19). Rehearsal: 1..30 days.
///         Optional: ALLOW_SHARED_HOLDERS=1 lets one address sit on both councils off the
///         genesis profile (rehearsals only); off unless set, values other than 0 / 1
///         rejected, refused on the genesis profile.
///         Optional: GENESIS_PROFILE=1 applies the genesis profile on any chain id; chain 40204
///         is always the genesis profile. Values other than 0 / 1 are rejected.
///         Optional: ALLOW_WEAK_GOVERNANCE=1 waives the production-strength checks below, for
///         rehearsal / devnet chains only; off unless set, values other than 0 / 1 rejected.
///         On the genesis profile the override is refused: the run reverts when it is set.
///
///         Chain id (GenesisProfile): before broadcasting, the run reads the node's chain id
///         (`eth_chainId`) and refuses any mismatch with forge's simulated id, so
///         `--chain-id` / `--chain` / `FOUNDRY_CHAIN_ID` cannot steer a 40204 deploy off the
///         genesis profile. Without a node (no --rpc-url) the genesis profile fails closed.
///         The book records the profile, the node id and whether any override was used.
///
///         Checks before broadcasting: 1 <= m <= n <= 10, owners distinct and nonzero (the
///         contract re-checks), minDelay >= 1 hour, proposalTtl within the multisig's bounds,
///         the deployer is no owner, and the two councils share no owner (unless
///         ALLOW_SHARED_HOLDERS=1). Production strength (owner decision 2026-10-19; waivable
///         only off the genesis profile with ALLOW_WEAK_GOVERNANCE=1): GOVERNANCE m >= 3,
///         n >= 5, m > n/2, minDelay >= 48 hours; GUARDIAN m >= 2, n >= 3, m > n/2; and the
///         GUARDIAN delay shorter than the GOVERNANCE delay, so a veto can land in time.
///
///         Dry run:  forge script script/DeployGenesisGovernance.s.sol --rpc-url <rpc>
///         Then:     ADDRESS_BOOK=genesis/governance.json forge script script/CheckDeployedAdmins.s.sol --rpc-url <rpc>
contract DeployGenesisGovernance is ScriptEnv, AdminChecks, Create2Deploy, GenesisBook, GenesisProfile {
    /// Same floor as MultisigTimelock2of3.MIN_DELAY_FLOOR (C044(a)); D5 uses it for GUARDIAN.
    uint256 public constant MIN_DELAY_FLOOR = 1 hours;
    /// Proposal expiry when GOV_PROPOSAL_TTL / GRD_PROPOSAL_TTL is unset (the genesis value).
    uint256 public constant DEFAULT_PROPOSAL_TTL = GENESIS_PROPOSAL_TTL;

    string internal constant OVERRIDE_REFUSED =
        "ALLOW_WEAK_GOVERNANCE is refused on the genesis profile (chain 40204 or GENESIS_PROFILE=1)";
    string internal constant SHARED_REFUSED =
        "ALLOW_SHARED_HOLDERS is refused on the genesis profile (chain 40204 or GENESIS_PROFILE=1)";

    string internal constant GOV_TIMELOCK = "Genesis.GovernanceTimelock";
    string internal constant GOV_MULTISIG = "Genesis.GovernanceMultisig";
    string internal constant GRD_TIMELOCK = "Genesis.GuardianTimelock";
    string internal constant GRD_MULTISIG = "Genesis.GuardianMultisig";
    string internal constant GRD_CANCELLER = GUARDIAN_CANCELLER_SALT;

    struct Council {
        address[] owners;
        uint256 threshold;
        uint256 minDelay;
        uint256 proposalTtl;
    }

    struct Deployed {
        address governanceTimelock;
        address governanceMultisig;
        address guardianTimelock;
        address guardianMultisig;
        address guardianCanceller;
    }

    /// @notice How the last `deployWith` ran; written into the book by `bookJson`.
    struct RunProfile {
        bool genesis;
        bool nodeChecked;
        uint256 nodeChainId;
        bool allowWeak;
        bool allowShared;
    }

    RunProfile public runProfile;

    function run() external returns (Deployed memory d) {
        address deployer = deployerAddress();
        Council memory gov = _councilFromEnv("GOV");
        Council memory grd = _councilFromEnv("GRD");
        bool allowShared = _envFlag("ALLOW_SHARED_HOLDERS");
        bool allowWeak = _envFlag("ALLOW_WEAK_GOVERNANCE");
        bool genesisProfile = _envFlag("GENESIS_PROFILE");
        // Resolve the output path before broadcasting, so a missing one fails first.
        vm.envString("GENESIS_GOVERNANCE_OUT");
        d = deployWith(deployer, gov, grd, allowShared, allowWeak, genesisProfile);
        _writeBook("GENESIS_GOVERNANCE_OUT", bookJson(deployer, d, gov, grd));
    }

    /// @notice The ceremony with explicit inputs (no env reads), for tests and callers. The
    ///         genesis profile still applies when block.chainid is GENESIS_CHAIN_ID.
    function deployWith(address deployer, Council memory gov, Council memory grd, bool allowShared, bool allowWeak)
        public
        returns (Deployed memory d)
    {
        return deployWith(deployer, gov, grd, allowShared, allowWeak, false);
    }

    /// @notice As above; `genesisProfile` forces the genesis profile on any chain id.
    function deployWith(
        address deployer,
        Council memory gov,
        Council memory grd,
        bool allowShared,
        bool allowWeak,
        bool genesisProfile
    ) public returns (Deployed memory d) {
        require(deployer != address(0), "deployer must be set");
        // Node chain id vs simulated chain id, before anything else (GenesisProfile).
        ChainProfile memory cp = _resolveChainProfile(genesisProfile);
        bool genesis = cp.genesis;
        require(!(genesis && allowWeak), OVERRIDE_REFUSED);
        require(!(genesis && allowShared), SHARED_REFUSED);
        _validate("GOVERNANCE", gov, deployer);
        _validate("GUARDIAN", grd, deployer);
        if (genesis) {
            _requireGenesisTtl("GOVERNANCE", gov);
            _requireGenesisTtl("GUARDIAN", grd);
        }
        if (allowWeak) {
            console.log("WARNING: ALLOW_WEAK_GOVERNANCE=1, production-strength checks waived (rehearsal/devnet only)");
        } else {
            _requireProductionStrength(gov, grd);
        }
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
        console.log("Genesis profile:", genesis);
        console.log("Node chain id checked:", cp.nodeChecked);
        runProfile = RunProfile({
            genesis: genesis,
            nodeChecked: cp.nodeChecked,
            nodeChainId: cp.nodeChainId,
            allowWeak: allowWeak,
            allowShared: allowShared
        });

        // Refuses to deploy anything unless the forge signer is the configured deployer.
        address broadcaster = _startBroadcastAsDeployer(deployer);
        _requireNotOwner("GOVERNANCE", gov, broadcaster);
        _requireNotOwner("GUARDIAN", grd, broadcaster);
        (d.governanceTimelock, d.governanceMultisig) = _deployCouncil(GOV_TIMELOCK, GOV_MULTISIG, gov, deployer);
        (d.guardianTimelock, d.guardianMultisig) = _deployCouncil(GRD_TIMELOCK, GRD_MULTISIG, grd, deployer);
        d.guardianCanceller = _deployCanceller(d.governanceTimelock, d.guardianTimelock);
        _handOver(d.governanceTimelock, d.governanceMultisig, deployer, d.guardianCanceller);
        _handOver(d.guardianTimelock, d.guardianMultisig, deployer, address(0));
        vm.stopBroadcast();

        _assertCouncil("GOVERNANCE", d.governanceTimelock, d.governanceMultisig, gov, deployer);
        _assertCouncil("GUARDIAN", d.guardianTimelock, d.guardianMultisig, grd, deployer);
        _assertGuardianVeto(d);
        if (genesis) {
            // The same on-chain floors CheckDeployedAdmins applies on 40204.
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
        console.log("GuardianCanceller  :", d.guardianCanceller);
    }

    function bookJson(address deployer, Deployed memory d, Council memory gov, Council memory grd)
        public
        view
        returns (string memory)
    {
        string[] memory names = new string[](5);
        address[] memory addrs = new address[](5);
        (names[0], addrs[0]) = ("GovernanceTimelock", d.governanceTimelock);
        (names[1], addrs[1]) = ("GovernanceMultisig", d.governanceMultisig);
        (names[2], addrs[2]) = ("GuardianTimelock", d.guardianTimelock);
        (names[3], addrs[3]) = ("GuardianMultisig", d.guardianMultisig);
        (names[4], addrs[4]) = ("GuardianCanceller", d.guardianCanceller);
        string memory params = string.concat(
            '"governance":{"threshold":',
            vm.toString(gov.threshold),
            ',"owners":',
            vm.toString(gov.owners.length),
            ',"minDelay":',
            vm.toString(gov.minDelay),
            ',"proposalTtl":',
            vm.toString(gov.proposalTtl),
            '},"guardian":{"threshold":',
            vm.toString(grd.threshold),
            ',"owners":',
            vm.toString(grd.owners.length),
            ',"minDelay":',
            vm.toString(grd.minDelay),
            ',"proposalTtl":',
            vm.toString(grd.proposalTtl),
            '},"guardianCancelsGovernance":true,"guardianRemovalExemptFromVeto":true,',
            _profileJson()
        );
        return _bookJson(deployer, names, addrs, params);
    }

    /// @notice True on GENESIS_CHAIN_ID, or when the caller forces the profile. By the simulated
    ///         chain id only; `deployWith` also requires the node to report the same id.
    function isGenesisProfile(bool forced) public view returns (bool) {
        return forced || block.chainid == GENESIS_CHAIN_ID;
    }

    /// @notice `"genesisProfile":…,"nodeChainIdChecked":…,"nodeChainId":…,"overrides":{…},"overrideUsed":…`
    function _profileJson() internal view returns (string memory) {
        RunProfile memory p = runProfile;
        return string.concat(
            '"genesisProfile":',
            vm.toString(p.genesis),
            ',"nodeChainIdChecked":',
            vm.toString(p.nodeChecked),
            ',"nodeChainId":',
            vm.toString(p.nodeChainId),
            ',"overrides":{"allowWeakGovernance":',
            vm.toString(p.allowWeak),
            ',"allowSharedHolders":',
            vm.toString(p.allowShared),
            '},"overrideUsed":',
            vm.toString(p.allowWeak || p.allowShared)
        );
    }

    /// @notice Genesis profile: the proposal TTL is fixed at 14 days (owner decision 2026-10-19).
    function _requireGenesisTtl(string memory name, Council memory c) internal pure {
        require(
            c.proposalTtl == GENESIS_PROPOSAL_TTL,
            string.concat(name, ": proposalTtl is fixed at 1209600 (14 days) on the genesis profile")
        );
    }

    function _councilFromEnv(string memory prefix) internal view returns (Council memory c) {
        c.owners = vm.envAddress(string.concat(prefix, "_OWNERS"), ",");
        c.threshold = vm.envUint(string.concat(prefix, "_THRESHOLD"));
        c.minDelay = vm.envUint(string.concat(prefix, "_MIN_DELAY"));
        // Unset -> the 14-day default; a set value must parse (vm.envUint reverts otherwise)
        // and is bounds-checked in _validate.
        string memory ttlKey = string.concat(prefix, "_PROPOSAL_TTL");
        c.proposalTtl = vm.envExists(ttlKey) ? vm.envUint(ttlKey) : DEFAULT_PROPOSAL_TTL;
    }

    function _validate(string memory name, Council memory c, address deployer) internal pure {
        uint256 n = c.owners.length;
        require(n >= 1 && n <= 10, string.concat(name, ": owner count must be 1..10"));
        require(c.threshold >= 1 && c.threshold <= n, string.concat(name, ": threshold must be 1..owners"));
        require(c.minDelay >= MIN_DELAY_FLOOR, string.concat(name, ": minDelay below the 1 hour floor"));
        require(
            c.proposalTtl >= PROPOSAL_TTL_MIN && c.proposalTtl <= PROPOSAL_TTL_MAX,
            string.concat(name, ": proposalTtl must be 1..30 days")
        );
        for (uint256 i = 0; i < n; i++) {
            require(c.owners[i] != address(0), string.concat(name, ": zero owner"));
            require(c.owners[i] != deployer, string.concat(name, ": the deployer cannot be an owner"));
            for (uint256 j = i + 1; j < n; j++) {
                require(c.owners[i] != c.owners[j], string.concat(name, ": duplicate owner"));
            }
        }
    }

    /// @notice Production-strength council parameters (C2 D5, owner decision 2026-10-19).
    ///         Waived only by an explicit ALLOW_WEAK_GOVERNANCE=1 off the genesis profile.
    function _requireProductionStrength(Council memory gov, Council memory grd) internal pure {
        require(
            gov.threshold >= GENESIS_GOV_MIN_THRESHOLD,
            "GOVERNANCE: threshold must be >= 3 (ALLOW_WEAK_GOVERNANCE=1 to waive)"
        );
        require(
            gov.owners.length >= GENESIS_GOV_MIN_OWNERS,
            "GOVERNANCE: owners must be >= 5 (ALLOW_WEAK_GOVERNANCE=1 to waive)"
        );
        require(
            gov.threshold * 2 > gov.owners.length,
            "GOVERNANCE: threshold must be a majority of owners (ALLOW_WEAK_GOVERNANCE=1 to waive)"
        );
        require(
            gov.minDelay >= GENESIS_GOV_MIN_DELAY,
            "GOVERNANCE: minDelay must be >= 48 hours (ALLOW_WEAK_GOVERNANCE=1 to waive)"
        );
        require(
            grd.threshold >= GENESIS_GRD_MIN_THRESHOLD,
            "GUARDIAN: threshold must be >= 2 (ALLOW_WEAK_GOVERNANCE=1 to waive)"
        );
        require(
            grd.owners.length >= GENESIS_GRD_MIN_OWNERS,
            "GUARDIAN: owners must be >= 3 (ALLOW_WEAK_GOVERNANCE=1 to waive)"
        );
        require(
            grd.threshold * 2 > grd.owners.length,
            "GUARDIAN: threshold must be a majority of owners (ALLOW_WEAK_GOVERNANCE=1 to waive)"
        );
        require(
            grd.minDelay < gov.minDelay,
            "GUARDIAN: minDelay must be shorter than GOVERNANCE minDelay (ALLOW_WEAK_GOVERNANCE=1 to waive)"
        );
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
        tl = _isLive(tlName, tlInit)
            ? _create2Address(tlName, tlInit)
            : address(new TimelockController{salt: Salts.salt(tlName)}(c.minDelay, none, none, deployer));

        bytes memory msInit =
            abi.encodePacked(type(MultisigProposer).creationCode, abi.encode(tl, c.owners, c.threshold, c.proposalTtl));
        ms = _isLive(msName, msInit)
            ? _create2Address(msName, msInit)
            : address(new MultisigProposer{salt: Salts.salt(msName)}(tl, c.owners, c.threshold, c.proposalTtl));
    }

    /// @notice CREATE2 GuardianCanceller(governance timelock, guardian timelock); reused when live.
    function _deployCanceller(address govTl, address grdTl) internal returns (address c) {
        bytes memory init = abi.encodePacked(type(GuardianCanceller).creationCode, abi.encode(govTl, grdTl));
        c = _isLive(GRD_CANCELLER, init)
            ? _create2Address(GRD_CANCELLER, init)
            : address(new GuardianCanceller{salt: Salts.salt(GRD_CANCELLER)}(govTl, grdTl));
    }

    /// @notice Hand `tl` to `ms` (and, when `canceller` is nonzero, CANCELLER only to it), then
    ///         renounce the deployer's admin. Runs only while the deployer still administers the
    ///         timelock; on a re-run after hand-over it is skipped and the postconditions
    ///         re-prove the end state.
    function _handOver(address tl, address ms, address deployer, address canceller) internal {
        TimelockController timelock = TimelockController(payable(tl));
        if (!timelock.hasRole(timelock.DEFAULT_ADMIN_ROLE(), deployer)) return;
        timelock.grantRole(timelock.PROPOSER_ROLE(), ms);
        timelock.grantRole(timelock.EXECUTOR_ROLE(), ms);
        timelock.grantRole(timelock.CANCELLER_ROLE(), ms);
        if (canceller != address(0)) timelock.grantRole(timelock.CANCELLER_ROLE(), canceller);
        timelock.renounceRole(timelock.DEFAULT_ADMIN_ROLE(), deployer);
    }

    /// @notice The GuardianCanceller (wired to GOVERNANCE, guardian = GUARDIAN timelock) holds
    ///         CANCELLER on the GOVERNANCE timelock and nothing else; neither the GUARDIAN
    ///         timelock nor its multisig holds any seat on it.
    function _assertGuardianVeto(Deployed memory d) internal view {
        TimelockController gt = TimelockController(payable(d.governanceTimelock));
        GuardianCanceller c = GuardianCanceller(d.guardianCanceller);
        require(c.governanceTimelock() == d.governanceTimelock, "GUARDIAN: canceller cancels on another timelock");
        require(c.guardian() == d.guardianTimelock, "GUARDIAN: canceller answers to another guardian");
        require(
            gt.hasRole(TIMELOCK_CANCELLER_ROLE, d.guardianCanceller),
            "GUARDIAN: guardian canceller cannot cancel GOVERNANCE operations"
        );
        bytes32[3] memory denied = [DEFAULT_ADMIN_ROLE, TIMELOCK_PROPOSER_ROLE, TIMELOCK_EXECUTOR_ROLE];
        for (uint256 i = 0; i < 3; i++) {
            require(
                !gt.hasRole(denied[i], d.guardianCanceller),
                "GUARDIAN: guardian canceller holds more than CANCELLER on GOVERNANCE"
            );
        }
        bytes32[4] memory all =
            [DEFAULT_ADMIN_ROLE, TIMELOCK_PROPOSER_ROLE, TIMELOCK_EXECUTOR_ROLE, TIMELOCK_CANCELLER_ROLE];
        for (uint256 i = 0; i < 4; i++) {
            require(!gt.hasRole(all[i], d.guardianTimelock), "GUARDIAN: guardian timelock holds a GOVERNANCE seat");
            require(!gt.hasRole(all[i], d.guardianMultisig), "GUARDIAN: guardian multisig holds a GOVERNANCE seat");
        }
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
