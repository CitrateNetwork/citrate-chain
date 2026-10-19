// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./AdminChecks.sol";
import {GuardianCanceller} from "../../src/genesis/GuardianCanceller.sol";

/// @title GenesisProfile: one chain-id source and one set of genesis floors for the C4 scripts
/// @notice The genesis profile (chain 40204) is chosen from the chain id the NODE reports, not
///         only from forge's simulated `block.chainid`. Forge lets the operator set the simulated
///         id independently of the node (`--chain-id`, `--chain`, `FOUNDRY_CHAIN_ID`), so a
///         `block.chainid` check alone can be steered off the genesis profile while the run
///         still broadcasts to a 40204 node. `_resolveChainProfile` therefore:
///           - asks the node (`vm.rpc("eth_chainId", "[]")` on the active fork) and refuses any
///             mismatch with `block.chainid`, in either direction;
///           - fails closed when there is no node to ask (pure simulation, no --rpc-url) and the
///             genesis profile would apply, since the floors could not be tied to a real chain.
///         Every C4 script that applies a genesis floor resolves its profile here, before it
///         broadcasts, and `CheckDeployedAdmins` re-checks the floors on the deployed contracts.
///
///         Floors (owner decisions 2026-10-19, fed#331), all read from chain by
///         `_councilFloorProblem`:
///           GOVERNANCE  minDelay >= 48 h; multisig m >= 3, n >= 5, m > n/2
///           GUARDIAN    multisig m >= 2, n >= 3, m > n/2
///           both        multisig fronts its timelock; proposalTtl == 14 days (fixed)
abstract contract GenesisProfile is Script, AdminChecks {
    /// The chain id that is always deployed under the genesis profile.
    uint256 public constant GENESIS_CHAIN_ID = 40204;
    uint256 public constant GENESIS_GOV_MIN_DELAY = 48 hours;
    uint256 public constant GENESIS_GOV_MIN_THRESHOLD = 3;
    uint256 public constant GENESIS_GOV_MIN_OWNERS = 5;
    uint256 public constant GENESIS_GRD_MIN_THRESHOLD = 2;
    uint256 public constant GENESIS_GRD_MIN_OWNERS = 3;
    /// Proposal TTL on the genesis profile: fixed, no other value is accepted.
    uint256 public constant GENESIS_PROPOSAL_TTL = 14 days;
    /// Rehearsal bounds; equal to MultisigProposer.MIN_/MAX_PROPOSAL_TTL (a test pins equality).
    uint256 public constant PROPOSAL_TTL_MIN = 1 days;
    uint256 public constant PROPOSAL_TTL_MAX = 30 days;

    /// CREATE2 salt name of the GuardianCanceller (DeployGenesisGovernance deploys it under it).
    string internal constant GUARDIAN_CANCELLER_SALT = "Genesis.GuardianCanceller";

    string internal constant GENESIS_NEEDS_NODE =
        "genesis profile needs a live node: run with --rpc-url (eth_chainId unavailable)";

    struct ChainProfile {
        bool genesis; // the genesis floors apply
        bool nodeChecked; // eth_chainId was read and equals block.chainid
        uint256 nodeChainId; // the id the node reported (0 when not checked)
    }

    /// @notice Resolve the profile for this run. `forced` applies the genesis profile on any
    ///         chain id (GENESIS_PROFILE=1). Reverts on a node / simulation chain-id mismatch,
    ///         and when the genesis profile applies but no node can be asked.
    function _resolveChainProfile(bool forced) internal returns (ChainProfile memory p) {
        (bool ok, uint256 node) = _nodeChainId();
        if (ok) {
            require(
                node == block.chainid,
                string.concat(
                    "chain id mismatch: node reports ",
                    vm.toString(node),
                    ", forge simulates ",
                    vm.toString(block.chainid),
                    " (drop --chain-id / --chain / FOUNDRY_CHAIN_ID)"
                )
            );
            (p.nodeChecked, p.nodeChainId) = (true, node);
        }
        p.genesis = forced || block.chainid == GENESIS_CHAIN_ID;
        require(ok || !p.genesis, GENESIS_NEEDS_NODE);
    }

    /// @notice The chain id the node behind the active fork reports, or (false, 0) when there
    ///         is no fork URL to ask. A response that is not a chain id reverts.
    /// @dev Virtual only so tests can stand in for a node; scripts never override it.
    function _nodeChainId() internal virtual returns (bool ok, uint256 id) {
        try vm.rpc("eth_chainId", "[]") returns (bytes memory r) {
            return (true, _decodeChainId(r));
        } catch {
            return (false, 0);
        }
    }

    /// @notice vm.rpc hands back the quantity's big-endian bytes ("0x9d0c" -> 0x9d0c).
    function _decodeChainId(bytes memory r) internal pure returns (uint256) {
        require(r.length != 0 && r.length <= 32, "eth_chainId: unreadable response");
        return uint256(bytes32(r)) >> (8 * (32 - r.length));
    }

    /// @notice A 0 / 1 switch: unset or "0" is off, "1" is on, anything else reverts, so a
    ///         typo cannot silently flip a safety switch either way.
    function _envFlag(string memory key) internal view returns (bool) {
        string memory raw = vm.envOr(key, string(""));
        bytes32 h = keccak256(bytes(raw));
        if (h == keccak256("") || h == keccak256("0")) return false;
        require(h == keccak256("1"), string.concat(key, " must be 0 or 1"));
        return true;
    }

    /// @notice Empty when the deployed council (`timelock` fronted by m-of-n `multisig`) meets
    ///         the genesis floors, read from chain; otherwise the first shortfall. `governance`
    ///         selects the GOVERNANCE floors (else GUARDIAN). Never reverts.
    function _councilFloorProblem(string memory name, address timelock, address multisig, bool governance)
        internal
        view
        returns (string memory)
    {
        if (timelock.code.length == 0) return string.concat(name, " timelock: no code");
        if (multisig.code.length == 0) return string.concat(name, " multisig: no code");
        (bool okDelay, bytes memory d) = timelock.staticcall(abi.encodeWithSignature("getMinDelay()"));
        if (!okDelay || d.length != 32) return string.concat(name, " timelock: getMinDelay() unreadable");
        if (governance && abi.decode(d, (uint256)) < GENESIS_GOV_MIN_DELAY) {
            return string.concat(name, " timelock: minDelay below the 48 h genesis floor");
        }
        (bool okFront, address fronted) = _readAddress(multisig, abi.encodeWithSignature("timelock()"));
        if (!okFront || fronted != timelock) return string.concat(name, " multisig does not front its timelock");
        (bool okM, uint256 m) = _readUint(multisig, abi.encodeWithSignature("threshold()"));
        (bool okN, uint256 n) = _readArrayLength(multisig, abi.encodeWithSignature("owners()"));
        if (!okM || !okN) return string.concat(name, " multisig: threshold/owners unreadable");
        (uint256 minM, uint256 minN) = governance
            ? (GENESIS_GOV_MIN_THRESHOLD, GENESIS_GOV_MIN_OWNERS)
            : (GENESIS_GRD_MIN_THRESHOLD, GENESIS_GRD_MIN_OWNERS);
        if (m < minM || n < minN) {
            return string.concat(
                name, " multisig: below the ", vm.toString(minM), "-of-", vm.toString(minN), " genesis floor"
            );
        }
        if (m * 2 <= n) return string.concat(name, " multisig: threshold is not a majority of owners");
        (bool okTtl, uint256 ttl) = _readUint(multisig, abi.encodeWithSignature("proposalTtl()"));
        if (!okTtl || ttl != GENESIS_PROPOSAL_TTL) {
            return string.concat(name, " multisig: proposalTtl is not the fixed 14-day genesis value");
        }
        return "";
    }

    function _requireCouncilFloor(string memory name, address timelock, address multisig, bool governance)
        internal
        view
    {
        string memory problem = _councilFloorProblem(name, timelock, multisig, governance);
        require(bytes(problem).length == 0, problem);
    }

    /// @notice The GOVERNANCE timelock's one permitted extra CANCELLER: the GuardianCanceller
    ///         that governance book `json` lists beside `govTl`, verified on chain. Empty
    ///         `problem` (and the canceller) only when:
    ///           - the book names `govTl` as its GovernanceTimelock and lists GuardianCanceller,
    ///             GuardianTimelock and GuardianMultisig;
    ///           - the canceller sits at its CREATE2 address (Arachnid factory,
    ///             GUARDIAN_CANCELLER_SALT, init = GuardianCanceller(govTl, GuardianTimelock)),
    ///             so the address itself commits to this build's creation code and those args;
    ///           - its runtime code is this build's GuardianCanceller for `govTl` (codehash
    ///             compared with a reference instance built here in simulation, never broadcast);
    ///           - it reads back governanceTimelock() == govTl and guardian() == GuardianTimelock;
    ///           - GuardianMultisig is the ceremony's MultisigProposer for the GuardianTimelock
    ///             (CREATE2 provenance under "Genesis.GuardianMultisig", incl. its proposal TTL),
    ///             and the GuardianTimelock's own complete holder sets are exactly {itself} as
    ///             admin and GuardianMultisig as proposer / executor / canceller (no extras).
    ///         Never reverts; anything unverifiable is a problem.
    function _bookGuardianCanceller(string memory json, address govTl)
        internal
        returns (string memory problem, address canceller)
    {
        if (
            !vm.keyExistsJson(json, ".contracts.GovernanceTimelock")
                || vm.parseJsonAddress(json, ".contracts.GovernanceTimelock") != govTl
        ) return ("governance book does not name this GovernanceTimelock", address(0));
        if (!vm.keyExistsJson(json, ".contracts.GuardianCanceller")) {
            return ("governance book lists no GuardianCanceller", address(0));
        }
        if (
            !vm.keyExistsJson(json, ".contracts.GuardianTimelock")
                || !vm.keyExistsJson(json, ".contracts.GuardianMultisig")
        ) return ("GuardianCanceller listed without GuardianTimelock and GuardianMultisig", address(0));
        address c = vm.parseJsonAddress(json, ".contracts.GuardianCanceller");
        address grdTl = vm.parseJsonAddress(json, ".contracts.GuardianTimelock");
        address grdMs = vm.parseJsonAddress(json, ".contracts.GuardianMultisig");

        if (govTl.code.length == 0 || grdTl.code.length == 0) {
            return ("GuardianCanceller: a timelock it is wired to has no code", address(0));
        }
        bytes memory init = abi.encodePacked(type(GuardianCanceller).creationCode, abi.encode(govTl, grdTl));
        // The same CREATE2 provenance AdminChecks uses for the councils (`_ceremonyCreate2Address`).
        address expected = _ceremonyCreate2Address(GUARDIAN_CANCELLER_SALT, init);
        if (c != expected) {
            return
                (
                    "GuardianCanceller is not at its CREATE2 address for (GovernanceTimelock, GuardianTimelock)",
                    address(0)
                );
        }
        if (c.code.length == 0) return ("GuardianCanceller: no code", address(0));
        if (c.codehash != address(new GuardianCanceller(govTl, grdTl)).codehash) {
            return ("GuardianCanceller: runtime code is not this build's GuardianCanceller", address(0));
        }
        (bool okT, address t) = _readAddress(c, abi.encodeWithSignature("governanceTimelock()"));
        if (!okT || t != govTl) return ("GuardianCanceller cancels on another timelock", address(0));
        (bool okG, address g) = _readAddress(c, abi.encodeWithSignature("guardian()"));
        if (!okG || g != grdTl) return ("GuardianCanceller answers to another guardian", address(0));
        // The guardian council is authenticated (ceremony MultisigProposer for GuardianTimelock)
        // before it counts as that timelock's sole holder.
        string memory grdAuth =
            _multisigProposerProblem(grdMs, grdTl, string.concat(GENESIS_SALT_PREFIX, "GuardianMultisig"));
        if (bytes(grdAuth).length != 0) return (string.concat("GuardianMultisig: ", grdAuth), address(0));
        string memory grd = _timelockHolderProblem(grdTl, grdMs, new address[](0));
        if (bytes(grd).length != 0) return (string.concat("GuardianTimelock: ", grd), address(0));
        return ("", c);
    }

    function _readUint(address target, bytes memory cd) internal view returns (bool ok, uint256 value) {
        (bool success, bytes memory ret) = target.staticcall(cd);
        if (!success || ret.length != 32) return (false, 0);
        return (true, abi.decode(ret, (uint256)));
    }

    /// @notice Length of an `address[]` return value, without trusting the encoding.
    function _readArrayLength(address target, bytes memory cd) internal view returns (bool ok, uint256 len) {
        (bool success, bytes memory ret) = target.staticcall(cd);
        if (!success || ret.length < 64) return (false, 0);
        (uint256 offset, uint256 n) = (_word(ret, 0), 0);
        if (offset > ret.length - 32) return (false, 0);
        n = _word(ret, offset);
        if (n > (ret.length - 32 - offset) / 32) return (false, 0);
        return (true, n);
    }

    function _word(bytes memory b, uint256 at) private pure returns (uint256 w) {
        assembly ("memory-safe") {
            w := mload(add(add(b, 32), at))
        }
    }
}
