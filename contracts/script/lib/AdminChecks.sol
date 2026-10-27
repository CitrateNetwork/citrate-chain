// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Vm} from "forge-std/Vm.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {MultisigProposer} from "../../src/genesis/MultisigProposer.sol";
import {Salts} from "../Salts.sol";

/// @title AdminChecks — post-deploy admin/owner/governance assertions (PBA-L2-002)
/// @notice The 2026-09-24 pre-bounty audit found that `new X{salt:}()` in a forge
///         script runs the constructor with `msg.sender == 0x4e59…956C` (the
///         Arachnid CREATE2 deployer). 21 live contracts on 40204 recorded that
///         factory as their governance / owner / DEFAULT_ADMIN, which nobody can
///         ever act as. Every ceremony script now calls these helpers after
///         deploying, so a regression fails the dry-run instead of shipping.
///
///         All reads are low-level `staticcall`s: a contract that does not
///         implement a given getter is simply not checked for that slot, and a
///         codeless target is an error in its own right.
abstract contract AdminChecks {
    address internal constant ARACHNID_FACTORY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    bytes32 internal constant DEFAULT_ADMIN_ROLE = 0x00;
    /// OZ TimelockController role ids (keccak256 of the role name, as OZ defines them).
    bytes32 internal constant TIMELOCK_PROPOSER_ROLE = keccak256("PROPOSER_ROLE");
    bytes32 internal constant TIMELOCK_EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    bytes32 internal constant TIMELOCK_CANCELLER_ROLE = keccak256("CANCELLER_ROLE");

    function _readAddress(address target, bytes memory cd) internal view returns (bool ok, address value) {
        (bool success, bytes memory ret) = target.staticcall(cd);
        if (!success || ret.length != 32) return (false, address(0));
        return (true, abi.decode(ret, (address)));
    }

    /// @dev A set/role getter is "true" only for a 32-byte 1; any other word
    ///      (not a bool encoding) means "not this kind of getter", never a revert.
    function _readBool(address target, bytes memory cd) internal view returns (bool ok, bool value) {
        (bool success, bytes memory ret) = target.staticcall(cd);
        if (!success || ret.length != 32) return (false, false);
        uint256 w = abi.decode(ret, (uint256));
        if (w > 1) return (false, false);
        return (true, w == 1);
    }

    /// @notice Every address-valued privileged getter the sweep reads: admin
    ///         and governance slots, fee recipients, bound callers, operators,
    ///         oracles, signers and wired dependencies. A contract without a
    ///         getter is simply not checked for it.
    /// @dev scripts/ci/privileged_slots_tripwire.sh requires every address slot
    ///      of a DeployAll contract to be read here or exempt with a reason
    ///      (contracts/script/lib/privileged_slots.json).
    /// @dev Built element by element into a dynamic array: under via-IR, the equivalent
    ///      `string[40]` array literal miscompiled DeployDormantLedgers (its first cheatcode
    ///      call went to a garbage address) once this sweep and the genesis checks shared a
    ///      contract. Keep the lists dynamic.
    function _addressSlotGetters() internal pure returns (string[] memory g) {
        g = new string[](40);
        g[0] = "governance()";
        g[1] = "pendingGovernance()";
        g[2] = "owner()";
        g[3] = "pendingOwner()";
        g[4] = "admin()";
        g[5] = "pendingAdmin()";
        g[6] = "guardian()";
        g[7] = "provider()";
        g[8] = "treasury()";
        g[9] = "treasuryAddress()";
        g[10] = "pendingTreasury()";
        g[11] = "feeRecipient()";
        g[12] = "marketplace()";
        g[13] = "verifier()";
        g[14] = "operator()";
        g[15] = "minter()";
        g[16] = "oracle()";
        g[17] = "pricingOracle()";
        g[18] = "signer()";
        g[19] = "verifyingSigner()";
        g[20] = "relayer()";
        g[21] = "slasher()";
        g[22] = "facilitator()";
        g[23] = "burner()";
        g[24] = "slashingContract()";
        g[25] = "bulkGateway()";
        g[26] = "jobRegistry()";
        g[27] = "modelRegistry()";
        g[28] = "marketMaker()";
        g[29] = "contributionAccounting()";
        g[30] = "contributions()";
        g[31] = "stakingPool()";
        g[32] = "distributionStablecoin()";
        g[33] = "wSALT()";
        g[34] = "registry()";
        g[35] = "recorder()";
        g[36] = "keeper()";
        g[37] = "manager()";
        g[38] = "controller()";
        g[39] = "beneficiary()";
    }

    /// @notice Every `mapping(address => bool)` membership the sweep reads.
    function _addressSetGetters() internal pure returns (string[] memory g) {
        g = new string[](12);
        g[0] = "authorizedRecorders(address)";
        g[1] = "authorizedDisputers(address)";
        g[2] = "authorizedSpenders(address)";
        g[3] = "authorizedActivityRecorders(address)";
        g[4] = "authorizedMatcher(address)";
        g[5] = "teeOracles(address)";
        g[6] = "isOracle(address)";
        g[7] = "isOracleMember(address)";
        g[8] = "isRecorder(address)";
        g[9] = "eligibleParticipant(address)";
        g[10] = "isOperator(address)";
        g[11] = "isMinter(address)";
    }

    /// @notice Every role the sweep reads through `hasRole(bytes32,address)`.
    function _probedRoleNames() internal pure returns (string[] memory g) {
        g = new string[](12);
        g[0] = "DEFAULT_ADMIN_ROLE";
        g[1] = "OPERATOR_ROLE";
        g[2] = "VALIDATOR_ROLE";
        g[3] = "REPORTER_ROLE";
        g[4] = "FACILITATOR_ROLE";
        g[5] = "MINTER_ROLE";
        g[6] = "PAUSER_ROLE";
        g[7] = "UPGRADER_ROLE";
        g[8] = "PROPOSER_ROLE";
        g[9] = "EXECUTOR_ROLE";
        g[10] = "CANCELLER_ROLE";
        g[11] = "TIMELOCK_ADMIN_ROLE";
    }

    function _roleId(string memory name) internal pure returns (bytes32) {
        return keccak256(bytes(name)) == keccak256("DEFAULT_ADMIN_ROLE") ? DEFAULT_ADMIN_ROLE : keccak256(bytes(name));
    }

    /// An address no genuine set or role contains: a getter that also answers
    /// "true" for it answers for everyone (a fallback), so its answer is ignored.
    address private constant UNHELD = address(uint160(uint256(keccak256("AdminChecks.unheld-probe"))));

    function _holds(address target, bytes memory cdWho, bytes memory cdUnheld) private view returns (bool) {
        (bool ok, bool v) = _readBool(target, cdWho);
        if (!ok || !v) return false;
        (bool ok2, bool v2) = _readBool(target, cdUnheld);
        return !(ok2 && v2);
    }

    /// @notice The first privileged slot of `target` that names `who`, as
    ///         "<getter> is <noun>", "<subject> is in <set>" or "<subject> holds
    ///         <ROLE>"; empty when there is none. Never reverts.
    function _holderProblem(address target, address who, string memory noun, string memory subject)
        internal
        view
        returns (string memory)
    {
        if (target.code.length == 0) return "no code at address";
        string[] memory getters = _addressSlotGetters();
        for (uint256 i = 0; i < getters.length; i++) {
            (bool ok, address a) = _readAddress(target, abi.encodeWithSignature(getters[i]));
            if (ok && a == who) return string.concat(getters[i], " is ", noun);
        }
        string[] memory sets = _addressSetGetters();
        for (uint256 i = 0; i < sets.length; i++) {
            if (_holds(target, abi.encodeWithSignature(sets[i], who), abi.encodeWithSignature(sets[i], UNHELD))) {
                return string.concat(subject, " is in ", sets[i]);
            }
        }
        string[] memory roles = _probedRoleNames();
        for (uint256 i = 0; i < roles.length; i++) {
            bytes32 r = _roleId(roles[i]);
            if (
                _holds(
                    target,
                    abi.encodeWithSignature("hasRole(bytes32,address)", r, who),
                    abi.encodeWithSignature("hasRole(bytes32,address)", r, UNHELD)
                )
            ) return string.concat(subject, " holds ", roles[i]);
        }
        return "";
    }

    /// @notice Returns an empty string when `target` is clean, otherwise the
    ///         first problem found. Never reverts, so a sweep can collect all.
    function _factoryAdminProblem(address target) internal view returns (string memory) {
        string memory p = _holderProblem(target, ARACHNID_FACTORY, "the CREATE2 factory", "CREATE2 factory");
        if (bytes(p).length != 0) return p;
        return _governingSeatProblem(target, ARACHNID_FACTORY, "CREATE2 factory");
    }

    /// @notice Like `_factoryAdminProblem` but for the deployer EOA: after the
    ///         hand-off it must hold no privileged slot on any deployed book
    ///         contract (governance/owner/admin, fee recipient, bound caller,
    ///         operator, oracle, signer, set membership or role).
    function _deployerAdminProblem(address target, address deployer) internal view returns (string memory) {
        string memory p = _holderProblem(target, deployer, "the deployer EOA", "deployer EOA");
        if (bytes(p).length != 0) return p;
        return _governingSeatProblem(target, deployer, "deployer EOA");
    }

    /// @notice C4 genesis governance: the seats that govern without being an "admin" slot.
    ///         OZ `TimelockController` PROPOSER / EXECUTOR / CANCELLER (whoever holds them
    ///         runs the timelock, and through it everything it administers), and an owner
    ///         seat on an m-of-n (`isOwner(address)`: MultisigProposer, MultisigTimelock2of3).
    ///         Empty string when `holder` sits in none of them.
    function _governingSeatProblem(address target, address holder, string memory who)
        internal
        view
        returns (string memory)
    {
        bytes32[3] memory roles = [TIMELOCK_PROPOSER_ROLE, TIMELOCK_EXECUTOR_ROLE, TIMELOCK_CANCELLER_ROLE];
        string[3] memory names = ["PROPOSER_ROLE", "EXECUTOR_ROLE", "CANCELLER_ROLE"];
        for (uint256 i = 0; i < 3; i++) {
            (bool ok, bool has) =
                _readBool(target, abi.encodeWithSignature("hasRole(bytes32,address)", roles[i], holder));
            if (ok && has) return string.concat(who, " holds timelock ", names[i]);
        }
        (bool okOwner, bool owner) = _readBool(target, abi.encodeWithSignature("isOwner(address)", holder));
        if (okOwner && owner) return string.concat(who, " is a multisig owner");
        return "";
    }

    /// @notice Revert unless OZ TimelockController `timelock` has been handed over to
    ///         `multisig`: the multisig holds PROPOSER, EXECUTOR and CANCELLER, execution is
    ///         not open to everyone, the timelock administers itself, its delay is
    ///         `minDelay`, and `deployer` (and the CREATE2 factory) hold no seat on it.
    function _assertTimelockHandover(
        string memory name,
        address timelock,
        address multisig,
        address deployer,
        uint256 minDelay
    ) internal view {
        _assertTimelockSeats(name, timelock, multisig, deployer);
        require(
            _timelockMinDelay(timelock) == minDelay,
            string.concat(name, ": timelock minDelay is not the intended value")
        );
    }

    /// @notice The seat half of `_assertTimelockHandover` (everything but the delay value):
    ///         `multisig` holds PROPOSER, EXECUTOR and CANCELLER, execution is not open to
    ///         everyone, the timelock administers itself, and neither `deployer` nor the
    ///         CREATE2 factory holds an admin slot or governing seat on it.
    function _assertTimelockSeats(string memory name, address timelock, address multisig, address deployer)
        internal
        view
    {
        _assertNoFactoryAdmin(name, timelock);
        _assertNoDeployerAdmin(name, timelock, deployer);
        bytes32[3] memory roles = [TIMELOCK_PROPOSER_ROLE, TIMELOCK_EXECUTOR_ROLE, TIMELOCK_CANCELLER_ROLE];
        for (uint256 i = 0; i < 3; i++) {
            (bool ok, bool has) =
                _readBool(timelock, abi.encodeWithSignature("hasRole(bytes32,address)", roles[i], multisig));
            require(ok && has, string.concat(name, ": multisig lacks a timelock role"));
        }
        (bool okOpen, bool open) =
            _readBool(timelock, abi.encodeWithSignature("hasRole(bytes32,address)", TIMELOCK_EXECUTOR_ROLE, address(0)));
        require(okOpen && !open, string.concat(name, ": timelock execution is open to anyone"));
        (bool okSelf, bool self) =
            _readBool(timelock, abi.encodeWithSignature("hasRole(bytes32,address)", DEFAULT_ADMIN_ROLE, timelock));
        require(okSelf && self, string.concat(name, ": timelock does not administer itself"));
    }

    // ---- Complete role-holder sets on an OZ TimelockController ----
    //
    // `_assertTimelockSeats` proves the multisig HOLDS the timelock roles and that the deploy
    // accounts do not; it cannot prove that nobody else does. OZ AccessControl is not
    // enumerable, so the full holder set is rebuilt from the timelock's own RoleGranted /
    // RoleRevoked history (every grant and revoke in OZ AccessControl emits one), then every
    // reconstructed account is re-read with `hasRole` on the live state. Anything that keeps the
    // set from being established fails closed: no RPC, a failed or out-of-range page, a history
    // that does not start at the timelock's construction, or a replay that disagrees with the
    // live state.

    Vm private constant HISTORY_VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    bytes32 internal constant ROLE_GRANTED_SIG = keccak256("RoleGranted(bytes32,address,address)");
    bytes32 internal constant ROLE_REVOKED_SIG = keccak256("RoleRevoked(bytes32,address,address)");
    bytes32 internal constant MIN_DELAY_CHANGE_SIG = keccak256("MinDelayChange(uint256,uint256)");
    /// The Citrate node clamps an eth_getLogs range to from..from+1000 WITHOUT an error
    /// (core/api eth_rpc.rs `max_block_range`), so a page never spans more than 1000 blocks.
    uint256 internal constant ROLE_HISTORY_MAX_WINDOW = 1000;

    uint8 internal constant HISTORY_GRANT = 1;
    uint8 internal constant HISTORY_REVOKE = 2;
    /// `MinDelayChange(0, d)`: what the TimelockController constructor emits last.
    uint8 internal constant HISTORY_DELAY_INIT = 3;

    struct RoleEvent {
        uint8 kind;
        bytes32 role;
        address account;
        /// RoleGranted / RoleRevoked `sender` (topic 3): the caller that made the change.
        address sender;
        /// HISTORY_DELAY_INIT only: the delay the constructor set (`MinDelayChange(0, d)`).
        uint256 delay;
        bytes32 txHash;
    }

    /// Live holders of the four timelock roles, as established from history + `hasRole`.
    struct TimelockHolders {
        address[] admins;
        address[] proposers;
        address[] executors;
        address[] cancellers;
    }

    /// @notice The timelock's role history, oldest first, from the node behind the active fork.
    ///         Pages `eth_getLogs` in windows of at most ROLE_HISTORY_MAX_WINDOW blocks from
    ///         TIMELOCK_HISTORY_FROM_BLOCK (default 0, i.e. the whole chain) to the fork head.
    ///         FROM_BLOCK is only a speed-up and is not trusted: `_timelockHolders` refuses any
    ///         window whose first event is not the timelock's CREATE2 construction.
    ///         `ok == false` (with the reason) when any page cannot be fetched or is malformed.
    /// @dev Virtual only so `forge test` (which has no node) can supply recorded logs;
    ///      scripts never override it.
    function _timelockRoleHistory(address timelock)
        internal
        virtual
        returns (bool ok, string memory why, RoleEvent[] memory events)
    {
        uint256 head = HISTORY_VM.getBlockNumber();
        uint256 from = HISTORY_VM.envOr("TIMELOCK_HISTORY_FROM_BLOCK", uint256(0));
        uint256 window = HISTORY_VM.envOr("TIMELOCK_HISTORY_WINDOW", ROLE_HISTORY_MAX_WINDOW);
        if (window == 0 || window > ROLE_HISTORY_MAX_WINDOW) {
            return (false, "role history: TIMELOCK_HISTORY_WINDOW must be 1..1000 blocks", events);
        }
        if (from > head) return (false, "role history: TIMELOCK_HISTORY_FROM_BLOCK is past the head", events);
        bool any;
        uint256 lastBlock;
        uint256 lastIndex;
        for (uint256 a = from; a <= head; a += window) {
            uint256 b = head - a < window ? head : a + window - 1;
            Vm.EthGetLogs[] memory logs;
            try HISTORY_VM.eth_getLogs(a, b, timelock, new bytes32[](0)) returns (Vm.EthGetLogs[] memory got) {
                logs = got;
            } catch {
                return (
                    false,
                    string.concat(
                        "role history unavailable: eth_getLogs failed for blocks ",
                        HISTORY_VM.toString(a),
                        "-",
                        HISTORY_VM.toString(b)
                    ),
                    events
                );
            }
            for (uint256 i = 0; i < logs.length; i++) {
                Vm.EthGetLogs memory l = logs[i];
                if (l.emitter != timelock || l.removed || l.blockNumber < a || l.blockNumber > b) {
                    return (false, "role history: eth_getLogs returned a log outside the query", events);
                }
                if (any && (l.blockNumber < lastBlock || (l.blockNumber == lastBlock && l.logIndex <= lastIndex))) {
                    return (false, "role history: eth_getLogs returned logs out of order", events);
                }
                (any, lastBlock, lastIndex) = (true, l.blockNumber, l.logIndex);
                (bool keep, RoleEvent memory e) = _decodeHistoryLog(l.topics, l.data, l.transactionHash);
                if (keep) events = _pushRoleEvent(events, e);
            }
        }
        return (true, "", events);
    }

    /// @notice A timelock log as a history entry; `keep == false` for logs that are neither a
    ///         role grant / revoke nor the constructor's `MinDelayChange(0, d)`.
    function _decodeHistoryLog(bytes32[] memory topics, bytes memory data, bytes32 txHash)
        internal
        pure
        returns (bool keep, RoleEvent memory e)
    {
        if (topics.length == 4 && (topics[0] == ROLE_GRANTED_SIG || topics[0] == ROLE_REVOKED_SIG)) {
            e.kind = topics[0] == ROLE_GRANTED_SIG ? HISTORY_GRANT : HISTORY_REVOKE;
            (e.role, e.account, e.txHash) = (topics[1], address(uint160(uint256(topics[2]))), txHash);
            e.sender = address(uint160(uint256(topics[3])));
            return (true, e);
        }
        if (topics.length == 1 && topics[0] == MIN_DELAY_CHANGE_SIG && data.length == 64) {
            (uint256 oldDelay, uint256 newDelay) = abi.decode(data, (uint256, uint256));
            if (oldDelay == 0) {
                (e.kind, e.delay, e.txHash) = (HISTORY_DELAY_INIT, newDelay, txHash);
                return (true, e);
            }
        }
        return (false, e);
    }

    function _pushRoleEvent(RoleEvent[] memory list, RoleEvent memory e)
        internal
        pure
        returns (RoleEvent[] memory out)
    {
        out = new RoleEvent[](list.length + 1);
        for (uint256 i = 0; i < list.length; i++) {
            out[i] = list[i];
        }
        out[list.length] = e;
    }

    function _isTimelockRole(bytes32 role) private pure returns (bool) {
        return role == DEFAULT_ADMIN_ROLE || role == TIMELOCK_PROPOSER_ROLE || role == TIMELOCK_EXECUTOR_ROLE
            || role == TIMELOCK_CANCELLER_ROLE;
    }

    /// @notice Replay `events` into the live holders of the four timelock roles. Empty `problem`
    ///         when the set is established: the history starts with the constructor's
    ///         self-administration grant (made by the CREATE2 factory, and the constructor's
    ///         events rebuild the timelock's ceremony CREATE2 address: `_timelockCreationProblem`),
    ///         the same transaction emitted `MinDelayChange(0, d)`,
    ///         and every account the history names reads back from `hasRole` exactly as the
    ///         replay says (a missing grant or revoke shows up as a disagreement).
    function _timelockHolders(address timelock, RoleEvent[] memory events)
        internal
        view
        returns (string memory problem, TimelockHolders memory h)
    {
        if (events.length == 0) return ("role history is empty", h);
        RoleEvent memory first = events[0];
        if (
            first.kind != HISTORY_GRANT || first.role != DEFAULT_ADMIN_ROLE || first.account != timelock
                || first.sender != ARACHNID_FACTORY
        ) return ("role history does not start at the timelock's construction", h);
        string memory creation = _timelockCreationProblem(timelock, events);
        if (bytes(creation).length != 0) return (creation, h);
        bool constructed;
        uint256 n;
        bytes32[] memory roles = new bytes32[](events.length);
        address[] memory accounts = new address[](events.length);
        bool[] memory held = new bool[](events.length);
        for (uint256 i = 0; i < events.length; i++) {
            RoleEvent memory e = events[i];
            if (e.kind == HISTORY_DELAY_INIT) {
                if (e.txHash == first.txHash) constructed = true;
                continue;
            }
            if (!_isTimelockRole(e.role)) continue;
            uint256 j = 0;
            while (j < n && !(roles[j] == e.role && accounts[j] == e.account)) j++;
            if (j == n) (roles[n], accounts[n], n) = (e.role, e.account, n + 1);
            held[j] = e.kind == HISTORY_GRANT;
        }
        if (!constructed) return ("role history: no constructor MinDelayChange(0, d) in the creation transaction", h);

        uint256[4] memory counts;
        bool[] memory live = new bool[](n);
        for (uint256 j = 0; j < n; j++) {
            (bool ok, bool has) =
                _readBool(timelock, abi.encodeWithSignature("hasRole(bytes32,address)", roles[j], accounts[j]));
            if (!ok) return ("hasRole unreadable", h);
            if (has != held[j]) return ("role history disagrees with the live hasRole state (incomplete history)", h);
            live[j] = has;
            if (has) counts[_roleSlot(roles[j])]++;
        }
        (h.admins, h.proposers, h.executors, h.cancellers) =
        (new address[](counts[0]), new address[](counts[1]), new address[](counts[2]), new address[](counts[3]));
        counts = [uint256(0), 0, 0, 0];
        for (uint256 j = 0; j < n; j++) {
            if (!live[j]) continue;
            uint256 slot = _roleSlot(roles[j]);
            address[] memory dst =
                slot == 0 ? h.admins : slot == 1 ? h.proposers : slot == 2 ? h.executors : h.cancellers;
            dst[counts[slot]++] = accounts[j];
        }
        return ("", h);
    }

    // ---- Where the history starts: the timelock's own CREATE2 construction (chain#320 P1) ----
    //
    // A replay is only complete if its window covers the timelock's construction. That used to
    // be taken from the first in-window `RoleGranted(DEFAULT_ADMIN_ROLE, timelock)` plus a
    // `MinDelayChange(0, d)` in the same transaction, a pair a deployer-controlled timelock can
    // emit again later; a window that starts after an earlier grant then never sees it. Nor can
    // the window be checked against state at a block (`eth_getCode(timelock, from - 1)`): the
    // Citrate node answers eth_getCode with the latest state whatever the block tag.
    //
    // The check therefore uses nothing but the logs. The first in-window event must be the
    // self-admin grant made BY THE CREATE2 FACTORY (topic `sender` == the Arachnid deployer),
    // and the constructor arguments rebuilt from that transaction's events must reproduce the
    // timelock's own address under a ceremony salt:
    //   address == keccak256(0xff ++ factory ++ Salts.salt(name) ++
    //                        keccak256(TimelockController.creationCode ++ abi.encode(args)))[12:]
    // That address commits to OZ TimelockController's genuine init code with those arguments,
    // so this constructor (and no other code: the timelock cannot self-destruct) ran there, and
    // its events are real. Inside the genuine contract a RoleGranted carries the factory as
    // `sender` only from the constructor: every later grant's sender is its caller, and the
    // Arachnid deployer (its runtime is checked) calls nothing, it only runs CREATE2. So the
    // first in-window event can only be the construction itself, and a window that starts after
    // it fails closed, whatever TIMELOCK_HISTORY_FROM_BLOCK says. It holds on anvil and on the
    // Citrate node alike, since both serve eth_getLogs topics, transaction hashes and order.

    /// Runtime code of the Arachnid deterministic-deployment proxy (0x4e59…956C).
    bytes32 internal constant ARACHNID_FACTORY_CODEHASH = keccak256(
        hex"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3"
    );

    /// Salts DeployGenesisGovernance gives its timelocks ("Genesis." + book name).
    function _ceremonyTimelockSalts() internal pure returns (string[2] memory) {
        return ["Genesis.GovernanceTimelock", "Genesis.GuardianTimelock"];
    }

    /// @notice Empty when `events` (oldest first, `events[0]` the factory-made self-admin grant)
    ///         open with the construction of `timelock`: the OZ TimelockController constructor's
    ///         events, all in one transaction and all made by the CREATE2 factory, rebuild
    ///         (minDelay, proposers, executors, admin) such that the ceremony's CREATE2 address
    ///         for them is `timelock`. See the section comment for why this proves the window
    ///         starts at the construction.
    function _timelockCreationProblem(address timelock, RoleEvent[] memory events)
        internal
        view
        returns (string memory)
    {
        if (ARACHNID_FACTORY.codehash != ARACHNID_FACTORY_CODEHASH) {
            return "role history: no Arachnid CREATE2 factory at its canonical address";
        }
        // OZ TimelockController(minDelay, proposers, executors, admin) emits, in order:
        //   RoleGranted(ADMIN, this); [RoleGranted(ADMIN, admin)]; per proposer RoleGranted(PROPOSER, p)
        //   then RoleGranted(CANCELLER, p); per executor RoleGranted(EXECUTOR, e); MinDelayChange(0, minDelay).
        bytes32 creationTx = events[0].txHash;
        address admin;
        uint256 nP;
        uint256 nE;
        address[] memory proposers = new address[](events.length);
        address[] memory executors = new address[](events.length);
        bool done;
        uint256 minDelay;
        for (uint256 i = 1; i < events.length && !done; i++) {
            RoleEvent memory e = events[i];
            if (e.txHash != creationTx) break;
            if (e.kind == HISTORY_DELAY_INIT) {
                (done, minDelay) = (true, e.delay);
            } else if (e.kind != HISTORY_GRANT || e.sender != ARACHNID_FACTORY) {
                return "role history: the timelock's creation transaction is not its constructor alone";
            } else if (e.role == DEFAULT_ADMIN_ROLE && i == 1) {
                admin = e.account;
            } else if (e.role == TIMELOCK_PROPOSER_ROLE && nE == 0) {
                proposers[nP++] = e.account;
            } else if (
                e.role == TIMELOCK_CANCELLER_ROLE && nE == 0 && nP != 0 && proposers[nP - 1] == e.account
                    && events[i - 1].role == TIMELOCK_PROPOSER_ROLE
            ) {
                continue;
            } else if (e.role == TIMELOCK_EXECUTOR_ROLE) {
                executors[nE++] = e.account;
            } else {
                return "role history: the timelock's creation transaction is not its constructor alone";
            }
        }
        if (!done) return "role history: no constructor MinDelayChange(0, d) in the creation transaction";
        assembly ("memory-safe") {
            mstore(proposers, nP)
            mstore(executors, nE)
        }
        bytes memory init =
            abi.encodePacked(type(TimelockController).creationCode, abi.encode(minDelay, proposers, executors, admin));
        string[2] memory salts = _ceremonyTimelockSalts();
        for (uint256 k = 0; k < salts.length; k++) {
            if (_ceremonyCreate2Address(salts[k], init) == timelock) return "";
        }
        return "role history: the timelock is not the ceremony's CREATE2 TimelockController for its creation events";
    }

    function _roleSlot(bytes32 role) private pure returns (uint256) {
        if (role == DEFAULT_ADMIN_ROLE) return 0;
        if (role == TIMELOCK_PROPOSER_ROLE) return 1;
        if (role == TIMELOCK_EXECUTOR_ROLE) return 2;
        return 3;
    }

    function _isExactly(address[] memory set, address only) private pure returns (bool) {
        return set.length == 1 && set[0] == only;
    }

    /// @notice Empty when the COMPLETE holder sets of OZ TimelockController `timelock` are: the
    ///         timelock itself as the sole DEFAULT_ADMIN, `council` as the sole PROPOSER and the
    ///         sole EXECUTOR, and `council` as CANCELLER with no other canceller outside
    ///         `extraCancellers`. Also requires `timelock` to run this build's OZ
    ///         TimelockController runtime code (the history replay relies on its events).
    ///         Never reverts; a history that cannot be established is a problem, not a pass.
    function _timelockHolderProblem(address timelock, address council, address[] memory extraCancellers)
        internal
        returns (string memory)
    {
        if (timelock.code.length == 0) return "no code at address";
        if (timelock.codehash != keccak256(type(TimelockController).runtimeCode)) {
            return "runtime code is not this build's OZ TimelockController";
        }
        // A chain whose contracts are in block 0 (r1006: genesis from ceremony state) has no
        // role-grant events: the same invariant is proved from state instead.
        if (_genesisChainMode(timelock)) return _timelockHolderStateProblem(timelock, council, extraCancellers);
        (bool ok, string memory why, RoleEvent[] memory events) = _timelockRoleHistory(timelock);
        if (!ok) return why;
        // A timelock deployed by a transaction always logs its constructor's RoleGranted events,
        // so a timelock with code and NO role history at all was placed in block 0.
        if (events.length == 0 && !_genesisChainDisabled()) {
            return _timelockHolderStateProblem(timelock, council, extraCancellers);
        }
        (string memory problem, TimelockHolders memory h) = _timelockHolders(timelock, events);
        if (bytes(problem).length != 0) return problem;
        if (!_isExactly(h.admins, timelock)) return "DEFAULT_ADMIN_ROLE holders are not exactly the timelock itself";
        if (!_isExactly(h.proposers, council)) return "PROPOSER_ROLE holders are not exactly the multisig";
        if (!_isExactly(h.executors, council)) return "EXECUTOR_ROLE holders are not exactly the multisig";
        bool councilCancels;
        for (uint256 i = 0; i < h.cancellers.length; i++) {
            address c = h.cancellers[i];
            if (c == council) {
                councilCancels = true;
                continue;
            }
            bool allowed;
            for (uint256 k = 0; k < extraCancellers.length; k++) {
                if (extraCancellers[k] == c) allowed = true;
            }
            if (!allowed) return "CANCELLER_ROLE is held by an account other than the multisig";
        }
        if (!councilCancels) return "the multisig lacks CANCELLER_ROLE";
        return "";
    }

    // ---- Genesis-chain mode: role holders from STATE (no event history at block 0) ----
    //
    // On a chain whose contracts were placed in block 0 (r1006's genesis from ceremony state)
    // there are no RoleGranted / RoleRevoked logs to rebuild the holder sets from. The same
    // invariant (each role held by exactly its expected accounts) is then proved from state:
    //   1. every expected holder holds its role (hasRole);
    //   2. no other KNOWN account does (every address in this run's books, the deployer, the
    //      CREATE2 factory: `genesisKnown`, filled by the caller);
    //   3. completeness: every non-zero storage slot of the timelock in the block-0 allocation
    //      (GENESIS_ALLOC, `{"alloc":{"<addr>":{"storage":{...}}}}`) is accounted for: an
    //      expected holder's `_roles[role].hasRole[holder]` slot, or `_minDelay` equal to
    //      getMinDelay(); a holder outside the expected set, a changed role admin or a scheduled
    //      operation leaves an unexplained slot and fails. Each allocation slot is also re-read
    //      from the chain and must match it. This proves the allocation's slots are on this
    //      chain; on its own it does not prove the chain holds no slot outside the allocation.
    //   For an AccessControlEnumerable timelock, the member lists are enumerated and compared
    //   exactly as well.
    // Mode: GENESIS_CHAIN=1 forces it, =0 disables it; otherwise it is on for a timelock with
    // code and no role history at all (a timelock deployed by a transaction always logs its
    // constructor's RoleGranted events, so only a block-0 placement has none). Detection does
    // not use eth_getCode at block 0: a Citrate node answers that with the latest code.

    /// Accounts the genesis-chain holder check sweeps for unexpected roles (see above).
    address[] internal genesisKnown;

    /// @dev Virtual only so `forge test` can set the mode and the allocation without the
    ///      process-wide environment; scripts never override them.
    function _genesisChainMode(address) internal virtual returns (bool) {
        return keccak256(bytes(HISTORY_VM.envOr("GENESIS_CHAIN", string("")))) == keccak256("1");
    }

    function _genesisChainDisabled() internal returns (bool) {
        return keccak256(bytes(HISTORY_VM.envOr("GENESIS_CHAIN", string("")))) == keccak256("0");
    }

    function _genesisAllocPath() internal virtual returns (string memory) {
        return HISTORY_VM.envOr("GENESIS_ALLOC", string(""));
    }

    function _contains(address[] memory set, address a) private pure returns (bool) {
        for (uint256 i = 0; i < set.length; i++) {
            if (set[i] == a) return true;
        }
        return false;
    }

    function _roleSlot(bytes32 role, address holder) private pure returns (bytes32) {
        // OZ AccessControl: mapping(bytes32 => RoleData) _roles at slot 0; RoleData.hasRole first.
        return keccak256(abi.encode(holder, keccak256(abi.encode(role, uint256(0)))));
    }

    function _timelockHolderStateProblem(address timelock, address council, address[] memory extraCancellers)
        internal
        returns (string memory)
    {
        bytes32[4] memory roles =
            [DEFAULT_ADMIN_ROLE, TIMELOCK_PROPOSER_ROLE, TIMELOCK_EXECUTOR_ROLE, TIMELOCK_CANCELLER_ROLE];
        string[4] memory names = ["DEFAULT_ADMIN_ROLE", "PROPOSER_ROLE", "EXECUTOR_ROLE", "CANCELLER_ROLE"];
        address[] memory cancellers = new address[](1 + extraCancellers.length);
        cancellers[0] = council;
        for (uint256 i = 0; i < extraCancellers.length; i++) {
            cancellers[i + 1] = extraCancellers[i];
        }
        for (uint256 r = 0; r < 4; r++) {
            address[] memory want = _expectedHolders(r, timelock, council, cancellers);
            for (uint256 i = 0; i < want.length; i++) {
                (bool ok, bool has) =
                    _readBool(timelock, abi.encodeWithSignature("hasRole(bytes32,address)", roles[r], want[i]));
                if (!ok || !has) return string.concat(names[r], ": an expected holder does not hold it");
            }
            // AccessControlEnumerable: the member list must be exactly the expected set.
            (bool okN, uint256 n) =
                _readUint256(timelock, abi.encodeWithSignature("getRoleMemberCount(bytes32)", roles[r]));
            if (okN) {
                if (n != want.length) return string.concat(names[r], ": the enumerated member count is not the expected set's");
                for (uint256 i = 0; i < n; i++) {
                    (bool okM, address m) =
                        _readAddress(timelock, abi.encodeWithSignature("getRoleMember(bytes32,uint256)", roles[r], i));
                    if (!okM || !_contains(want, m)) return string.concat(names[r], ": an enumerated member is not expected");
                }
            }
            address[] memory known = genesisKnown;
            for (uint256 i = 0; i <= known.length; i++) {
                address k = i < known.length ? known[i] : ARACHNID_FACTORY;
                if (_contains(want, k)) continue;
                (bool ok, bool has) =
                    _readBool(timelock, abi.encodeWithSignature("hasRole(bytes32,address)", roles[r], k));
                if (ok && has) return string.concat(names[r], " is held by an account other than the expected set");
            }
        }
        return _timelockAllocCompleteness(timelock, council, cancellers);
    }

    function _expectedHolders(uint256 r, address timelock, address council, address[] memory cancellers)
        private
        pure
        returns (address[] memory want)
    {
        if (r == 3) return cancellers;
        want = new address[](1);
        want[0] = r == 0 ? timelock : council;
    }

    function _timelockAllocCompleteness(address timelock, address council, address[] memory cancellers)
        internal
        returns (string memory)
    {
        string memory path = _genesisAllocPath();
        if (bytes(path).length == 0) {
            return "genesis-chain mode needs GENESIS_ALLOC (the block-0 allocation) to prove the holder sets complete";
        }
        string memory alloc = HISTORY_VM.readFile(path);
        string memory key =
            string.concat(".alloc.", HISTORY_VM.toLowercase(HISTORY_VM.toString(timelock)), ".storage");
        if (!HISTORY_VM.keyExistsJson(alloc, key)) return "the timelock's storage is not in GENESIS_ALLOC";
        string[] memory slots = HISTORY_VM.parseJsonKeys(alloc, key);
        (bool okD, uint256 minDelay) = _readUint256(timelock, abi.encodeWithSignature("getMinDelay()"));
        if (!okD) return "cannot read getMinDelay()";
        for (uint256 i = 0; i < slots.length; i++) {
            bytes32 k = HISTORY_VM.parseBytes32(slots[i]);
            bytes32 v = HISTORY_VM.parseJsonBytes32(alloc, string.concat(key, ".", slots[i]));
            if (HISTORY_VM.load(timelock, k) != v) return "GENESIS_ALLOC disagrees with the chain's state of the timelock";
            if (v == bytes32(0)) continue;
            if (!_slotExplained(k, v, timelock, council, cancellers, minDelay)) {
                return "an unaccounted storage slot (a role holder outside the expected set, a changed role admin, or a scheduled operation)";
            }
        }
        return "";
    }

    function _slotExplained(
        bytes32 k,
        bytes32 v,
        address timelock,
        address council,
        address[] memory cancellers,
        uint256 minDelay
    ) private pure returns (bool) {
        if (k == bytes32(uint256(2))) return uint256(v) == minDelay; // TimelockController._minDelay
        if (uint256(v) != 1) return false;
        if (k == _roleSlot(DEFAULT_ADMIN_ROLE, timelock)) return true;
        if (k == _roleSlot(TIMELOCK_PROPOSER_ROLE, council)) return true;
        if (k == _roleSlot(TIMELOCK_EXECUTOR_ROLE, council)) return true;
        for (uint256 i = 0; i < cancellers.length; i++) {
            if (k == _roleSlot(TIMELOCK_CANCELLER_ROLE, cancellers[i])) return true;
        }
        return false;
    }

    function _readUint256(address target, bytes memory cd) private view returns (bool ok, uint256 value) {
        (bool success, bytes memory ret) = target.staticcall(cd);
        if (!success || ret.length != 32) return (false, 0);
        return (true, abi.decode(ret, (uint256)));
    }

    /// @notice Revert unless `_timelockHolderProblem` is empty (see there).
    function _assertTimelockSoleHolders(
        string memory name,
        address timelock,
        address council,
        address[] memory extraCancellers
    ) internal {
        string memory problem = _timelockHolderProblem(timelock, council, extraCancellers);
        require(bytes(problem).length == 0, string.concat(name, ": ", problem));
    }

    // ---- Council authentication: CREATE2 provenance of a MultisigProposer ----
    //
    // A council's getters (`timelock()`, `threshold()`, `owners()`, `isOwner()`) are only worth
    // reading once the contract is known to BE a MultisigProposer built with those values: any
    // contract can answer them (a single-signer forwarder can report 3-of-5 and `isOwner == false`
    // for every deploy account while holding the timelock's roles itself). The genesis ceremony
    // (DeployGenesisGovernance) deploys each council with `new MultisigProposer{salt}` through the
    // Arachnid factory, so its address is
    //   keccak256(0xff ++ factory ++ Salts.salt(saltName) ++ keccak256(creationCode ++ args))[12:]
    // Recomputing that from the expected timelock and the CLAIMED owners / threshold / proposalTtl, and getting
    // the council's own address back, proves the runtime code (the factory ran exactly that init
    // code there; the constructor is deterministic), the immutables (timelock, threshold, proposalTtl) and
    // the owner set the constructor stored (no function writes it afterwards). A contract that
    // lies about any of them sits at a different address.

    /// Salt-name prefix DeployGenesisGovernance gives its councils: "Genesis." + book name
    /// ("GovernanceMultisig", "GuardianMultisig").
    string internal constant GENESIS_SALT_PREFIX = "Genesis.";

    /// @notice The address the Arachnid factory gives `initCode` under `Salts.salt(saltName)`.
    function _ceremonyCreate2Address(string memory saltName, bytes memory initCode) internal pure returns (address) {
        return address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(bytes1(0xff), ARACHNID_FACTORY, Salts.salt(saltName), keccak256(initCode))
                    )
                )
            )
        );
    }

    /// @notice MultisigProposer init code for the given constructor arguments (one place, so a
    ///         constructor change is one edit here).
    function _multisigProposerInitCode(
        address timelock,
        address[] memory owners,
        uint256 threshold,
        uint256 proposalTtl
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            type(MultisigProposer).creationCode, abi.encode(timelock, owners, threshold, proposalTtl)
        );
    }

    /// @notice Empty when `multisig` is the MultisigProposer that the genesis ceremony deploys
    ///         under `saltName` for (`timelock`, its reported owners, its reported threshold, its
    ///         reported proposalTtl),
    ///         i.e. its address is that CREATE2 address and it has code. Only after this passes
    ///         are its getters the contract's real state. Never reverts on a well-formed answer;
    ///         a malformed `owners()` return reverts in decoding, which fails the caller closed.
    function _multisigProposerProblem(address multisig, address timelock, string memory saltName)
        internal
        view
        returns (string memory)
    {
        if (multisig.code.length == 0) return "no code at address";
        (bool okT, bytes memory rt) = multisig.staticcall(abi.encodeWithSignature("threshold()"));
        if (!okT || rt.length != 32) return "threshold() unreadable";
        (bool okO, bytes memory ro) = multisig.staticcall(abi.encodeWithSignature("owners()"));
        if (!okO || ro.length < 64) return "owners() unreadable";
        (bool okL, bytes memory rl) = multisig.staticcall(abi.encodeWithSignature("proposalTtl()"));
        if (!okL || rl.length != 32) return "proposalTtl() unreadable";
        address[] memory owners = abi.decode(ro, (address[]));
        uint256 threshold = abi.decode(rt, (uint256));
        uint256 ttl = abi.decode(rl, (uint256));
        if (_ceremonyCreate2Address(saltName, _multisigProposerInitCode(timelock, owners, threshold, ttl)) != multisig)
        {
            return string.concat(
                "not the MultisigProposer the ceremony deploys (",
                saltName,
                ") for this timelock, owners, threshold and proposal TTL"
            );
        }
        return "";
    }

    /// @notice Revert unless `_multisigProposerProblem` is empty (see there).
    function _assertMultisigProposer(string memory name, address multisig, address timelock, string memory saltName)
        internal
        view
    {
        string memory problem = _multisigProposerProblem(multisig, timelock, saltName);
        require(bytes(problem).length == 0, string.concat(name, ": ", problem));
    }

    /// @notice `getMinDelay()` of an OZ TimelockController. Reverts when `timelock` has none.
    function _timelockMinDelay(address timelock) internal view returns (uint256) {
        (bool ok, bytes memory ret) = timelock.staticcall(abi.encodeWithSignature("getMinDelay()"));
        require(ok && ret.length == 32, "timelock: getMinDelay() unreadable");
        return abi.decode(ret, (uint256));
    }

    /// @notice Revert if `deployer` holds any admin slot or governing seat on `target`.
    function _assertNoDeployerAdmin(string memory name, address target, address deployer) internal view {
        string memory problem = _deployerAdminProblem(target, deployer);
        require(bytes(problem).length == 0, string.concat(name, ": ", problem));
    }

    /// @notice Revert if `target` names the CREATE2 factory in any admin slot.
    function _assertNoFactoryAdmin(string memory name, address target) internal view {
        string memory problem = _factoryAdminProblem(target);
        require(bytes(problem).length == 0, string.concat(name, ": ", problem));
    }

    /// @notice Revert unless `governance()` is exactly `expected`.
    function _assertGovernance(string memory name, address target, address expected) internal view {
        _assertNoFactoryAdmin(name, target);
        (bool ok, address g) = _readAddress(target, abi.encodeWithSignature("governance()"));
        require(ok && g == expected, string.concat(name, ": governance() is not the intended key"));
    }

    /// @notice Revert unless `expected` holds DEFAULT_ADMIN_ROLE.
    function _assertAdminRole(string memory name, address target, address expected) internal view {
        _assertNoFactoryAdmin(name, target);
        (bool ok, bool has) =
            _readBool(target, abi.encodeWithSignature("hasRole(bytes32,address)", DEFAULT_ADMIN_ROLE, expected));
        require(ok && has, string.concat(name, ": intended key lacks DEFAULT_ADMIN_ROLE"));
    }

    /// @notice Revert unless `expected` holds DEFAULT_ADMIN_ROLE on `target` and NO address in
    ///         `others` does. For contracts whose initial admin is a constructor argument: checks
    ///         the actual accounts that took part in the deploy (configured deployer, the real
    ///         broadcaster, the CREATE2 factory), not only the one the script was told about.
    function _assertSoleAdminAmong(string memory name, address target, address expected, address[] memory others)
        internal
        view
    {
        _assertAdminRole(name, target, expected);
        for (uint256 i = 0; i < others.length; i++) {
            require(others[i] != expected, string.concat(name, ": intended admin is also a deploy account"));
            (bool ok, bool has) =
                _readBool(target, abi.encodeWithSignature("hasRole(bytes32,address)", DEFAULT_ADMIN_ROLE, others[i]));
            require(ok && !has, string.concat(name, ": a deploy account holds DEFAULT_ADMIN_ROLE"));
        }
    }

    /// @notice Revert unless `owner()` is exactly `expected`.
    function _assertOwner(string memory name, address target, address expected) internal view {
        _assertNoFactoryAdmin(name, target);
        (bool ok, address o) = _readAddress(target, abi.encodeWithSignature("owner()"));
        require(ok && o == expected, string.concat(name, ": owner() is not the intended key"));
    }
}
