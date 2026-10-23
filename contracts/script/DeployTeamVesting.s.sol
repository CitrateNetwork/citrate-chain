// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";
import "./Salts.sol";
import "./lib/AdminChecks.sol";
import "./lib/Create2Deploy.sol";
import "./lib/GenesisBook.sol";
import "./lib/GenesisProfile.sol";
import {TeamVestingWallet} from "../src/genesis/TeamVestingWallet.sol";

/// @title DeployTeamVesting: one funded OZ VestingWalletCliff per team holder (C2 D2 / G2)
/// @notice Reads the schedule from the JSON file in TEAM_VESTING_FILE (no amounts live in
///         this repo) and, per entry, deploys `TeamVestingWallet{salt: "TeamVesting.<label>"}`
///         and funds it with native SALT. Writes a book-shaped JSON to TEAM_VESTING_OUT.
///
///         Input (TEAM_VESTING_FILE; must sit under ./genesis, see foundry.toml):
///           {"wallets":[
///             {"label":"team_a", "beneficiary":"0x…", "start":1798761600,
///              "duration":126144000, "cliff":31536000, "amount":"1000000000000000000000"}
///           ]}
///         `start` is a unix timestamp; `duration` and `cliff` are seconds from `start`;
///         `amount` is wei of native SALT (a decimal string, so no JSON number precision
///         is lost). Labels are 1..32 of [A-Za-z0-9_], unique, and part of the CREATE2
///         salt ("TeamVesting.<label>"); the output book names each wallet
///         "TeamVesting_<label>" (a JSON-path-safe key for CheckDeployedAdmins).
///
///         Required env: TEAM_VESTING_FILE, TEAM_VESTING_OUT, and CEREMONY_DEPLOYER_ADDRESS
///         or DEPLOYER_ADDRESS (must equal the forge signer, which pays the total; enforced).
///
///         Fail closed on signer mismatch: the account Forge actually broadcasts as must be
///         the configured deployer, or the script reverts before deploying or funding
///         anything; no beneficiary may be that broadcaster either.
///
///         Checks before broadcasting, per entry: beneficiary nonzero and not the deployer,
///         start > 0, start not before the deploy block's timestamp (unless
///         ALLOW_PAST_VESTING_START=1, off unless set), duration > 0, cliff <= duration,
///         amount > 0, label unique. Re-runnable:
///         a live wallet is reused and topped up only to `amount` (balance + released);
///         a wallet already holding more than `amount` fails the run.
contract DeployTeamVesting is ScriptEnv, AdminChecks, Create2Deploy, GenesisBook, GenesisProfile {
    struct Grant {
        string label;
        address beneficiary;
        uint64 start;
        uint64 duration;
        uint64 cliff;
        uint256 amount;
    }

    function run() external returns (address[] memory wallets) {
        address deployer = deployerAddress();
        Grant[] memory grants = parseGrants(vm.readFile(vm.envString("TEAM_VESTING_FILE")));
        vm.envString("TEAM_VESTING_OUT"); // resolve before broadcasting: a missing path fails first
        bool allowPastStart = envUintOr("ALLOW_PAST_VESTING_START", 0) == 1;
        wallets = deployWith(deployer, grants, allowPastStart);
        _writeBook("TEAM_VESTING_OUT", bookJson(deployer, grants, wallets));
    }

    /// @notice Parse the `wallets` array of a schedule file.
    function parseGrants(string memory json) public view returns (Grant[] memory grants) {
        uint256 n = 0;
        while (vm.keyExistsJson(json, string.concat(".wallets[", vm.toString(n), "]"))) n++;
        require(n > 0, "TEAM_VESTING_FILE: no wallets");
        grants = new Grant[](n);
        for (uint256 i = 0; i < n; i++) {
            string memory k = string.concat(".wallets[", vm.toString(i), "].");
            grants[i] = Grant({
                label: vm.parseJsonString(json, string.concat(k, "label")),
                beneficiary: vm.parseJsonAddress(json, string.concat(k, "beneficiary")),
                start: _u64(vm.parseJsonUint(json, string.concat(k, "start"))),
                duration: _u64(vm.parseJsonUint(json, string.concat(k, "duration"))),
                cliff: _u64(vm.parseJsonUint(json, string.concat(k, "cliff"))),
                amount: vm.parseJsonUint(json, string.concat(k, "amount"))
            });
        }
    }

    /// @notice The ceremony with explicit inputs (no env reads), for tests and callers.
    /// @param allowPastStart accept a `start` before `block.timestamp` (ALLOW_PAST_VESTING_START=1).
    function deployWith(address deployer, Grant[] memory grants, bool allowPastStart)
        public
        returns (address[] memory wallets)
    {
        require(deployer != address(0), "deployer must be set");
        // Node chain id vs simulated chain id (GenesisProfile): the book records block.chainid.
        _resolveChainProfile(false);
        require(grants.length > 0, "no vesting grants");
        if (allowPastStart) console.log("WARNING: ALLOW_PAST_VESTING_START=1, past start timestamps accepted");
        uint256 total = 0;
        for (uint256 i = 0; i < grants.length; i++) {
            _validate(grants[i], deployer, allowPastStart);
            for (uint256 j = i + 1; j < grants.length; j++) {
                require(
                    keccak256(bytes(grants[i].label)) != keccak256(bytes(grants[j].label)),
                    string.concat("duplicate label ", grants[i].label)
                );
            }
            total += grants[i].amount;
        }
        console.log("=== Team vesting (C2 D2) ===");
        console.log("Deployer:", deployer);
        console.log("Wallets:", grants.length);
        console.log("Total (wei):", total);

        wallets = new address[](grants.length);
        // Refuses to deploy or fund anything unless the forge signer is the configured deployer.
        address broadcaster = _startBroadcastAsDeployer(deployer);
        for (uint256 i = 0; i < grants.length; i++) {
            require(
                grants[i].beneficiary != broadcaster, string.concat(grants[i].label, ": beneficiary is the broadcaster")
            );
        }
        for (uint256 i = 0; i < grants.length; i++) {
            wallets[i] = _deployAndFund(grants[i]);
        }
        vm.stopBroadcast();

        for (uint256 i = 0; i < grants.length; i++) {
            _assertWallet(grants[i], wallets[i], deployer);
            _assertNoDeployerAdmin(_salted(grants[i]), wallets[i], broadcaster);
            console.log(string.concat("TeamVesting.", grants[i].label, ":"), wallets[i]);
        }
    }

    function bookJson(address deployer, Grant[] memory grants, address[] memory wallets)
        public
        view
        returns (string memory)
    {
        string[] memory names = new string[](grants.length);
        uint256 total = 0;
        for (uint256 i = 0; i < grants.length; i++) {
            names[i] = string.concat("TeamVesting_", grants[i].label);
            total += grants[i].amount;
        }
        string memory params =
            string.concat('"wallets":', vm.toString(grants.length), ',"totalWei":"', vm.toString(total), '"');
        return _bookJson(deployer, names, wallets, params);
    }

    function _salted(Grant memory g) internal pure returns (string memory) {
        return string.concat("TeamVesting.", g.label);
    }

    function _deployAndFund(Grant memory g) internal returns (address w) {
        string memory name = _salted(g);
        bytes memory init = abi.encodePacked(
            type(TeamVestingWallet).creationCode, abi.encode(g.beneficiary, g.start, g.duration, g.cliff)
        );
        w = _isLive(name, init)
            ? _create2Address(name, init)
            : address(new TeamVestingWallet{salt: Salts.salt(name)}(g.beneficiary, g.start, g.duration, g.cliff));
        uint256 held = w.balance + TeamVestingWallet(payable(w)).released();
        require(held <= g.amount, string.concat(name, ": already holds more than its amount"));
        if (held < g.amount) {
            (bool ok,) = payable(w).call{value: g.amount - held}("");
            require(ok, string.concat(name, ": funding transfer failed"));
        }
    }

    function _validate(Grant memory g, address deployer, bool allowPastStart) internal view {
        bytes memory l = bytes(g.label);
        require(l.length != 0 && l.length <= 32, "label must be 1..32 characters");
        for (uint256 i = 0; i < l.length; i++) {
            bytes1 ch = l[i];
            bool ok = (ch >= "a" && ch <= "z") || (ch >= "A" && ch <= "Z") || (ch >= "0" && ch <= "9") || ch == "_";
            require(ok, "label may hold only [A-Za-z0-9_]");
        }
        require(g.beneficiary != address(0), string.concat(g.label, ": zero beneficiary"));
        require(g.beneficiary != deployer, string.concat(g.label, ": beneficiary is the deployer"));
        require(g.start != 0, string.concat(g.label, ": start must be set"));
        require(
            allowPastStart || g.start >= block.timestamp,
            string.concat(g.label, ": start is in the past (ALLOW_PAST_VESTING_START=1 to allow)")
        );
        require(g.duration != 0, string.concat(g.label, ": duration must be > 0"));
        require(g.cliff <= g.duration, string.concat(g.label, ": cliff exceeds duration"));
        require(g.amount != 0, string.concat(g.label, ": amount must be > 0"));
    }

    function _assertWallet(Grant memory g, address w, address deployer) internal view {
        string memory name = _salted(g);
        _assertOwner(name, w, g.beneficiary);
        _assertNoDeployerAdmin(name, w, deployer);
        TeamVestingWallet v = TeamVestingWallet(payable(w));
        require(v.start() == g.start, string.concat(name, ": start mismatch"));
        require(v.duration() == g.duration, string.concat(name, ": duration mismatch"));
        require(v.cliff() == uint256(g.start) + g.cliff, string.concat(name, ": cliff mismatch"));
        require(w.balance + v.released() == g.amount, string.concat(name, ": not funded to its amount"));
    }

    function _u64(uint256 x) internal pure returns (uint64) {
        require(x <= type(uint64).max, "value exceeds uint64");
        return uint64(x);
    }
}
