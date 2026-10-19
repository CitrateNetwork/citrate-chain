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
///         Fail closed on signer mismatch: the account Forge actually broadcasts as must be
///           the configured deployer (CEREMONY_DEPLOYER_ADDRESS / DEPLOYER_ADDRESS), or the
///           script reverts before sending anything. Postconditions then check, on the live
///           ledger, that GOVERNANCE_TIMELOCK is admin and that none of {configured deployer,
///           actual broadcaster, CREATE2 factory, this script} holds DEFAULT_ADMIN_ROLE.
///
///         Required env: GOVERNANCE_TIMELOCK (an OZ TimelockController, e.g. the
///         GovernanceTimelock from DeployGenesisGovernance), PATRONAGE_KYC_REGISTRY and
///         PATRONAGE_MEMBERSHIP (the KYC registry and membership contract PatronageLedger
///         reads; both immutable, both must have code), DORMANT_LEDGERS_OUT, and
///         CEREMONY_DEPLOYER_ADDRESS or DEPLOYER_ADDRESS (must equal the forge
///         broadcast signer; enforced).
contract DeployDormantLedgers is ScriptEnv, AdminChecks, Create2Deploy, GenesisBook {
    string internal constant FRL = "FederatedRoundLedger";

    struct Deployed {
        address federatedRoundLedger;
        address patronageLedger;
    }

    function run() external returns (Deployed memory d) {
        address deployer = deployerAddress();
        address governance = vm.envAddress("GOVERNANCE_TIMELOCK");
        address kyc = vm.envAddress("PATRONAGE_KYC_REGISTRY");
        address membership = vm.envAddress("PATRONAGE_MEMBERSHIP");
        vm.envString("DORMANT_LEDGERS_OUT"); // resolve before broadcasting: a missing path fails first
        d = deployWith(deployer, governance, kyc, membership);
        _writeBook("DORMANT_LEDGERS_OUT", bookJson(deployer, governance, d));
    }

    /// @notice The ceremony with explicit inputs (no env reads), for tests and callers.
    function deployWith(address deployer, address governance, address kyc, address membership)
        public
        returns (Deployed memory d)
    {
        require(deployer != address(0), "deployer must be set");
        require(governance != deployer, "GOVERNANCE_TIMELOCK cannot be the deployer");
        require(_isTimelock(governance), "GOVERNANCE_TIMELOCK is not a TimelockController");
        require(kyc.code.length != 0, "PATRONAGE_KYC_REGISTRY has no code on this chain");
        require(membership.code.length != 0, "PATRONAGE_MEMBERSHIP has no code on this chain");

        console.log("=== Dormant ledgers (C2 D9) ===");
        console.log("Deployer:", deployer);
        console.log("Governance timelock:", governance);

        vm.startBroadcast();
        // The account Forge signs with is chosen by CLI flags (--sender / --private-key /
        // --account), not by DEPLOYER_ADDRESS. Every postcondition and the address-book gate are
        // phrased in terms of the configured deployer, so a different broadcaster would escape
        // them: refuse to send anything unless the two agree.
        (, address broadcaster,) = vm.readCallers();
        require(broadcaster == deployer, "broadcast sender is not the configured deployer (DEPLOYER_ADDRESS)");
        bytes memory frlInit = type(FederatedRoundLedger).creationCode;
        d.federatedRoundLedger = _isLive(FRL, frlInit)
            ? _create2Address(FRL, frlInit)
            : address(new FederatedRoundLedger{salt: Salts.salt(FRL)}());

        // GOVERNANCE_TIMELOCK is the explicit initial admin: nothing to hand over or revoke.
        d.patronageLedger = address(new PatronageLedger(kyc, membership, governance));
        vm.stopBroadcast();

        _assertDormant(d, deployer, broadcaster, governance, kyc, membership);
        console.log("FederatedRoundLedger:", d.federatedRoundLedger);
        console.log("PatronageLedger     :", d.patronageLedger);
    }

    function bookJson(address deployer, address governance, Deployed memory d) public view returns (string memory) {
        string[] memory names = new string[](2);
        address[] memory addrs = new address[](2);
        (names[0], addrs[0]) = ("FederatedRoundLedger", d.federatedRoundLedger);
        (names[1], addrs[1]) = ("PatronageLedger", d.patronageLedger);
        return _bookJson(deployer, names, addrs, string.concat('"governance":"', vm.toString(governance), '"'));
    }

    function _isTimelock(address a) internal view returns (bool) {
        if (a.code.length == 0) return false;
        (bool ok, bytes memory ret) = a.staticcall(abi.encodeWithSignature("getMinDelay()"));
        return ok && ret.length == 32;
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
