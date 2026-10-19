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
///           deployer, NOT CREATE2. Its `Auth` constructor grants DEFAULT_ADMIN_ROLE to
///           `msg.sender`, which under a salted deploy is the Arachnid factory (the
///           PBA-L2-002 orphaning). Under CREATE the deployer is admin; the script then
///           grants DEFAULT_ADMIN_ROLE to GOVERNANCE_TIMELOCK and revokes its own. No
///           SETTLER / COOP / LEDGER_YEAR_KEEPER role is granted to anyone. Its address
///           therefore depends on the deployer nonce, and every run deploys a new instance:
///           take the address from DORMANT_LEDGERS_OUT, do not re-run to "reuse".
///
///         Required env: GOVERNANCE_TIMELOCK (an OZ TimelockController, e.g. the
///         GovernanceTimelock from DeployGenesisGovernance), PATRONAGE_KYC_REGISTRY and
///         PATRONAGE_MEMBERSHIP (the KYC registry and membership contract PatronageLedger
///         reads; both immutable, both must have code), DORMANT_LEDGERS_OUT, and
///         CEREMONY_DEPLOYER_ADDRESS or DEPLOYER_ADDRESS (the forge signer).
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
        bytes memory frlInit = type(FederatedRoundLedger).creationCode;
        d.federatedRoundLedger = _isLive(FRL, frlInit)
            ? _create2Address(FRL, frlInit)
            : address(new FederatedRoundLedger{salt: Salts.salt(FRL)}());

        PatronageLedger ledger = new PatronageLedger(kyc, membership);
        ledger.grantRole(ledger.DEFAULT_ADMIN_ROLE(), governance);
        ledger.revokeRole(ledger.DEFAULT_ADMIN_ROLE(), deployer);
        d.patronageLedger = address(ledger);
        vm.stopBroadcast();

        _assertDormant(d, deployer, governance, kyc, membership);
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

    function _assertDormant(Deployed memory d, address deployer, address governance, address kyc, address membership)
        internal
        view
    {
        require(d.federatedRoundLedger.code.length != 0, "FederatedRoundLedger: no code");
        _assertNoFactoryAdmin("FederatedRoundLedger", d.federatedRoundLedger);
        _assertNoDeployerAdmin("FederatedRoundLedger", d.federatedRoundLedger, deployer);

        PatronageLedger ledger = PatronageLedger(d.patronageLedger);
        _assertAdminRole("PatronageLedger", d.patronageLedger, governance);
        _assertNoDeployerAdmin("PatronageLedger", d.patronageLedger, deployer);
        require(address(ledger.kyc()) == kyc, "PatronageLedger: kyc mismatch");
        require(address(ledger.membership()) == membership, "PatronageLedger: membership mismatch");
        bytes32[3] memory ops = [ledger.SETTLER_ROLE(), ledger.COOP_ROLE(), ledger.YEAR_KEEPER_ROLE()];
        for (uint256 i = 0; i < 3; i++) {
            require(
                !ledger.hasRole(ops[i], deployer) && !ledger.hasRole(ops[i], governance),
                "PatronageLedger: an operational role is wired (not dormant)"
            );
        }
        require(ledger.totalUnits() == 0, "PatronageLedger: not empty");
    }
}
