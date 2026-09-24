// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";

interface IClassification {
    function getClearance(bytes32 user) external view returns (uint8, bool);
}
interface IMultiSig {
    function draft(
        bytes32 envelope_id, bytes32 initiator, bytes32 artifact_root,
        string calldata artifact_cid, bytes32[] calldata required_signers,
        uint8 threshold, uint64 expires_at, bytes32 corr_id
    ) external;
    function sign(bytes32 envelope_id, bytes32 signer, bytes calldata signer_sig, string calldata auth_mode) external;
    function isSignedThresholdMet(bytes32 envelope_id) external view returns (bool);
}
interface IRoleEscalation {
    function requestElevation(
        bytes32 user, bytes32 tenant, bytes32 role, uint32 duration_sec,
        bytes32 corr_id, bytes calldata reauth_proof, string calldata reauth_proof_kind
    ) external;
}

/// @title ProvisionWithMultisig — prove the real distinct-signer provisioning
///        flow on 40204: clearance check → 2-of-3 envelope drafted → two
///        DISTINCT signer keys sign → threshold met → RoleEscalation elevation.
/// @dev Env: DEPLOY_KEY (role-admin + drafter), MSIG_SIGNER1_KEY, MSIG_SIGNER2_KEY.
contract ProvisionWithMultisig is Script {
    IClassification constant CLASS = IClassification(0xd4b1680684106888b7c55d19fB236b41c192340e);
    IMultiSig constant MSE = IMultiSig(0x01f6293FEB59C5950A484F35CE4317B40d8F76be);
    IRoleEscalation constant ROLE = IRoleEscalation(0xC9B8c0bd4BDf70502095276dEE2b3f4d5da1488e);

    function run() external {
        uint256 adminKey = vm.envUint("DEPLOY_KEY");
        uint256 s1 = vm.envUint("MSIG_SIGNER1_KEY");
        uint256 s2 = vm.envUint("MSIG_SIGNER2_KEY");

        bytes32 user = keccak256("user-alice-co");
        bytes32 tenant = keccak256("scope-unit");
        bytes32 role = keccak256("role-admin");
        bytes32 env_id = keccak256("prov-msig-demo-1");
        bytes32 corr = keccak256("prov-corr-1");

        bytes32[] memory signers = new bytes32[](3);
        signers[0] = keccak256("approver-chief-eng");
        signers[1] = keccak256("approver-pm");
        signers[2] = keccak256("approver-dcma");

        // 1. Clearance check (view).
        (uint8 clr, bool fn_) = CLASS.getClearance(user);
        console2.log("clearance level:", clr, "foreign-national:", fn_);

        // 2. Draft a 2-of-3 envelope (drafter = admin).
        vm.startBroadcast(adminKey);
        MSE.draft(env_id, user, keccak256("elevation-artifact"), "ipfs://prov-msig-demo", signers, 2, 0, corr);
        vm.stopBroadcast();

        // 3. Two DISTINCT signer keys each sign a distinct identity.
        vm.startBroadcast(s1);
        MSE.sign(env_id, signers[0], hex"01", "hsm");
        vm.stopBroadcast();
        vm.startBroadcast(s2);
        MSE.sign(env_id, signers[1], hex"02", "hsm");
        vm.stopBroadcast();

        require(MSE.isSignedThresholdMet(env_id), "threshold not met");
        console2.log("threshold met: true");

        // 4. Elevation dispatch (role-admin).
        vm.startBroadcast(adminKey);
        ROLE.requestElevation(user, tenant, role, 3600, corr, hex"01", "kba");
        vm.stopBroadcast();
        console2.log("requestElevation dispatched");
    }
}
