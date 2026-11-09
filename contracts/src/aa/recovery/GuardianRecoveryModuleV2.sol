// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {IValidator, IHook} from "@kernel/interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "@kernel/interfaces/PackedUserOperation.sol";

/// @title GuardianRecoveryModuleV2 (RED SKELETON)
/// @notice Interface only, so the red suite compiles. Every entry point reverts; the
///         implementation lands in the next commit (0.6.0 W-GUARDV2).
contract GuardianRecoveryModuleV2 is IValidator, IHook {
    uint48 public constant RECOVERY_DELAY = 0;

    error AlreadyInstalled(address smartAccount);
    error InvalidInstallData();
    error InvalidGuardianCount();
    error InvalidThreshold();
    error DuplicateGuardian();
    error ZeroGuardian();
    error RecoveryActionNotAllowed();
    error InvalidGuardianSignatures();
    error NoPendingRecovery();
    error RedSkeleton();

    mapping(address smartAccount => uint64) public recoveryNonce;

    function onInstall(bytes calldata) external payable override {
        revert RedSkeleton();
    }

    function onUninstall(bytes calldata) external payable override {
        revert RedSkeleton();
    }

    function isModuleType(uint256) external pure override returns (bool) {
        revert RedSkeleton();
    }

    function isInitialized(address) external pure override returns (bool) {
        revert RedSkeleton();
    }

    function configOf(address) external pure returns (uint8, address[] memory) {
        revert RedSkeleton();
    }

    function pendingRecovery(address) external pure returns (bytes32, uint48, uint64) {
        revert RedSkeleton();
    }

    function recoveryDigest(address, bytes32, uint64) public pure returns (bytes32) {
        revert RedSkeleton();
    }

    function initiateRecovery(address, bytes calldata, bytes calldata) external pure returns (uint48) {
        revert RedSkeleton();
    }

    function cancelRecovery() external pure {
        revert RedSkeleton();
    }

    function validateUserOp(PackedUserOperation calldata, bytes32) external payable override returns (uint256) {
        revert RedSkeleton();
    }

    function isValidSignatureWithSender(address, bytes32, bytes calldata) external pure override returns (bytes4) {
        revert RedSkeleton();
    }

    function preCheck(address, uint256, bytes calldata) external payable override returns (bytes memory) {
        revert RedSkeleton();
    }

    function postCheck(bytes calldata) external payable override {
        revert RedSkeleton();
    }
}
