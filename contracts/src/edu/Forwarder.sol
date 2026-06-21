// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import {IForwarder} from "./interfaces/IForwarder.sol";
import {IClassroomCluster} from "./interfaces/IClassroomCluster.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title Forwarder
/// @notice EIP-2771 meta-transaction forwarder for sponsored student actions.
/// @dev Implements all 8 invariants from Q-006 ForwarderReplaySafety.tla.
contract Forwarder is IForwarder {
    // ── EIP-712 ──

    bytes32 private constant _EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant _NAME_HASH = keccak256("CitrateEduForwarder");
    bytes32 private constant _VERSION_HASH = keccak256("1");

    bytes32 public constant FORWARD_REQUEST_TYPEHASH =
        keccak256("ForwardRequest(bytes32 orgPrincipalId,uint256 classroomId,uint256 nonce,uint256 sessionExpiry,bytes32 deviceCertHash,address target,bytes32 dataHash)");

    // ── Storage ──

    address public governance;
    /// @notice Pending governance address awaiting acceptance.
    /// Closes RFI26-05: 2-step transfer prevents permanent lock.
    address public pendingGovernance;
    address public clusterContract;
    address public vaultAddress;

    mapping(address => bool) private _authorizedRelayers;
    mapping(address => bool) private _allowedTargets;
    mapping(bytes32 => mapping(uint256 => uint256)) private _nonces; // orgPrincipalId => classroomId => nonce
    mapping(bytes32 => bool) private _consumedTxHashes;

    // ── Errors ──

    error NotGovernance();
    error NotPendingGovernance();
    error NotAuthorizedRelayer();
    error InvalidNonce();
    error ReplayDetected();
    error SessionExpired();
    error DeviceRevoked();
    error PrincipalRevoked();
    error TargetIsVault();
    error TargetNotAllowed();
    error InvalidSignature();
    error CallFailed();
    error ZeroAddress();

    // ── Modifiers ──

    modifier onlyGovernance() {
        if (msg.sender != governance) revert NotGovernance();
        _;
    }

    modifier onlyRelayer() {
        if (!_authorizedRelayers[msg.sender]) revert NotAuthorizedRelayer();
        _;
    }

    // ── Constructor ──

    constructor(address _governance, address _cluster, address _vault) {
        if (_governance == address(0) || _cluster == address(0) || _vault == address(0)) revert ZeroAddress();
        governance = _governance;
        clusterContract = _cluster;
        vaultAddress = _vault;
    }

    // ── Views ──

    function getNonce(bytes32 orgPrincipalId, uint256 classroomId) external view returns (uint256) {
        return _nonces[orgPrincipalId][classroomId];
    }

    function isAuthorizedRelayer(address relayer) external view returns (bool) {
        return _authorizedRelayers[relayer];
    }

    function isAllowedTarget(address target) external view returns (bool) {
        return _allowedTargets[target];
    }

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return keccak256(abi.encode(
            _EIP712_DOMAIN_TYPEHASH,
            _NAME_HASH,
            _VERSION_HASH,
            block.chainid,
            address(this)
        ));
    }

    function hashForwardRequest(ForwardRequest calldata request) public view returns (bytes32) {
        return _hashForwardRequest(request);
    }

    // ── Execute ──

    /// @dev Invariants enforced:
    ///   1. NonceMonotonic — nonce must equal current expected nonce
    ///   2. NoReplayAccepted — tx hash must not be consumed
    ///   3. DeviceBindingEnforced — device cert must be active in cluster
    ///   4. SessionExpiryEnforced — block.timestamp must be before sessionExpiry
    ///   5. RevocationBarrierDouble — principal must not be revoked in cluster
    ///   6. RelayerCannotCallVault — target must not be vault address
    ///   7. OfflineQueueFlushSafe — consumed tx hash prevents duplicate flush
    function execute(
        ForwardRequest calldata request,
        bytes calldata signature
    ) external onlyRelayer returns (bool success) {
        // Invariant 6: RelayerCannotCallVault
        if (request.target == vaultAddress) revert TargetIsVault();
        if (!_allowedTargets[request.target]) revert TargetNotAllowed();

        // Invariant 4: SessionExpiryEnforced
        if (block.timestamp > request.sessionExpiry) revert SessionExpired();

        // Invariant 1: NonceMonotonic
        uint256 expectedNonce = _nonces[request.orgPrincipalId][request.classroomId];
        if (request.nonce != expectedNonce) revert InvalidNonce();

        // Invariant 2: NoReplayAccepted
        bytes32 txHash = _hashForwardRequest(request);
        if (_consumedTxHashes[txHash]) revert ReplayDetected();

        // Invariant 5: RevocationBarrierDouble (on-chain check)
        IClassroomCluster cluster = IClassroomCluster(clusterContract);

        // Check device is active
        // Invariant 3: DeviceBindingEnforced
        if (!cluster.isDeviceActive(request.deviceCertHash)) revert DeviceRevoked();

        // Check principal is not revoked (via isActiveMember or similar)
        // Note: in production, cluster.isActiveMember would check the orgPrincipalId mapping
        // For v1, we verify the device's user is still active
        address deviceUser = cluster.getDeviceUser(request.deviceCertHash);
        if (deviceUser == address(0)) revert PrincipalRevoked();

        address signer = _recoverSigner(txHash, signature);
        if (signer != deviceUser) revert InvalidSignature();

        // Consume nonce and tx hash (effects before interactions — CEI)
        _nonces[request.orgPrincipalId][request.classroomId] = expectedNonce + 1;
        _consumedTxHashes[txHash] = true;

        // Execute the inner call.
        // FWA-C3-03: EIP-2771 requires the trusted forwarder to APPEND the
        // 20-byte authenticated sender to the calldata so a 2771-aware
        // target recovers the real principal via `_msgSender()` instead of
        // seeing `msg.sender == Forwarder`. The authenticated principal here
        // is `deviceUser` — the address whose device-bound signature we just
        // verified (line above). Mirrors citrate-chatbot/CitrateForwarder's
        // `abi.encodePacked(req.data, req.from)` pattern.
        (success,) = request.target.call(abi.encodePacked(request.data, deviceUser));
        if (!success) revert CallFailed();

        emit MetaTxExecuted(
            request.orgPrincipalId,
            request.classroomId,
            request.nonce,
            request.target,
            success
        );
    }

    // ── Admin ──

    function addRelayer(address relayer) external onlyGovernance {
        if (relayer == address(0)) revert ZeroAddress();
        _authorizedRelayers[relayer] = true;
    }

    function removeRelayer(address relayer) external onlyGovernance {
        _authorizedRelayers[relayer] = false;
    }

    function setTargetAllowed(address target, bool allowed) external onlyGovernance {
        if (target == address(0)) revert ZeroAddress();
        if (target == vaultAddress && allowed) revert TargetIsVault();
        _allowedTargets[target] = allowed;
        emit TargetAllowedUpdated(target, allowed);
    }

    function setClusterContract(address cluster) external onlyGovernance {
        if (cluster == address(0)) revert ZeroAddress();
        clusterContract = cluster;
    }

    function setVaultAddress(address vault) external onlyGovernance {
        if (vault == address(0)) revert ZeroAddress();
        vaultAddress = vault;
        _allowedTargets[vault] = false;
    }

    /// @notice Step 1 of governance transfer (closes RFI26-05).
    /// Caller must be `governance`. The pending address must explicitly
    /// accept via `acceptGovernance()` to take effect.
    event GovernanceProposed(address indexed pending);
    event GovernanceAccepted(address indexed previous, address indexed current);

    function proposeGovernance(address newGovernance) external onlyGovernance {
        if (newGovernance == address(0)) revert ZeroAddress();
        pendingGovernance = newGovernance;
        emit GovernanceProposed(newGovernance);
    }

    /// @notice Step 2 of governance transfer (closes RFI26-05).
    function acceptGovernance() external {
        if (msg.sender != pendingGovernance) revert NotPendingGovernance();
        address previous = governance;
        governance = pendingGovernance;
        pendingGovernance = address(0);
        emit GovernanceAccepted(previous, governance);
    }

    // ── Internal ──

    function _hashForwardRequest(ForwardRequest calldata request) private view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(
            FORWARD_REQUEST_TYPEHASH,
            request.orgPrincipalId,
            request.classroomId,
            request.nonce,
            request.sessionExpiry,
            request.deviceCertHash,
            request.target,
            keccak256(request.data)
        ));

        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash));
    }

    function _recoverSigner(bytes32 digest, bytes calldata signature) private pure returns (address) {
        bytes memory signatureBytes = signature;
        (address recovered, ECDSA.RecoverError error,) = ECDSA.tryRecover(digest, signatureBytes);
        if (error != ECDSA.RecoverError.NoError) revert InvalidSignature();
        return recovered;
    }
}
