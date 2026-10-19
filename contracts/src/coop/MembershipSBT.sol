// ── VENDORED: DO NOT EDIT. Change upstream, then re-vendor with a new header. ─────
// Source:    citrate-coop/contracts/src/MembershipSBT.sol (BUSL-1.1, licensor Citrate Inc.)
// Upstream:  Citrate-Labs metarepo working tree, where citrate-coop is tracked
//            (audit LAB-B-010; coop remote git@github.com:CitrateNetwork/citrate-coop.git),
//            labs main 2206a47ddc56542dd6fdc4d53f6f0cf411eb86d4, copied 2026-10-18.
// Integrity: every line after this 10-line header is byte-identical to upstream:
//            `tail -n +11 <this file> | sha256sum` == a00f20c9a180df3d1c23282d4989a2259dc3baeee00576709b5cc21b9cb6773e
// Why:       C2 D9 / C4: PatronageLedger is deployed dormant at betanet genesis by the
//            citrate-chain ceremony (script/DeployDormantLedgers.s.sol).
// ───────────────────────────────────────────────────────────────────────────────────
// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "./lib/Auth.sol";

/// @notice The KYC oracle the IDP authority mirrors on-chain.
interface IKYCRegistry {
    function isVerified(address account) external view returns (bool);
    function identityOf(address account) external view returns (bytes32);
}

/// @title MembershipSBT — soulbound cooperative membership (RFC-CIT-COOP-0001)
/// @notice The MEMBERSHIP rail. One soulbound (ERC-5192) token per KYC identity,
///         one vote each. Worker-members must hold >= 51% of the votes (AB 816).
///         This is governance identity only — it carries NO economic weight
///         (patronage lives in PatronageLedger). See ADR-0001, ADR-0002, ADR-0005.
/// @dev Formal: specs/tla/coop/MembershipVoting.tla. Feature: features/coop_membership.feature.
contract MembershipSBT is Auth {
    bytes32 public constant REGISTRAR_ROLE = keccak256("REGISTRAR_ROLE");

    enum MemberClass { None, Worker, Investor }

    struct Member {
        bytes32 kycIdentity;
        uint64 joinedAt;
        MemberClass class;
        bytes32[] agentIds;
    }

    IKYCRegistry public immutable kyc;
    bytes32[] public projectModelIds;

    uint256 private _nextTokenId = 1;
    uint256 private _workerCount;
    uint256 private _memberCount;

    mapping(address => uint256) public tokenOf;      // member => tokenId (0 = none)
    mapping(uint256 => address) public ownerOf;      // tokenId => member
    mapping(bytes32 => bool) public identityUsed;    // kyc identity => has a seat
    mapping(address => Member) private _members;

    event MemberAdmitted(address indexed member, uint256 indexed tokenId, MemberClass class, bytes32 kycIdentity);
    event MemberExpelled(address indexed member, uint256 indexed tokenId);
    event Locked(uint256 tokenId); // ERC-5192

    error AlreadyMember();
    error IdentityAlreadySeated();
    error NotKycVerified();
    error WorkerMajorityViolated();
    error SoulboundLocked();
    error NotAMember();

    constructor(address kycRegistry, bytes32[] memory modelIds) {
        kyc = IKYCRegistry(kycRegistry);
        projectModelIds = modelIds;
        _grant(REGISTRAR_ROLE, msg.sender);
    }

    // --- minting / membership ---

    /// @notice Mint a soulbound membership token. One per KYC identity; KYC-gated;
    ///         worker-control (>=51%) enforced when admitting a community investor.
    function mint(address to, MemberClass class_, bytes32[] calldata agentIds)
        external
        onlyRole(REGISTRAR_ROLE)
        returns (uint256 tokenId)
    {
        if (class_ == MemberClass.None) revert NotAMember();
        if (tokenOf[to] != 0) revert AlreadyMember();
        if (!kyc.isVerified(to)) revert NotKycVerified();

        bytes32 id = kyc.identityOf(to);
        if (identityUsed[id]) revert IdentityAlreadySeated();

        // Worker control: after this admission, workers must be >= 51% of members.
        uint256 newWorkers = class_ == MemberClass.Worker ? _workerCount + 1 : _workerCount;
        uint256 newTotal = _memberCount + 1;
        if (newWorkers * 100 < 51 * newTotal) revert WorkerMajorityViolated();

        tokenId = _nextTokenId++;
        tokenOf[to] = tokenId;
        ownerOf[tokenId] = to;
        identityUsed[id] = true;
        _members[to] = Member({kycIdentity: id, joinedAt: uint64(block.timestamp), class: class_, agentIds: agentIds});
        _workerCount = newWorkers;
        _memberCount = newTotal;

        emit MemberAdmitted(to, tokenId, class_, id);
        emit Locked(tokenId);
    }

    /// @notice Expel a member (governance, for cause). Frees the seat and identity.
    function expel(address member) external onlyRole(REGISTRAR_ROLE) {
        uint256 tokenId = tokenOf[member];
        if (tokenId == 0) revert NotAMember();
        Member storage m = _members[member];
        if (m.class == MemberClass.Worker) _workerCount -= 1;
        _memberCount -= 1;
        identityUsed[m.kycIdentity] = false;
        delete ownerOf[tokenId];
        delete tokenOf[member];
        delete _members[member];
        emit MemberExpelled(member, tokenId);
    }

    // --- ERC-5192 soulbound: every token is permanently locked ---

    function locked(uint256) external pure returns (bool) {
        return true;
    }

    function transferFrom(address, address, uint256) external pure {
        revert SoulboundLocked();
    }

    function safeTransferFrom(address, address, uint256) external pure {
        revert SoulboundLocked();
    }

    function approve(address, uint256) external pure {
        revert SoulboundLocked();
    }

    function setApprovalForAll(address, bool) external pure {
        revert SoulboundLocked();
    }

    // --- views ---

    function isMember(address a) public view returns (bool) {
        return tokenOf[a] != 0;
    }

    function memberClass(address a) external view returns (MemberClass) {
        return _members[a].class;
    }

    function identityOf(address a) external view returns (bytes32) {
        return _members[a].kycIdentity;
    }

    function agentIdsOf(address a) external view returns (bytes32[] memory) {
        return _members[a].agentIds;
    }

    function workerCount() external view returns (uint256) {
        return _workerCount;
    }

    function memberCount() external view returns (uint256) {
        return _memberCount;
    }

    function balanceOf(address a) external view returns (uint256) {
        return tokenOf[a] == 0 ? 0 : 1;
    }
}
