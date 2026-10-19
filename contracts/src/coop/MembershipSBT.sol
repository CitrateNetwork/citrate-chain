// ── VENDORED: DO NOT EDIT. Change upstream, then re-vendor with a new header. ─────
// Source:    CitrateNetwork/citrate-coop contracts/src/MembershipSBT.sol
// Upstream:  github.com/CitrateNetwork/citrate-coop @ 07b7f5768b5403b3e6bdffdf6eac67a831847916
//            (main, squash-merge of citrate-coop #5), re-vendored 2026-10-19.
// Includes:  PBA R2 remediation (citrate-coop #3), Apache-2.0 relicense, explicit initial admin/registrar, role-holder validation.
// Integrity: every line after this 10-line header is byte-identical to upstream:
//            `tail -n +11 <this file> | sha256sum` == b3f73e20e2f6286388e3b7262a410df283277b4ba8ed6776032b8bd6f37590cb
// Why:       C2 D9 / C4: deployed dormant at betanet genesis by the citrate-chain
//            ceremony (script/DeployDormantLedgers.s.sol).
// ───────────────────────────────────────────────────────────────────────────────────
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "./lib/Auth.sol";

/// @notice PBA-L2-040 (COOP-02): told when a member is expelled so vote-weight state (delegation)
///         never outlives the seat. The CooperativeGovernor implements it.
interface IExpelHook {
    function onMemberExpelled(address member) external;
}

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

    /// PBA-L2-040 (COOP-02): the governor, notified on expel. Set once by the admin (the factory).
    address public governanceHook;

    event MemberAdmitted(address indexed member, uint256 indexed tokenId, MemberClass class, bytes32 kycIdentity);
    event MemberExpelled(address indexed member, uint256 indexed tokenId);
    event Locked(uint256 tokenId); // ERC-5192

    error AlreadyMember();
    error IdentityAlreadySeated();
    error NotKycVerified();
    error WorkerMajorityViolated();
    error SoulboundLocked();
    error NotAMember();
    error HookAlreadySet();
    error ZeroHook();

    /// @param initialAdmin     sole initial DEFAULT_ADMIN_ROLE holder (see Auth)
    /// @param initialRegistrar sole initial REGISTRAR_ROLE holder (bootstrap onboarding). Explicit —
    ///                         never `msg.sender` — for the same reason as the admin.
    constructor(address kycRegistry, bytes32[] memory modelIds, address initialAdmin, address initialRegistrar)
        Auth(initialAdmin)
    {
        _requireHolder(initialRegistrar);
        kyc = IKYCRegistry(kycRegistry);
        projectModelIds = modelIds;
        _grantAs(REGISTRAR_ROLE, initialRegistrar, address(0)); // construction-time grant (see Auth)
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

    /// @notice Wire the governance hook (one-shot; the factory does it before handing admin over).
    function setGovernanceHook(address hook) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (governanceHook != address(0)) revert HookAlreadySet();
        if (hook == address(0)) revert ZeroHook();
        governanceHook = hook;
    }

    /// @notice Expel a member (governance, for cause). Frees the seat and identity.
    /// @dev PBA-L2-040: (COOP-03/B-014) re-checks the AB 816 >= 51% worker share, which mint enforced
    ///      but expel did not; (COOP-02) notifies the governor so the member's delegation is cleared.
    function expel(address member) external onlyRole(REGISTRAR_ROLE) {
        uint256 tokenId = tokenOf[member];
        if (tokenId == 0) revert NotAMember();
        Member storage m = _members[member];
        uint256 newWorkers = m.class == MemberClass.Worker ? _workerCount - 1 : _workerCount;
        uint256 newTotal = _memberCount - 1;
        if (newWorkers * 100 < 51 * newTotal) revert WorkerMajorityViolated();
        _workerCount = newWorkers;
        _memberCount = newTotal;
        identityUsed[m.kycIdentity] = false;
        delete ownerOf[tokenId];
        delete tokenOf[member];
        delete _members[member];
        emit MemberExpelled(member, tokenId);
        if (governanceHook != address(0)) IExpelHook(governanceHook).onMemberExpelled(member);
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

    /// @notice The id the next admitted member will get (ids only grow). The governor snapshots it
    ///         at propose: only members seated before the proposal may vote on it (PBA-L2-040 B-014).
    function nextTokenId() external view returns (uint256) {
        return _nextTokenId;
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
