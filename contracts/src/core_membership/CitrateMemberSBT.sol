// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Base64.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "./MemberEmblem.sol";

/// @title CitrateMemberSBT — CORE-S5.4 (citrate-core planset 02 §5.2b)
///
/// Soulbound (non-transferable) ERC-721 membership token, cloned from
/// the AgentSBT / OrganizationSBT pattern in `src/cit_agent/`:
///   - transfers between non-zero addresses revert (`_update` override);
///     mint (from = 0) and burn (to = 0) are allowed;
///   - minting is `onlyOwner` (the core-membership grant orchestrator's
///     operator-gated signer, Rule 8);
///   - quarantine / revocation hooks mirror AgentSBT's quarantine and
///     OrganizationSBT's deactivate.
///
/// Identity binding: each token binds `keccak256(sub)` (the OIDC subject
/// from auth.citrate.ai, hashed off-chain — raw `sub` never goes on
/// chain) to exactly one tokenId, owned by the member's smart wallet.
/// One token per sub, ever: the sub-hash binding survives revocation so
/// a revoked member cannot silently receive a fresh token under the
/// same identity (see "Open design questions" below).
///
/// Parent linkage (AgentSBT mirror): AgentSBT gates minting on
/// `OrganizationSBT.isActive(parent_org_id)`. This contract exposes the
/// same parent-side surface — `isActive(uint256 tokenId)` — so a future
/// AgentSBT revision (or a member-scoped agent SBT) can store a
/// `parent_member_id` and gate on an active membership exactly the way
/// AgentSBT gates on an active org today. The child-side field lives in
/// the child contract, so no AgentSBT change is required until that WP
/// lands; this contract only has to keep `isActive`'s semantics stable.
///
/// Open design questions (natspec'd per CORE-S5.4, for governance /
/// counsel review before deployment — deployment itself is Rule-8
/// operator work and requires security sign-off + the counsel gate):
///   Q1. Should a revoked sub ever be re-mintable (e.g. after a
///       successful appeal)? Current answer: no — binding is permanent;
///       an appeal would need a governance-approved contract migration.
///   Q2. Should quarantine suspend `isActive` (current behavior) or
///       only flag the member while leaving downstream linkage intact?
///       Current behavior is the conservative fail-closed reading.
contract CitrateMemberSBT is ERC721, Ownable {
    struct Member {
        /// keccak256 of the OIDC `sub` claim (hashed off-chain).
        bytes32 subHash;
        /// Membership term start (unix seconds).
        uint64 termStart;
        /// Membership term end (unix seconds); renewals extend this.
        uint64 termEnd;
        /// Fail-closed suspension flag (AgentSBT quarantine mirror).
        bool quarantined;
        /// Permanent revocation flag; set when the token is revoked
        /// (burned). Kept in storage so history is queryable after burn.
        bool revoked;
        /// M-2.3 — KYC attestation, set by the membership orchestrator once
        /// identity verification clears.
        ///
        /// This gates MONEY OUT only. Owner decision A.7: a paid-but-unverified
        /// member keeps membership, access and their validator slot; what they
        /// cannot do is withdraw the bond or download from the commissary.
        /// `MemberBond` reads this FIRST on every value-out path, ahead of the
        /// time lock (decision A.6 — KYC supersedes every withdrawal check,
        /// even after the lock elapses).
        ///
        /// Deliberately NOT part of `isActive`: folding it in there would turn
        /// the KYC gate into a participation paywall, which A.7 forbids.
        bool kycVerified;
    }

    /// Token id → member record.
    mapping(uint256 => Member) private _members;

    /// subHash → tokenId + 1 (0 = never minted). The +1 sentinel lets
    /// tokenId 0 be distinguishable from "unbound".
    mapping(bytes32 => uint256) private _tokenIdPlusOneBySub;

    uint256 public nextTokenId;

    error TransferNotAllowed();
    error SubAlreadyBound();
    error UnknownSub();
    error UnknownToken();
    error AlreadyRevoked();
    error InvalidTerm();
    error ZeroAddress();

    event MemberMinted(
        uint256 indexed tokenId,
        address indexed member,
        bytes32 indexed subHash,
        uint64 termStart,
        uint64 termEnd
    );
    event MemberTermRenewed(uint256 indexed tokenId, uint64 newTermEnd);
    event MemberQuarantined(uint256 indexed tokenId);
    event MemberUnquarantined(uint256 indexed tokenId);
    event KycVerifiedSet(uint256 indexed tokenId, bool verified);
    event MemberRevoked(uint256 indexed tokenId, bytes32 indexed subHash);

    constructor(address initialOwner)
        ERC721("Citrate MemberSBT", "CIT-MEMBER")
        Ownable(initialOwner)
    {}

    /// Mint a membership SBT to the member's smart wallet. One token
    /// per subHash, ever (revoked bindings are not reusable — Q1).
    /// @param to        member smart-wallet address (token owner)
    /// @param subHash   keccak256 of the OIDC `sub` claim
    /// @param termStart membership term start (unix seconds)
    /// @param termEnd   membership term end (unix seconds), > termStart
    function mintMember(
        address to,
        bytes32 subHash,
        uint64 termStart,
        uint64 termEnd
    ) external onlyOwner returns (uint256 tokenId) {
        if (to == address(0)) revert ZeroAddress();
        if (termEnd <= termStart) revert InvalidTerm();
        if (_tokenIdPlusOneBySub[subHash] != 0) revert SubAlreadyBound();

        tokenId = nextTokenId++;
        _members[tokenId] = Member({
            subHash: subHash,
            termStart: termStart,
            termEnd: termEnd,
            quarantined: false,
            revoked: false,
            // Fail-closed: a freshly minted membership is unverified until the
            // orchestrator attests otherwise. Payment does not imply KYC.
            kycVerified: false
        });
        _tokenIdPlusOneBySub[subHash] = tokenId + 1;
        _safeMint(to, tokenId);
        emit MemberMinted(tokenId, to, subHash, termStart, termEnd);
    }

    /// Extend the membership term on renewal (orchestrator-driven; the
    /// membership service is the source of truth for settled payment).
    function renewTerm(uint256 tokenId, uint64 newTermEnd) external onlyOwner {
        Member storage m = _requireMember(tokenId);
        if (m.revoked) revert AlreadyRevoked();
        if (newTermEnd <= m.termEnd) revert InvalidTerm();
        m.termEnd = newTermEnd;
        emit MemberTermRenewed(tokenId, newTermEnd);
    }

    /// Fail-closed suspension (AgentSBT quarantine mirror). Off-chain
    /// twin: the membership service audit chain's quarantine entry.
    function quarantine(uint256 tokenId) external onlyOwner {
        Member storage m = _requireMember(tokenId);
        m.quarantined = true;
        emit MemberQuarantined(tokenId);
    }

    function unquarantine(uint256 tokenId) external onlyOwner {
        Member storage m = _requireMember(tokenId);
        m.quarantined = false;
        emit MemberUnquarantined(tokenId);
    }

    /// Permanent revocation: burns the token and marks the record
    /// revoked. The subHash binding is kept, so the same identity can
    /// never be re-minted (Q1). Triggers: KYC loss, refund-after-grant
    /// (06 §1 T6), terms violation — all orchestrator-adjudicated.
    function revoke(uint256 tokenId) external onlyOwner {
        Member storage m = _requireMember(tokenId);
        if (m.revoked) revert AlreadyRevoked();
        m.revoked = true;
        _burn(tokenId);
        emit MemberRevoked(tokenId, m.subHash);
    }

    // ── Views ──────────────────────────────────────────────────────

    function getMember(uint256 tokenId) external view returns (Member memory) {
        return _members[_requireMinted(tokenId)];
    }

    /// On-chain, deterministic ERC-721 metadata (WS-2). Returns a
    /// `data:application/json;base64,…` document embedding a
    /// `data:image/svg+xml;base64,…` emblem generated wholly on-chain from the
    /// token owner's wallet address via `MemberEmblem` — an EXACT port of
    /// citrate-core's `sbtArt.ts`, so the explorer emblem is byte-identical to
    /// the in-app one. No IPFS, no baseURI, no placeholder (Rule 1): the seed
    /// is the owner address itself, so parity is structural, not configured.
    ///
    /// Reverts (ERC721NonexistentToken via `_requireOwned`) for unminted or
    /// burned/revoked tokens — there is no empty/placeholder URI path.
    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        address owner = _requireOwned(tokenId);
        Member storage m = _members[tokenId];

        (string memory svg, uint256 palIdx) = MemberEmblem.render(owner);

        string memory image = string(
            abi.encodePacked(
                "data:image/svg+xml;base64,",
                Base64.encode(bytes(svg))
            )
        );

        string memory json = string(
            abi.encodePacked(
                '{"name":"Citrate MemberSBT #',
                Strings.toString(tokenId),
                '","description":"Soulbound Citrate membership token. The emblem is generated deterministically on-chain from the member wallet address (no IPFS, no external image) and matches the in-app identity mark.","image":"',
                image,
                '","attributes":[',
                _attributes(owner, m, palIdx),
                "]}"
            )
        );

        return string(
            abi.encodePacked(
                "data:application/json;base64,",
                Base64.encode(bytes(json))
            )
        );
    }

    /// The metadata attribute array (member fields + emblem seed params).
    function _attributes(address owner, Member storage m, uint256 palIdx)
        private
        view
        returns (string memory)
    {
        return string(
            abi.encodePacked(
                '{"trait_type":"Wallet","value":"',
                Strings.toHexString(owner),
                '"},{"trait_type":"Sub Hash","value":"',
                Strings.toHexString(uint256(m.subHash), 32),
                '"},{"trait_type":"Term Start","display_type":"date","value":',
                Strings.toString(uint256(m.termStart)),
                '},{"trait_type":"Term End","display_type":"date","value":',
                Strings.toString(uint256(m.termEnd)),
                '},{"trait_type":"Palette","value":"',
                Strings.toString(palIdx),
                '"}'
            )
        );
    }

    /// Look up the tokenId bound to a subHash. Reverts for unbound subs.
    function tokenIdForSub(bytes32 subHash) external view returns (uint256) {
        uint256 plusOne = _tokenIdPlusOneBySub[subHash];
        if (plusOne == 0) revert UnknownSub();
        return plusOne - 1;
    }

    /// M-2.3 — record (or withdraw) the KYC attestation for a membership.
    ///
    /// Orchestrator-driven: the membership service holds the verification
    /// result. Revocable in both directions on purpose — if a verification is
    /// later invalidated, the money-out gate must close again, and
    /// `MemberBond` re-reads this on every value-out path rather than caching
    /// it at release time.
    function setKycVerified(uint256 tokenId, bool verified) external onlyOwner {
        Member storage m = _requireMember(tokenId);
        if (m.revoked) revert AlreadyRevoked();
        m.kycVerified = verified;
        emit KycVerifiedSet(tokenId, verified);
    }

    /// True iff this membership carries a live KYC attestation.
    ///
    /// Fail-closed on a revoked or quarantined membership: money must not
    /// leave for a member whose standing has lapsed, whatever the flag says.
    function isKycVerified(uint256 tokenId) external view returns (bool) {
        Member storage m = _members[tokenId];
        return m.kycVerified && !m.revoked && !m.quarantined;
    }

    /// True if a subHash has ever been bound (including revoked ones).
    function isSubBound(bytes32 subHash) external view returns (bool) {
        return _tokenIdPlusOneBySub[subHash] != 0;
    }

    /// Parent-linkage surface (OrganizationSBT.isActive mirror): a
    /// membership is active iff the token exists (not revoked/burned),
    /// is not quarantined, and the current time is inside the term.
    /// Future member-parented SBTs gate their mints on this, exactly
    /// as AgentSBT.mintAgent gates on OrganizationSBT.isActive.
    function isActive(uint256 tokenId) external view returns (bool) {
        Member storage m = _members[tokenId];
        return _ownerOf(tokenId) != address(0)
            && !m.revoked
            && !m.quarantined
            && block.timestamp >= m.termStart
            && block.timestamp <= m.termEnd;
    }

    // ── Internal helpers ───────────────────────────────────────────

    function _requireMember(uint256 tokenId) internal view returns (Member storage m) {
        m = _members[tokenId];
        // A member record exists iff the token was minted at some point
        // (termEnd is always > 0 for minted records).
        if (m.termEnd == 0) revert UnknownToken();
    }

    function _requireMinted(uint256 tokenId) internal view returns (uint256) {
        if (_members[tokenId].termEnd == 0) revert UnknownToken();
        return tokenId;
    }

    // ── Soulbound enforcement (AgentSBT pattern, verbatim) ─────────

    /// Overrides ERC721's `_update` to block transfers between
    /// non-zero addresses. Mint (from = 0) and burn (to = 0) are
    /// allowed; transfers revert.
    function _update(address to, uint256 tokenId, address auth)
        internal
        override
        returns (address)
    {
        address from = _ownerOf(tokenId);
        if (from != address(0) && to != address(0)) {
            revert TransferNotAllowed();
        }
        return super._update(to, tokenId, auth);
    }
}
