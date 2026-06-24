// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./interfaces/IERC3009.sol";
import "./lib/ReentrancyGuard.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title WrappedSALT (wSALT)
/// @notice ERC-20 wrapper around native SALT with EIP-3009 transferWithAuthorization support.
/// @dev Enables gasless, authorized token transfers for x402 payment flows.
///
/// Permit2 compatibility roadmap:
///   - wSALT can be integrated with Uniswap Permit2 for unified approval management.
///   - The EIP-712 domain and nonce scheme are designed to coexist with Permit2 signatures.
///   - Future: add `permit()` (EIP-2612) for single-tx approve-and-transfer patterns.
contract WrappedSALT is IERC3009, ReentrancyGuard {
    string public constant name = "Wrapped SALT";
    string public constant symbol = "wSALT";
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    // EIP-3009 authorization state: authorizer => nonce => used
    mapping(address => mapping(bytes32 => bool)) private _authorizationStates;

    // EIP-712 domain separator (computed at deployment, includes chainId + address)
    /// RM-B1 / WP-D2.2 (audit SOL-02): pre-fix DOMAIN_SEPARATOR was
    /// `immutable` — captured ONCE at construction. After a hard-fork
    /// chainId change (which Citrate's re-genesis policy explicitly
    /// allows), all stored authorizations remained signed under the
    /// OLD chainId yet the contract verified them against the cached
    /// chainId, making cross-fork replay possible. Post-fix the
    /// domain separator is rebuilt on every verify when
    /// `block.chainid != _CACHED_CHAIN_ID`. OZ EIP712.sol pattern.
    bytes32 private immutable _CACHED_DOMAIN_SEPARATOR;
    uint256 private immutable _CACHED_CHAIN_ID;
    bytes32 private immutable _HASHED_NAME;
    bytes32 private immutable _HASHED_VERSION;
    bytes32 private immutable _TYPE_HASH;

    // EIP-712 type hashes
    bytes32 public constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH =
        keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)");

    /// RFI-01 / WP-H1.1: distinct typehash for the fee-bearing flow.
    /// Binds `(treasury, fee)` into the signed digest so a caller
    /// cannot substitute either parameter at submission time. See
    /// `transferWithFeeAuthorization` and the RFI-01 audit note in
    /// `.audit/2026-04-25-reaudit/06_FINDINGS_SOLIDITY_CONTRACTS.md`.
    bytes32 public constant TRANSFER_WITH_FEE_AUTHORIZATION_TYPEHASH =
        keccak256("TransferWithFeeAuthorization(address from,address to,uint256 value,address treasury,uint256 fee,uint256 validAfter,uint256 validBefore,bytes32 nonce)");

    bytes32 public constant RECEIVE_WITH_AUTHORIZATION_TYPEHASH =
        keccak256("ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)");

    bytes32 public constant CANCEL_AUTHORIZATION_TYPEHASH =
        keccak256("CancelAuthorization(address authorizer,bytes32 nonce)");

    /// @notice Reverts when a caller invokes
    ///         `transferWithFeeAuthorization` with `(treasury, fee)`
    ///         values that do not match the EIP-712 digest signed by
    ///         `from`. Specifically: signature recovery does not yield
    ///         `from`, OR the recovered signer is `address(0)`.
    /// @dev See RFI-01. The previous implementation reused the
    ///      `TRANSFER_WITH_AUTHORIZATION_TYPEHASH` digest, which left
    ///      `(treasury, fee)` outside the signed payload. The fix uses
    ///      a distinct typehash; this error is the structural marker
    ///      that the new typehash is in force.
    error InvalidFeeAuthorization();

    // ERC-20 events
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Deposit(address indexed account, uint256 amount);
    event Withdrawal(address indexed account, uint256 amount);

    constructor() {
        _TYPE_HASH = keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );
        _HASHED_NAME = keccak256(bytes(name));
        _HASHED_VERSION = keccak256(bytes("1"));
        _CACHED_CHAIN_ID = block.chainid;
        _CACHED_DOMAIN_SEPARATOR = _buildDomainSeparator(
            _TYPE_HASH,
            _HASHED_NAME,
            _HASHED_VERSION
        );
    }

    /// SOL-02 fix: rebuild on chainId change.
    function _buildDomainSeparator(
        bytes32 typeHash,
        bytes32 nameHash,
        bytes32 versionHash
    ) private view returns (bytes32) {
        return keccak256(
            abi.encode(typeHash, nameHash, versionHash, block.chainid, address(this))
        );
    }

    /// @notice Returns the EIP-712 domain separator for the current chainId.
    /// RM-B1 / WP-D2.2 (audit SOL-02): if `block.chainid` matches the
    /// cached value at construction, returns the cached separator;
    /// otherwise rebuilds on the fly. This prevents cross-fork replay
    /// after a re-genesis chainId change.
    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        if (block.chainid == _CACHED_CHAIN_ID) {
            return _CACHED_DOMAIN_SEPARATOR;
        }
        return _buildDomainSeparator(_TYPE_HASH, _HASHED_NAME, _HASHED_VERSION);
    }

    // ============================================================
    // ERC-20 Standard Functions
    // ============================================================

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 currentAllowance = allowance[from][msg.sender];
        if (currentAllowance != type(uint256).max) {
            require(currentAllowance >= amount, "wSALT: insufficient allowance");
            allowance[from][msg.sender] = currentAllowance - amount;
        }
        _transfer(from, to, amount);
        return true;
    }

    // ============================================================
    // Wrap/Unwrap (deposit/withdraw native SALT)
    // ============================================================

    /// @notice Wrap native SALT into wSALT
    function deposit() external payable nonReentrant {
        require(msg.value > 0, "wSALT: zero deposit");
        balanceOf[msg.sender] += msg.value;
        totalSupply += msg.value;
        emit Deposit(msg.sender, msg.value);
        emit Transfer(address(0), msg.sender, msg.value);
    }

    /// @notice Unwrap wSALT back to native SALT
    function withdraw(uint256 amount) external nonReentrant {
        require(balanceOf[msg.sender] >= amount, "wSALT: insufficient balance");
        balanceOf[msg.sender] -= amount;
        totalSupply -= amount;
        emit Withdrawal(msg.sender, amount);
        emit Transfer(msg.sender, address(0), amount);
        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "wSALT: native transfer failed");
    }

    /// @notice Deposit via receive
    receive() external payable nonReentrant {
        balanceOf[msg.sender] += msg.value;
        totalSupply += msg.value;
        emit Deposit(msg.sender, msg.value);
        emit Transfer(address(0), msg.sender, msg.value);
    }

    // ============================================================
    // EIP-3009: Transfer With Authorization
    // ============================================================

    /// @inheritdoc IERC3009
    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(block.timestamp > validAfter, "wSALT: authorization not yet valid");
        require(block.timestamp < validBefore, "wSALT: authorization expired");
        require(!_authorizationStates[from][nonce], "wSALT: authorization already used");

        bytes32 structHash = keccak256(abi.encode(
            TRANSFER_WITH_AUTHORIZATION_TYPEHASH,
            from, to, value, validAfter, validBefore, nonce
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash));
        address signer = _recoverCanonical(digest, v, r, s);
        require(signer != address(0) && signer == from, "wSALT: invalid signature");

        _authorizationStates[from][nonce] = true;
        emit AuthorizationUsed(from, nonce);

        _transfer(from, to, value);
    }

    /// @notice Authorize a transfer of `value` from `from` and split
    ///         it internally into `value - fee` to `to` plus `fee` to
    ///         `treasury`. Single signed authorization for the FULL
    ///         value — caller cannot route any other recipient OR
    ///         redirect the fee leg.
    ///
    /// RM-B1 / WP-D2.1 (audit SOL-01): pre-fix the X402Facilitator
    /// settled `netValue` via `transferWithAuthorization` and pulled
    /// the fee via a separate `transferFrom` requiring an off-chain
    /// allowance. That breaks x402's gasless-UX claim — users either
    /// had to grant unbounded allowances (MEV/sandwich surface) or
    /// the fee leg reverted after the authorization was marked used.
    ///
    /// Post-fix: this function consumes ONE EIP-3009 authorization
    /// for the gross `value`, then splits internally:
    ///   - `value - fee` → `to`
    ///   - `fee`         → `treasury`
    /// The user signs ONCE for `value` and the routing is done by
    /// the contract; no separate allowance required.
    ///
    /// RFI-01 / WP-H1.1 (re-audit Stream 4): the prior implementation
    /// reused `TRANSFER_WITH_AUTHORIZATION_TYPEHASH`, which left
    /// `(treasury, fee)` OUTSIDE the signed digest. A mempool watcher
    /// could front-run any in-flight authorization with
    /// `treasury=attacker, fee=value`, redirecting the entire payment.
    /// The fix below uses a distinct typehash
    /// `TRANSFER_WITH_FEE_AUTHORIZATION_TYPEHASH` that binds
    /// `(treasury, fee)` into the digest — making the only valid call
    /// shape one where the caller-supplied `(treasury, fee)` match the
    /// values the user signed.
    ///
    /// @param from        Token holder authorizing the spend.
    /// @param to          Net-value recipient.
    /// @param treasury    Fee recipient. Bound to the EIP-712 digest.
    /// @param value       Gross value debited from `from`.
    /// @param fee         Amount routed to `treasury`. Bound to the digest.
    /// @param validAfter  Earliest block timestamp at which the auth is valid.
    /// @param validBefore Latest block timestamp at which the auth is valid.
    /// @param nonce       Single-use authorization nonce.
    /// @param v           ECDSA recovery id.
    /// @param r           ECDSA signature r component.
    /// @param s           ECDSA signature s component.
    function transferWithFeeAuthorization(
        address from,
        address to,
        address treasury,
        uint256 value,
        uint256 fee,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(fee <= value, "wSALT: fee exceeds value");
        require(treasury != address(0), "wSALT: zero treasury");
        require(block.timestamp > validAfter, "wSALT: authorization not yet valid");
        require(block.timestamp < validBefore, "wSALT: authorization expired");
        require(!_authorizationStates[from][nonce], "wSALT: authorization already used");

        // RFI-01: bind (treasury, fee) into the signed digest. Using
        // the distinct TRANSFER_WITH_FEE_AUTHORIZATION_TYPEHASH means
        // a signature minted for the legacy `transferWithAuthorization`
        // path CANNOT be replayed against this entry, AND the caller
        // cannot substitute `treasury` or `fee` at submission time.
        bytes32 structHash = keccak256(abi.encode(
            TRANSFER_WITH_FEE_AUTHORIZATION_TYPEHASH,
            from, to, value, treasury, fee, validAfter, validBefore, nonce
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash));
        address signer = _recoverCanonical(digest, v, r, s);
        if (signer == address(0) || signer != from) {
            revert InvalidFeeAuthorization();
        }

        _authorizationStates[from][nonce] = true;
        emit AuthorizationUsed(from, nonce);

        // Split internally — single source of truth on the fee math.
        uint256 netValue = value - fee;
        if (netValue > 0) {
            _transfer(from, to, netValue);
        }
        if (fee > 0) {
            _transfer(from, treasury, fee);
        }
    }

    /// @inheritdoc IERC3009
    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(to == msg.sender, "wSALT: caller must be payee");
        require(block.timestamp > validAfter, "wSALT: authorization not yet valid");
        require(block.timestamp < validBefore, "wSALT: authorization expired");
        require(!_authorizationStates[from][nonce], "wSALT: authorization already used");

        bytes32 structHash = keccak256(abi.encode(
            RECEIVE_WITH_AUTHORIZATION_TYPEHASH,
            from, to, value, validAfter, validBefore, nonce
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash));
        address signer = _recoverCanonical(digest, v, r, s);
        require(signer != address(0) && signer == from, "wSALT: invalid signature");

        _authorizationStates[from][nonce] = true;
        emit AuthorizationUsed(from, nonce);

        _transfer(from, to, value);
    }

    /// @inheritdoc IERC3009
    function cancelAuthorization(
        address authorizer,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(!_authorizationStates[authorizer][nonce], "wSALT: authorization already used");

        bytes32 structHash = keccak256(abi.encode(
            CANCEL_AUTHORIZATION_TYPEHASH,
            authorizer, nonce
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash));
        address signer = _recoverCanonical(digest, v, r, s);
        require(signer != address(0) && signer == authorizer, "wSALT: invalid signature");

        _authorizationStates[authorizer][nonce] = true;
        emit AuthorizationCanceled(authorizer, nonce);
    }

    /// @inheritdoc IERC3009
    function authorizationState(address authorizer, bytes32 nonce) external view returns (bool) {
        return _authorizationStates[authorizer][nonce];
    }

    // ============================================================
    // Internal
    // ============================================================

    /// @notice Malleability-safe ECDSA recovery (FWA-C3-05).
    /// @dev Replaces the bare `ecrecover`, which accepted BOTH `(v,r,s)`
    ///      and its complementary `(v^1, r, n-s)` form — a watcher could
    ///      front-run an in-flight EIP-3009 relay with the malleated form
    ///      (same nonce, different tx hash) and steal the relay leg /
    ///      break off-chain sig-hash bookkeeping. OZ `ECDSA.tryRecover`
    ///      enforces low-s (s <= secp256k1n/2, EIP-2) and v in {27,28},
    ///      so only the canonical signature recovers a non-zero address.
    ///      Returns `address(0)` on any malleable/invalid input, matching
    ///      the existing `signer == address(0)` rejection at each callsite.
    function _recoverCanonical(bytes32 digest, uint8 v, bytes32 r, bytes32 s)
        internal
        pure
        returns (address)
    {
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, v, r, s);
        if (err != ECDSA.RecoverError.NoError) return address(0);
        return recovered;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(from != address(0), "wSALT: transfer from zero address");
        require(to != address(0), "wSALT: transfer to zero address");
        require(balanceOf[from] >= amount, "wSALT: insufficient balance");

        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
    }
}
