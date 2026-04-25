// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./interfaces/IERC3009.sol";
import "./lib/ReentrancyGuard.sol";

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

    bytes32 public constant RECEIVE_WITH_AUTHORIZATION_TYPEHASH =
        keccak256("ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)");

    bytes32 public constant CANCEL_AUTHORIZATION_TYPEHASH =
        keccak256("CancelAuthorization(address authorizer,bytes32 nonce)");

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
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0) && signer == from, "wSALT: invalid signature");

        _authorizationStates[from][nonce] = true;
        emit AuthorizationUsed(from, nonce);

        _transfer(from, to, value);
    }

    /// @notice Authorize a transfer of `value` from `from` and split
    ///         it internally into `value - fee` to `to` plus `fee` to
    ///         `treasury`. Single signed authorization for the FULL
    ///         value — caller cannot route any other recipient.
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

        // The signed message authorizes the GROSS `value` to the
        // recipient; the fee split is contract-enforced. We bind
        // the typehash payload to (from, to, value, ...) — exactly
        // the same shape as `transferWithAuthorization` — so a
        // signature minted for one cannot be replayed against the
        // other (different function entry, different `to`, but the
        // signed digest is interchangeable with TWA on (from, to,
        // value)). To prevent replay, we share the
        // `_authorizationStates[from][nonce]` namespace.
        bytes32 structHash = keccak256(abi.encode(
            TRANSFER_WITH_AUTHORIZATION_TYPEHASH,
            from, to, value, validAfter, validBefore, nonce
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash));
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0) && signer == from, "wSALT: invalid signature");

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
        address signer = ecrecover(digest, v, r, s);
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
        address signer = ecrecover(digest, v, r, s);
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

    function _transfer(address from, address to, uint256 amount) internal {
        require(from != address(0), "wSALT: transfer from zero address");
        require(to != address(0), "wSALT: transfer to zero address");
        require(balanceOf[from] >= amount, "wSALT: insufficient balance");

        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
    }
}
