// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

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
    bytes32 public immutable DOMAIN_SEPARATOR;

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
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name)),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
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
    receive() external payable {
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
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0) && signer == from, "wSALT: invalid signature");

        _authorizationStates[from][nonce] = true;
        emit AuthorizationUsed(from, nonce);

        _transfer(from, to, value);
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
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
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
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
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
