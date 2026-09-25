// Semgrep rule fixture for pba-r2-tripwires.yml (run: semgrep --test .semgrep/).
pragma solidity ^0.8.26;

contract CtorMsgSender is Governable {
    address a;
    // ruleid: pba-l2-002-constructor-msg-sender
    constructor() Governable(msg.sender) {
        // ruleid: pba-l2-002-constructor-msg-sender
        a = msg.sender;
    }
}

contract StateInit {
    // ruleid: pba-l2-002-state-initialiser-msg-sender
    address public owner = msg.sender;
    // ok: pba-l2-002-state-initialiser-msg-sender
    function f() external view returns (address) { return msg.sender; }
}

contract HelperInit {
    address a;
    constructor() { _init(); }
    function _init() internal {
        // ruleid: pba-l2-002-constructor-helper-msg-sender
        a = msg.sender;
    }
}

contract Clean {
    address a;
    constructor(address x) { a = x; }
    // ok: pba-l2-002-constructor-msg-sender
    function g() external view returns (address) { return msg.sender; }
}

contract Signers {
    mapping(bytes32 => bool) hasSigned;
    function bad(bytes32 id, bytes32 signer) external {
        // ruleid: pba-l2-014-signer-not-bound-to-caller
        hasSigned[signer] = true;
    }
    function good(bytes32 id, bytes32 signer) external {
        if (signer != QuorumIdentity.subjectKey(msg.sender)) revert();
        // ok: pba-l2-014-signer-not-bound-to-caller
        hasSigned[signer] = true;
    }
    function gate(bytes32 id) external view returns (bool) {
        // ruleid: pba-l2-012-trusts-envelope-self-threshold
        return oracle.isSignedThresholdMet(id);
    }
}

contract AdminUnchecked {
    address governance;
    constructor(address g) {
        if (g == address(0)) revert();
        // ruleid: pba-l2-002-constructor-admin-unchecked
        governance = g;
    }
}

contract AdminChecked {
    address governance;
    constructor(address g) {
        // ok: pba-l2-002-constructor-admin-unchecked
        governance = InitialAdmin.check(g);
    }
}

contract AdminCheckedFirst {
    address owner;
    constructor(address g) {
        InitialAdmin.check(g);
        // ok: pba-l2-002-constructor-admin-unchecked
        owner = g;
    }
}

contract OwnersChecked {
    address[3] owners;
    constructor(address[3] memory o) {
        for (uint8 i = 0; i < 3; i++) {
            InitialAdmin.check(o[i]);
        }
        // ok: pba-l2-002-constructor-admin-unchecked
        owners = o;
    }
}

contract FactoryCompared {
    address private _governance;
    address guardian;
    constructor(address g, address h) {
        if (g == InitialAdmin.CREATE2_FACTORY) revert();
        require(h != InitialAdmin.CREATE2_FACTORY, "factory");
        // ok: pba-l2-002-constructor-admin-unchecked
        _governance = g;
        // ok: pba-l2-002-constructor-admin-unchecked
        guardian = h;
    }
}

contract NotAnAdminSlot {
    address vault;
    constructor(address v) {
        // ok: pba-l2-002-constructor-admin-unchecked
        vault = v;
    }
}

contract RoleUnchecked {
    constructor(address a) {
        // ruleid: pba-l2-002-constructor-admin-unchecked
        _grantRole(DEFAULT_ADMIN_ROLE, a);
    }
}

contract HelperUnchecked {
    constructor(address a) {
        // ruleid: pba-l2-002-constructor-admin-unchecked
        _transferOwnership(a);
    }
}

contract OwnableUnchecked is Ownable {
    // ruleid: pba-l2-002-ownable-unchecked
    constructor(address o) ERC721("a", "b") Ownable(o) {}
}

contract OwnableChecked is Ownable {
    // ok: pba-l2-002-ownable-unchecked
    constructor(address o) ERC721("a", "b") Ownable(o) {
        InitialAdmin.check(o);
    }
}

contract OwnableCheckedInline is Ownable {
    // ok: pba-l2-002-ownable-unchecked
    constructor(address o) Ownable(InitialAdmin.check(o)) {}
}
