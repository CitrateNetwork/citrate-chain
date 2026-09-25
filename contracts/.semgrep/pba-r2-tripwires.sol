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
