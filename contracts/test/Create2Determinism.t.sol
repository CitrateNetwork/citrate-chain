// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "../script/Salts.sol";
import "../src/ModelRegistry.sol";
import "../src/WrappedSALT.sol";
import "../src/ComputePool.sol";
import "../src/IPFSIncentives.sol";
import "../src/InferenceRouter.sol";
import "../src/X402Paywall.sol";

/**
 * @title Create2DeterminismTest
 * @notice The CI determinism gate for the reroll-stable address book.
 *
 * Proves the ceremony deploys via CREATE2, so each address is a pure function
 * of (salt, init_code, deployer) and is INDEPENDENT of deploy order / the
 * deployer's nonce. A `CREATE2` address is `keccak256(0xff ++ deployer ++ salt
 * ++ keccak256(init_code))[12:]`; we recompute that with `vm.computeCreate2Address`
 * and assert the deployed contract lands there.
 *
 * REGRESSION TEETH: if anyone reverts a `new X{salt: …}(…)` back to a plain
 * `new X(…)`, the resulting CREATE address (which depends on nonce) stops
 * matching `computeCreate2Address`, and this test fails — so the address-scramble
 * bug (every reroll reshuffling the whole address book) cannot come back unnoticed.
 *
 * NB: in a forge TEST, `new X{salt:}` uses CREATE2 from `address(this)` (the test
 * contract), not the genesis Arachnid 0x4e59… proxy that forge SCRIPTS use. The
 * determinism PROPERTY is identical either way; only the deployer differs, so we
 * pass `address(this)` as the deployer to `computeCreate2Address`.
 */
contract Create2DeterminismTest is Test {
    function _assertCreate2(address deployed, bytes32 salt, bytes memory initCode) internal view {
        address expected = vm.computeCreate2Address(salt, keccak256(initCode), address(this));
        assertEq(deployed, expected, "deploy is not CREATE2 / wrong salt");
    }

    /// No-arg contracts: init_code == creationCode.
    function test_noArg_contracts_are_create2() public {
        ModelRegistry mr = new ModelRegistry{salt: Salts.salt("ModelRegistry")}();
        _assertCreate2(address(mr), Salts.salt("ModelRegistry"), type(ModelRegistry).creationCode);

        WrappedSALT ws = new WrappedSALT{salt: Salts.salt("WrappedSALT")}();
        _assertCreate2(address(ws), Salts.salt("WrappedSALT"), type(WrappedSALT).creationCode);

        ComputePool cp = new ComputePool{salt: Salts.salt("ComputePool")}();
        _assertCreate2(address(cp), Salts.salt("ComputePool"), type(ComputePool).creationCode);

        IPFSIncentives ip = new IPFSIncentives{salt: Salts.salt("IPFSIncentives")}();
        _assertCreate2(address(ip), Salts.salt("IPFSIncentives"), type(IPFSIncentives).creationCode);
    }

    /// Constructor-arg contracts: init_code == creationCode ++ abi.encode(args).
    /// Their address stays deterministic because the dependency address is itself
    /// a (deterministic) CREATE2 address.
    function test_argConstructor_contracts_are_create2() public {
        ModelRegistry mr = new ModelRegistry{salt: Salts.salt("ModelRegistry")}();
        InferenceRouter router = new InferenceRouter{salt: Salts.salt("InferenceRouter")}(address(mr));
        _assertCreate2(
            address(router),
            Salts.salt("InferenceRouter"),
            abi.encodePacked(type(InferenceRouter).creationCode, abi.encode(address(mr)))
        );

        WrappedSALT ws = new WrappedSALT{salt: Salts.salt("WrappedSALT")}();
        X402Paywall pw = new X402Paywall{salt: Salts.salt("X402Paywall")}(address(ws), 1 ether);
        _assertCreate2(
            address(pw),
            Salts.salt("X402Paywall"),
            abi.encodePacked(type(X402Paywall).creationCode, abi.encode(address(ws), uint256(1 ether)))
        );
    }

    /// The address must not depend on the deployer's nonce (the whole point).
    function test_address_is_nonce_independent() public {
        bytes32 s = Salts.salt("ComputePool");
        bytes32 h = keccak256(type(ComputePool).creationCode);
        address a0 = vm.computeCreate2Address(s, h, address(this));
        vm.setNonce(address(this), 12345);
        address a1 = vm.computeCreate2Address(s, h, address(this));
        assertEq(a0, a1, "CREATE2 address must not depend on nonce");
    }

    /// Distinct contracts get distinct salts (no accidental collision).
    function test_salts_are_distinct() public pure {
        assertTrue(Salts.salt("ModelRegistry") != Salts.salt("WrappedSALT"));
        assertTrue(Salts.salt("ComputePool") != Salts.salt("ComputePoolTraining"));
    }
}
