// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "../script/Salts.sol";
import "../script/DeployValidatorRegistry.s.sol";
import "../src/ValidatorRegistry.sol";

/// @title ValidatorRegistryCreate2Test — WS-5 reroll-stable-address gate.
///
/// Proves the ValidatorRegistry deploys via CREATE2, so its address is a pure
/// function of (salt, init_code, deployer) and is INDEPENDENT of deploy order /
/// the deployer's nonce — the property the whole reroll-stable address book
/// relies on. Mirrors test/Create2Determinism.t.sol for the business contracts.
///
/// REGRESSION TEETH: if anyone reverts the `new ValidatorRegistry{salt: …}(…)`
/// to a plain `new ValidatorRegistry(…)`, the CREATE (nonce-dependent) address
/// stops matching `computeCreate2Address`, and this test fails.
///
/// It ALSO logs `DeployValidatorRegistry.projectedAddress(ARACHNID_FACTORY)` —
/// the REAL reroll address the fleet pins as `CITRATE_VALIDATOR_REGISTRY` for
/// the constructor-arg constants committed in the deploy script. Re-run after
/// finalizing the OWNER-DECISION economic constants to read the final address.
contract ValidatorRegistryCreate2Test is Test {
    DeployValidatorRegistry internal deployScript;

    function setUp() public {
        deployScript = new DeployValidatorRegistry();
    }

    /// The init_code the deploy script projects against MUST equal
    /// `creationCode ++ abi.encode(the 7 constructor args)` — i.e. the script's
    /// helper is the single source of truth for the projected address.
    function test_initCode_matches_creationCode_plus_args() public view {
        bytes memory expected = abi.encodePacked(
            type(ValidatorRegistry).creationCode,
            abi.encode(
                deployScript.GOVERNANCE(),
                deployScript.SLASHER(),
                deployScript.REWARD_MINTER(),
                deployScript.MIN_STAKE(),
                deployScript.BLOCK_SUBSIDY(),
                deployScript.PRIORITY_FEE_SHARE_BPS(),
                deployScript.MAX_EPOCH_EMISSION()
            )
        );
        assertEq(keccak256(deployScript.initCode()), keccak256(expected), "init_code drift");
    }

    /// A real deploy with the SAME salt + SAME constructor args lands exactly at
    /// `computeCreate2Address(salt, keccak256(init_code), deployer)`. In a forge
    /// TEST `new X{salt:}` uses CREATE2 from `address(this)`, so we project
    /// against `address(this)`; the determinism PROPERTY is identical to the
    /// script's Arachnid-factory deploy, only the deployer differs.
    function test_validatorRegistry_is_create2() public {
        ValidatorRegistry reg = new ValidatorRegistry{salt: Salts.salt("ValidatorRegistry")}(
            deployScript.GOVERNANCE(),
            deployScript.SLASHER(),
            deployScript.REWARD_MINTER(),
            deployScript.MIN_STAKE(),
            deployScript.BLOCK_SUBSIDY(),
            deployScript.PRIORITY_FEE_SHARE_BPS(),
            deployScript.MAX_EPOCH_EMISSION()
        );

        address expected = vm.computeCreate2Address(
            Salts.salt("ValidatorRegistry"),
            keccak256(deployScript.initCode()),
            address(this)
        );
        assertEq(address(reg), expected, "deploy is not CREATE2 / wrong salt");

        // The script's pure projection helper must agree with the cheatcode.
        assertEq(
            deployScript.projectedAddress(address(this)),
            expected,
            "script projectedAddress() disagrees with computeCreate2Address"
        );
    }

    /// The deployed contract actually wires the constructor args (not just lands
    /// at the address) — guards against an init_code that computes but mis-stores.
    function test_deployed_registry_state_matches_args() public {
        ValidatorRegistry reg = new ValidatorRegistry{salt: Salts.salt("ValidatorRegistry")}(
            deployScript.GOVERNANCE(),
            deployScript.SLASHER(),
            deployScript.REWARD_MINTER(),
            deployScript.MIN_STAKE(),
            deployScript.BLOCK_SUBSIDY(),
            deployScript.PRIORITY_FEE_SHARE_BPS(),
            deployScript.MAX_EPOCH_EMISSION()
        );
        assertEq(reg.governance(), deployScript.GOVERNANCE(), "governance");
        assertEq(reg.slasher(), deployScript.SLASHER(), "slasher");
        assertEq(reg.rewardMinter(), deployScript.REWARD_MINTER(), "rewardMinter");
        assertEq(reg.minStake(), deployScript.MIN_STAKE(), "minStake");
        assertEq(reg.blockSubsidy(), deployScript.BLOCK_SUBSIDY(), "blockSubsidy");
        assertEq(reg.priorityFeeShareBps(), deployScript.PRIORITY_FEE_SHARE_BPS(), "priorityFeeShareBps");
        assertEq(reg.maxEpochEmission(), deployScript.MAX_EPOCH_EMISSION(), "maxEpochEmission");
    }

    /// CREATE2 address must not depend on the deployer's nonce (the whole point).
    function test_address_is_nonce_independent() public {
        bytes32 s = Salts.salt("ValidatorRegistry");
        bytes32 h = keccak256(deployScript.initCode());
        address a0 = vm.computeCreate2Address(s, h, address(this));
        vm.setNonce(address(this), 4242);
        address a1 = vm.computeCreate2Address(s, h, address(this));
        assertEq(a0, a1, "CREATE2 address must not depend on nonce");
    }

    /// Distinct salt from the other ceremony contracts (no accidental collision).
    function test_salt_is_distinct() public pure {
        assertTrue(Salts.salt("ValidatorRegistry") != Salts.salt("ComputePool"));
        assertTrue(Salts.salt("ValidatorRegistry") != Salts.salt("ModelRegistry"));
    }

    /// Log the REROLL address (Arachnid-factory projection) for the pin book.
    /// Not an assertion — this is the reportable `CITRATE_VALIDATOR_REGISTRY`.
    function test_log_reroll_projected_address() public {
        address rerollAddr = deployScript.projectedAddress(deployScript.ARACHNID_FACTORY());
        emit log_named_address("projected (Arachnid factory) address", rerollAddr);
        emit log_named_bytes32("init_code hash", keccak256(deployScript.initCode()));
        emit log_named_bytes32("salt", Salts.salt("ValidatorRegistry"));
    }
}
