// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {AppRegistry, IEnvelopeOracle} from "../../src/boeing/AppRegistry.sol";

/// @notice Test stand-in for the on-chain MultiSigEnvelope contract.
///         Implements only `isSignedThresholdMet(bytes32)` — the sole
///         method AppRegistry consumes.
contract MockEnvelopeOracle is IEnvelopeOracle {
    mapping(bytes32 => bool) public met;

    function setMet(bytes32 id, bool v) external {
        met[id] = v;
    }

    function isSignedThresholdMet(bytes32 envelope_id) external view returns (bool) {
        return met[envelope_id];
    }
}

/// @notice A trivial deployable contract used to exercise the
///         bytecode-hash binding invariant.
contract Dummy {
    uint256 public stored;
    function set(uint256 v) external { stored = v; }
}

contract AppRegistryTest is Test {
    AppRegistry internal registry;
    MockEnvelopeOracle internal oracle;
    address internal governance;
    address internal recorder;
    address internal owner1;
    address internal nobody;

    bytes32 internal constant SCOPE_BCA = keccak256("scope-bca");
    bytes32 internal constant SCOPE_BDS = keccak256("scope-bds");
    bytes32 internal constant ENV_1 = keccak256("env-1");
    bytes32 internal constant ENV_2 = keccak256("env-2");
    bytes32 internal constant APP_1 = keccak256("app-1");
    bytes32 internal constant APP_2 = keccak256("app-2");

    function setUp() public {
        governance = makeAddr("governance");
        recorder = makeAddr("recorder");
        owner1 = makeAddr("owner1");
        nobody = makeAddr("nobody");
        oracle = new MockEnvelopeOracle();
        vm.prank(governance);
        registry = new AppRegistry(governance, address(oracle));
        // Authorize the recorder.
        vm.prank(governance);
        registry.setRecorder(recorder, true);
    }

    // ── Constructor + governance ───────────────────────────────────

    function test_constructor_rejects_zero_governance() public {
        vm.expectRevert(AppRegistry.ZeroGovernance.selector);
        new AppRegistry(address(0), address(oracle));
    }

    function test_constructor_rejects_zero_envelope_oracle() public {
        vm.expectRevert(AppRegistry.ZeroEnvelopeOracle.selector);
        new AppRegistry(governance, address(0));
    }

    function test_governance_set_correctly() public view {
        assertEq(registry.governance(), governance);
        assertEq(address(registry.envelope_oracle()), address(oracle));
    }

    function test_setRecorder_emits_event() public {
        vm.expectEmit(true, false, false, true);
        emit AppRegistry.RecorderSet(makeAddr("rec2"), true);
        vm.prank(governance);
        registry.setRecorder(makeAddr("rec2"), true);
    }

    function test_setRecorder_only_governance() public {
        vm.prank(nobody);
        vm.expectRevert(abi.encodeWithSelector(AppRegistry.NotGovernance.selector, nobody));
        registry.setRecorder(nobody, true);
    }

    // ── proposeApp ─────────────────────────────────────────────────

    function _proposeAppBasic(bytes32 app_id, bytes32 scope, bytes32 env) internal {
        address[] memory empty;
        vm.prank(recorder);
        registry.proposeApp(
            app_id,
            scope,
            "test-app",
            "1.0",
            owner1,
            env,
            empty,
            keccak256("source-cid-1")
        );
    }

    function test_proposeApp_moves_to_pending() public {
        _proposeAppBasic(APP_1, SCOPE_BCA, ENV_1);
        AppRegistry.AppEntry memory a = registry.getApp(APP_1);
        assertEq(uint8(a.state), uint8(AppRegistry.AppState.Pending));
        assertEq(a.scope, SCOPE_BCA);
        assertEq(a.deploy_envelope, ENV_1);
        assertEq(a.name, "test-app");
        assertEq(a.owner, owner1);
    }

    function test_proposeApp_only_recorder() public {
        address[] memory empty;
        vm.prank(nobody);
        vm.expectRevert(abi.encodeWithSelector(AppRegistry.NotRecorder.selector, nobody));
        registry.proposeApp(APP_1, SCOPE_BCA, "x", "1", owner1, ENV_1, empty, bytes32(0));
    }

    function test_proposeApp_rejects_empty_name() public {
        address[] memory empty;
        vm.prank(recorder);
        vm.expectRevert(AppRegistry.EmptyName.selector);
        registry.proposeApp(APP_1, SCOPE_BCA, "", "1", owner1, ENV_1, empty, bytes32(0));
    }

    function test_proposeApp_rejects_duplicate_app_id() public {
        _proposeAppBasic(APP_1, SCOPE_BCA, ENV_1);
        address[] memory empty;
        vm.prank(recorder);
        vm.expectRevert(abi.encodeWithSelector(AppRegistry.AppAlreadyExists.selector, APP_1));
        registry.proposeApp(APP_1, SCOPE_BDS, "x", "1", owner1, ENV_2, empty, bytes32(0));
    }

    function test_proposeApp_appears_in_byScope() public {
        _proposeAppBasic(APP_1, SCOPE_BCA, ENV_1);
        bytes32[] memory ids = registry.byScope(SCOPE_BCA);
        assertEq(ids.length, 1);
        assertEq(ids[0], APP_1);
        assertEq(registry.byScope(SCOPE_BDS).length, 0);
    }

    function test_proposeApp_scope_filter_isolates() public {
        _proposeAppBasic(APP_1, SCOPE_BCA, ENV_1);
        _proposeAppBasic(APP_2, SCOPE_BDS, ENV_2);
        assertEq(registry.byScope(SCOPE_BCA).length, 1);
        assertEq(registry.byScope(SCOPE_BDS).length, 1);
        assertEq(registry.byScope(SCOPE_BCA)[0], APP_1);
        assertEq(registry.byScope(SCOPE_BDS)[0], APP_2);
    }

    // ── deploy (multi-sig gate) ────────────────────────────────────

    function test_deploy_requires_envelope_threshold_met() public {
        _proposeAppBasic(APP_1, SCOPE_BCA, ENV_1);
        // Envelope NOT met.
        vm.expectRevert(abi.encodeWithSelector(AppRegistry.EnvelopeThresholdNotMet.selector, ENV_1));
        registry.deploy(APP_1);
    }

    function test_deploy_succeeds_when_envelope_met() public {
        _proposeAppBasic(APP_1, SCOPE_BCA, ENV_1);
        oracle.setMet(ENV_1, true);
        registry.deploy(APP_1);
        AppRegistry.AppEntry memory a = registry.getApp(APP_1);
        assertEq(uint8(a.state), uint8(AppRegistry.AppState.Deployed));
        assertEq(a.deployed_at_block, block.number);
    }

    function test_deploy_rejects_nonexistent_app() public {
        vm.expectRevert(abi.encodeWithSelector(AppRegistry.AppDoesNotExist.selector, APP_1));
        registry.deploy(APP_1);
    }

    function test_deploy_rejects_app_not_in_pending() public {
        _proposeAppBasic(APP_1, SCOPE_BCA, ENV_1);
        oracle.setMet(ENV_1, true);
        registry.deploy(APP_1);
        // Now it's Deployed; calling deploy again should revert.
        vm.expectRevert(
            abi.encodeWithSelector(
                AppRegistry.AppNotInState.selector,
                APP_1,
                AppRegistry.AppState.Pending,
                AppRegistry.AppState.Deployed
            )
        );
        registry.deploy(APP_1);
    }

    function test_deploy_emits_AppDeployed_event() public {
        address[] memory two = new address[](2);
        two[0] = address(new Dummy());
        two[1] = address(new Dummy());
        vm.prank(recorder);
        registry.proposeApp(APP_1, SCOPE_BCA, "x", "1", owner1, ENV_1, two, bytes32(0));
        oracle.setMet(ENV_1, true);
        vm.expectEmit(true, true, false, true);
        emit AppRegistry.AppDeployed(APP_1, ENV_1, 2, block.number);
        registry.deploy(APP_1);
    }

    // ── recordFailureOnEnvelopeReject ──────────────────────────────

    function test_recordFailure_when_envelope_not_met() public {
        _proposeAppBasic(APP_1, SCOPE_BCA, ENV_1);
        // CHAIN-B-C025 RC-8: the Failed transition is now recorder-gated.
        // Envelope is not met → an authorized recorder's claim is accepted.
        vm.prank(recorder);
        registry.recordFailureOnEnvelopeReject(APP_1);
        AppRegistry.AppEntry memory a = registry.getApp(APP_1);
        assertEq(uint8(a.state), uint8(AppRegistry.AppState.Failed));
    }

    /// CHAIN-B-C025 RC-8: an unprivileged caller can no longer burn a
    /// pending app id by racing `recordFailureOnEnvelopeReject`.
    function test_recordFailure_rejects_unauthorized() public {
        _proposeAppBasic(APP_1, SCOPE_BCA, ENV_1);
        vm.prank(nobody);
        vm.expectRevert(abi.encodeWithSelector(AppRegistry.NotRecorder.selector, nobody));
        registry.recordFailureOnEnvelopeReject(APP_1);
        // App stays Pending → still deployable.
        assertEq(uint8(registry.getApp(APP_1).state), uint8(AppRegistry.AppState.Pending));
    }

    function test_recordFailure_reverts_if_envelope_actually_met() public {
        _proposeAppBasic(APP_1, SCOPE_BCA, ENV_1);
        oracle.setMet(ENV_1, true);
        // Caller claims rejection but envelope IS met; safer to revert.
        vm.prank(recorder);
        vm.expectRevert(abi.encodeWithSelector(AppRegistry.EnvelopeThresholdNotMet.selector, ENV_1));
        registry.recordFailureOnEnvelopeReject(APP_1);
    }

    // ── retire ─────────────────────────────────────────────────────

    function test_retire_by_owner() public {
        _proposeAppBasic(APP_1, SCOPE_BCA, ENV_1);
        oracle.setMet(ENV_1, true);
        registry.deploy(APP_1);
        vm.prank(owner1);
        registry.retire(APP_1);
        assertEq(uint8(registry.getApp(APP_1).state), uint8(AppRegistry.AppState.Retired));
    }

    function test_retire_by_governance() public {
        _proposeAppBasic(APP_1, SCOPE_BCA, ENV_1);
        oracle.setMet(ENV_1, true);
        registry.deploy(APP_1);
        vm.prank(governance);
        registry.retire(APP_1);
        assertEq(uint8(registry.getApp(APP_1).state), uint8(AppRegistry.AppState.Retired));
    }

    function test_retire_rejects_unauthorized() public {
        _proposeAppBasic(APP_1, SCOPE_BCA, ENV_1);
        oracle.setMet(ENV_1, true);
        registry.deploy(APP_1);
        vm.prank(nobody);
        vm.expectRevert(abi.encodeWithSelector(AppRegistry.NotGovernance.selector, nobody));
        registry.retire(APP_1);
    }

    function test_retire_rejects_not_deployed() public {
        _proposeAppBasic(APP_1, SCOPE_BCA, ENV_1);
        // Still Pending.
        vm.prank(owner1);
        vm.expectRevert(
            abi.encodeWithSelector(
                AppRegistry.AppNotInState.selector,
                APP_1,
                AppRegistry.AppState.Deployed,
                AppRegistry.AppState.Pending
            )
        );
        registry.retire(APP_1);
    }

    function test_retire_is_absorbing() public {
        _proposeAppBasic(APP_1, SCOPE_BCA, ENV_1);
        oracle.setMet(ENV_1, true);
        registry.deploy(APP_1);
        vm.prank(owner1);
        registry.retire(APP_1);
        // Retire again → reverts (not in Deployed).
        vm.prank(owner1);
        vm.expectRevert(
            abi.encodeWithSelector(
                AppRegistry.AppNotInState.selector,
                APP_1,
                AppRegistry.AppState.Deployed,
                AppRegistry.AppState.Retired
            )
        );
        registry.retire(APP_1);
    }

    // ── registerContract (bytecode-hash invariant) ─────────────────

    function _deployDummyAndHash() internal returns (address, bytes32) {
        Dummy d = new Dummy();
        bytes32 hash = keccak256(address(d).code);
        return (address(d), hash);
    }

    function test_registerContract_happy_path() public {
        (address dAddr, bytes32 dHash) = _deployDummyAndHash();
        vm.prank(recorder);
        registry.registerContract(dAddr, keccak256("src-1"), dHash, makeAddr("oracle1"), ENV_1, APP_1);
        AppRegistry.ContractEntry memory c = registry.getContract(dAddr);
        assertEq(c.contract_addr, dAddr);
        assertEq(c.bytecode_hash, dHash);
        assertEq(c.deployed_by_app, APP_1);
    }

    function test_registerContract_rejects_bytecode_mismatch() public {
        (address dAddr,) = _deployDummyAndHash();
        bytes32 wrong = keccak256("not-the-real-bytecode");
        vm.prank(recorder);
        bytes32 actual = keccak256(dAddr.code);
        vm.expectRevert(
            abi.encodeWithSelector(AppRegistry.BytecodeMismatch.selector, dAddr, wrong, actual)
        );
        registry.registerContract(dAddr, bytes32(0), wrong, address(0), bytes32(0), APP_1);
    }

    function test_registerContract_rejects_duplicate() public {
        (address dAddr, bytes32 dHash) = _deployDummyAndHash();
        vm.prank(recorder);
        registry.registerContract(dAddr, bytes32(0), dHash, address(0), bytes32(0), APP_1);
        vm.prank(recorder);
        vm.expectRevert(
            abi.encodeWithSelector(AppRegistry.ContractAlreadyRegistered.selector, dAddr)
        );
        registry.registerContract(dAddr, bytes32(0), dHash, address(0), bytes32(0), APP_1);
    }

    function test_registerContract_rejects_zero_address() public {
        vm.prank(recorder);
        vm.expectRevert(AppRegistry.ZeroContractAddress.selector);
        registry.registerContract(address(0), bytes32(0), bytes32(0), address(0), bytes32(0), APP_1);
    }

    function test_registerContract_only_recorder() public {
        (address dAddr, bytes32 dHash) = _deployDummyAndHash();
        vm.prank(nobody);
        vm.expectRevert(abi.encodeWithSelector(AppRegistry.NotRecorder.selector, nobody));
        registry.registerContract(dAddr, bytes32(0), dHash, address(0), bytes32(0), APP_1);
    }

    function test_registerContract_appears_in_allContracts() public {
        (address dAddr, bytes32 dHash) = _deployDummyAndHash();
        vm.prank(recorder);
        registry.registerContract(dAddr, bytes32(0), dHash, address(0), bytes32(0), APP_1);
        address[] memory all = registry.allContracts();
        assertEq(all.length, 1);
        assertEq(all[0], dAddr);
        assertEq(registry.contractCount(), 1);
    }

    function test_registerContract_multiple_appear_in_order() public {
        (address d1, bytes32 h1) = _deployDummyAndHash();
        (address d2, bytes32 h2) = _deployDummyAndHash();
        vm.prank(recorder);
        registry.registerContract(d1, bytes32(0), h1, address(0), bytes32(0), APP_1);
        vm.prank(recorder);
        registry.registerContract(d2, bytes32(0), h2, address(0), bytes32(0), APP_1);
        address[] memory all = registry.allContracts();
        assertEq(all.length, 2);
        assertEq(all[0], d1);
        assertEq(all[1], d2);
    }
}
