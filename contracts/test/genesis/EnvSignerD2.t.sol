// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {TenantHierarchy} from "../../src/rbac/TenantHierarchy.sol";
import {SendWithEnvKey} from "../../script/SendWithEnvKey.s.sol";
import {DeployDpf02Rbac} from "../../script/DeployDpf02Rbac.s.sol";
import {DeployDpf06Suppliers} from "../../script/DeployDpf06Suppliers.s.sol";
import {DeployDpf07FL} from "../../script/DeployDpf07FL.s.sol";
import {DeployQuorumS6} from "../../script/DeployQuorumS6.s.sol";
import {DeployDpf05Provenance} from "../../script/DeployDpf05Provenance.s.sol";
import {DeployDpf09AppsContracts} from "../../script/DeployDpf09AppsContracts.s.sol";
import {DeployDpf10Assistant} from "../../script/DeployDpf10Assistant.s.sol";
import {DeployDpf11Governance} from "../../script/DeployDpf11Governance.s.sol";
import {DeployDpf12Ontology} from "../../script/DeployDpf12Ontology.s.sol";
import {DeployDpf13Procurement} from "../../script/DeployDpf13Procurement.s.sol";
import {DeployDpf14InterOrg} from "../../script/DeployDpf14InterOrg.s.sol";
import {DeployDpf15Compliance} from "../../script/DeployDpf15Compliance.s.sol";
import {DeployDpf16Sponsor} from "../../script/DeployDpf16Sponsor.s.sol";
import {DeployDpf17Release} from "../../script/DeployDpf17Release.s.sol";

/// r1007 option A (fed GO2 sheet section 12, lead 2026-11-11): the 14 post-genesis (D2) scripts can
/// broadcast from a key held only in the environment. For each script this checks that:
/// - the env-key path creates exactly the r1007 nonce table's number of contracts, at the
///   signer's consecutive CREATE addresses;
/// - those contracts have the same runtime code lengths, in the same order, as the CLI-wallet
///   path, so the same contracts land at the same nonces and no address moves;
/// - a key that does not belong to EXPECTED_SENDER is refused, as is a key with no
///   EXPECTED_SENDER.
/// Keys come through virtual hooks, not vm.setEnv, because the env is process-global and other
/// suites run in parallel. The env values set here are the ones PBA_R2_DeployScripts also sets.
interface ISigned {
    function setSigner(uint256 key, address expected) external;
}

contract H_DeployDpf02Rbac is DeployDpf02Rbac {
    uint256 internal k;
    address internal e;
    function setSigner(uint256 key, address expected) external { k = key; e = expected; }
    function _envSignerKey() internal view override returns (uint256) { return k; }
    function _envExpectedSender() internal view override returns (address) { return e; }
}
contract H_DeployDpf06Suppliers is DeployDpf06Suppliers {
    uint256 internal k;
    address internal e;
    function setSigner(uint256 key, address expected) external { k = key; e = expected; }
    function _envSignerKey() internal view override returns (uint256) { return k; }
    function _envExpectedSender() internal view override returns (address) { return e; }
}
contract H_DeployDpf07FL is DeployDpf07FL {
    uint256 internal k;
    address internal e;
    function setSigner(uint256 key, address expected) external { k = key; e = expected; }
    function _envSignerKey() internal view override returns (uint256) { return k; }
    function _envExpectedSender() internal view override returns (address) { return e; }
}
contract H_DeployQuorumS6 is DeployQuorumS6 {
    uint256 internal k;
    address internal e;
    function setSigner(uint256 key, address expected) external { k = key; e = expected; }
    function _envSignerKey() internal view override returns (uint256) { return k; }
    function _envExpectedSender() internal view override returns (address) { return e; }
}
contract H_DeployDpf05Provenance is DeployDpf05Provenance {
    uint256 internal k;
    address internal e;
    function setSigner(uint256 key, address expected) external { k = key; e = expected; }
    function _envSignerKey() internal view override returns (uint256) { return k; }
    function _envExpectedSender() internal view override returns (address) { return e; }
}
contract H_DeployDpf09AppsContracts is DeployDpf09AppsContracts {
    uint256 internal k;
    address internal e;
    function setSigner(uint256 key, address expected) external { k = key; e = expected; }
    function _envSignerKey() internal view override returns (uint256) { return k; }
    function _envExpectedSender() internal view override returns (address) { return e; }
}
contract H_DeployDpf10Assistant is DeployDpf10Assistant {
    uint256 internal k;
    address internal e;
    function setSigner(uint256 key, address expected) external { k = key; e = expected; }
    function _envSignerKey() internal view override returns (uint256) { return k; }
    function _envExpectedSender() internal view override returns (address) { return e; }
}
contract H_DeployDpf11Governance is DeployDpf11Governance {
    uint256 internal k;
    address internal e;
    function setSigner(uint256 key, address expected) external { k = key; e = expected; }
    function _envSignerKey() internal view override returns (uint256) { return k; }
    function _envExpectedSender() internal view override returns (address) { return e; }
}
contract H_DeployDpf12Ontology is DeployDpf12Ontology {
    uint256 internal k;
    address internal e;
    function setSigner(uint256 key, address expected) external { k = key; e = expected; }
    function _envSignerKey() internal view override returns (uint256) { return k; }
    function _envExpectedSender() internal view override returns (address) { return e; }
}
contract H_DeployDpf13Procurement is DeployDpf13Procurement {
    uint256 internal k;
    address internal e;
    function setSigner(uint256 key, address expected) external { k = key; e = expected; }
    function _envSignerKey() internal view override returns (uint256) { return k; }
    function _envExpectedSender() internal view override returns (address) { return e; }
}
contract H_DeployDpf14InterOrg is DeployDpf14InterOrg {
    uint256 internal k;
    address internal e;
    function setSigner(uint256 key, address expected) external { k = key; e = expected; }
    function _envSignerKey() internal view override returns (uint256) { return k; }
    function _envExpectedSender() internal view override returns (address) { return e; }
}
contract H_DeployDpf15Compliance is DeployDpf15Compliance {
    uint256 internal k;
    address internal e;
    function setSigner(uint256 key, address expected) external { k = key; e = expected; }
    function _envSignerKey() internal view override returns (uint256) { return k; }
    function _envExpectedSender() internal view override returns (address) { return e; }
}
contract H_DeployDpf16Sponsor is DeployDpf16Sponsor {
    uint256 internal k;
    address internal e;
    function setSigner(uint256 key, address expected) external { k = key; e = expected; }
    function _envSignerKey() internal view override returns (uint256) { return k; }
    function _envExpectedSender() internal view override returns (address) { return e; }
}
contract H_DeployDpf17Release is DeployDpf17Release {
    uint256 internal k;
    address internal e;
    function setSigner(uint256 key, address expected) external { k = key; e = expected; }
    function _envSignerKey() internal view override returns (uint256) { return k; }
    function _envExpectedSender() internal view override returns (address) { return e; }
}

contract H_Send is SendWithEnvKey {
    uint256 internal k;
    address internal e;
    address internal t;
    uint256 internal v;
    bytes internal d;
    function setSigner(uint256 key, address expected) external { k = key; e = expected; }
    function setCall(address to, uint256 value, bytes calldata data) external { t = to; v = value; d = data; }
    function _envSignerKey() internal view override returns (uint256) { return k; }
    function _envExpectedSender() internal view override returns (address) { return e; }
    function _to() internal view override returns (address) { return t; }
    function _value() internal view override returns (uint256) { return v; }
    function _data() internal view override returns (bytes memory) { return d; }
}

contract Sink {
    uint256 public last;
    function poke(uint256 x) external payable { last = x; }
}

contract EnvSignerD2Test is Test {
    address constant SENDER = 0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38; // forge default sender
    uint256 constant PK = 0xA11CE5EC2E7;
    address multisig = makeAddr("multisig");

    function setUp() public {
        vm.setEnv("DEPLOYER_ADDRESS", vm.toString(SENDER));
        vm.setEnv("GOVERNANCE", vm.toString(multisig));
        vm.setEnv("ROOT_GOVERNANCE", vm.toString(multisig));
        vm.etch(multisig, hex"00");
        TenantHierarchy th = new TenantHierarchy();
        vm.setEnv("TENANT_HIERARCHY", vm.toString(address(th)));
        vm.deal(vm.addr(PK), 100 ether);
    }

    function _creations(address by) internal returns (address[] memory out, uint256[] memory lens) {
        VmSafe.AccountAccess[] memory acc = vm.stopAndReturnStateDiff();
        uint256 n;
        for (uint256 i; i < acc.length; i++) {
            if (acc[i].kind == VmSafe.AccountAccessKind.Create && acc[i].accessor == by) n++;
        }
        out = new address[](n);
        lens = new uint256[](n);
        n = 0;
        for (uint256 i; i < acc.length; i++) {
            if (acc[i].kind == VmSafe.AccountAccessKind.Create && acc[i].accessor == by) {
                out[n] = acc[i].account;
                lens[n] = acc[i].account.code.length;
                n++;
            }
        }
    }

    function _run(ISigned h) internal {
        (bool ok, bytes memory ret) = address(h).call(abi.encodeWithSignature("run()"));
        if (!ok) {
            assembly { revert(add(ret, 32), mload(ret)) }
        }
    }

    /// CLI-wallet path first (forge's default sender), then the env-key path from a different
    /// account. Each path's creations come from its own sender's nonces, so neither affects the
    /// other's addresses.
    function _same(ISigned envPath, ISigned cliPath, uint256 count) internal {
        cliPath.setSigner(0, address(0));
        vm.startStateDiffRecording();
        _run(cliPath);
        (address[] memory b, uint256[] memory lb) = _creations(SENDER);
        assertEq(b.length, count, "creations from the CLI wallet");

        address signer = vm.addr(PK);
        envPath.setSigner(PK, signer);
        uint64 n0 = vm.getNonce(signer);
        vm.startStateDiffRecording();
        _run(envPath);
        (address[] memory a, uint256[] memory la) = _creations(signer);
        assertEq(a.length, count, "creations from the env key");
        for (uint256 i; i < a.length; i++) {
            assertEq(a[i], vm.computeCreateAddress(signer, n0 + i), "CREATE address at the next nonce");
            assertGt(la[i], 0, "code");
            assertEq(la[i], lb[i], "same contract at the same position");
        }
    }

    function test_DeployDpf02Rbac_envKey_sameCreationsAsBefore() public { _same(ISigned(address(new H_DeployDpf02Rbac())), ISigned(address(new H_DeployDpf02Rbac())), 6); }
    function test_DeployDpf06Suppliers_envKey_sameCreationsAsBefore() public { _same(ISigned(address(new H_DeployDpf06Suppliers())), ISigned(address(new H_DeployDpf06Suppliers())), 2); }
    function test_DeployDpf07FL_envKey_sameCreationsAsBefore() public { _same(ISigned(address(new H_DeployDpf07FL())), ISigned(address(new H_DeployDpf07FL())), 1); }
    function test_DeployQuorumS6_envKey_sameCreationsAsBefore() public { _same(ISigned(address(new H_DeployQuorumS6())), ISigned(address(new H_DeployQuorumS6())), 8); }
    function test_DeployDpf05Provenance_envKey_sameCreationsAsBefore() public { _same(ISigned(address(new H_DeployDpf05Provenance())), ISigned(address(new H_DeployDpf05Provenance())), 1); }
    function test_DeployDpf09AppsContracts_envKey_sameCreationsAsBefore() public { _same(ISigned(address(new H_DeployDpf09AppsContracts())), ISigned(address(new H_DeployDpf09AppsContracts())), 2); }
    function test_DeployDpf10Assistant_envKey_sameCreationsAsBefore() public { _same(ISigned(address(new H_DeployDpf10Assistant())), ISigned(address(new H_DeployDpf10Assistant())), 1); }
    function test_DeployDpf11Governance_envKey_sameCreationsAsBefore() public { _same(ISigned(address(new H_DeployDpf11Governance())), ISigned(address(new H_DeployDpf11Governance())), 2); }
    function test_DeployDpf12Ontology_envKey_sameCreationsAsBefore() public { _same(ISigned(address(new H_DeployDpf12Ontology())), ISigned(address(new H_DeployDpf12Ontology())), 1); }
    function test_DeployDpf13Procurement_envKey_sameCreationsAsBefore() public { _same(ISigned(address(new H_DeployDpf13Procurement())), ISigned(address(new H_DeployDpf13Procurement())), 1); }
    function test_DeployDpf14InterOrg_envKey_sameCreationsAsBefore() public { _same(ISigned(address(new H_DeployDpf14InterOrg())), ISigned(address(new H_DeployDpf14InterOrg())), 1); }
    function test_DeployDpf15Compliance_envKey_sameCreationsAsBefore() public { _same(ISigned(address(new H_DeployDpf15Compliance())), ISigned(address(new H_DeployDpf15Compliance())), 1); }
    function test_DeployDpf16Sponsor_envKey_sameCreationsAsBefore() public { _same(ISigned(address(new H_DeployDpf16Sponsor())), ISigned(address(new H_DeployDpf16Sponsor())), 1); }
    function test_DeployDpf17Release_envKey_sameCreationsAsBefore() public { _same(ISigned(address(new H_DeployDpf17Release())), ISigned(address(new H_DeployDpf17Release())), 1); }

    function test_wrongKey_isRefused() public {
        H_DeployDpf13Procurement h = new H_DeployDpf13Procurement();
        h.setSigner(PK, makeAddr("someone-else"));
        vm.expectRevert(bytes("EnvSigner: PRIVATE_KEY does not belong to EXPECTED_SENDER"));
        h.run();
    }

    function test_keyWithoutExpectedSender_isRefused() public {
        H_DeployDpf02Rbac h = new H_DeployDpf02Rbac();
        h.setSigner(PK, address(0));
        vm.expectRevert(bytes("EnvSigner: PRIVATE_KEY is set but EXPECTED_SENDER is not"));
        h.run();
    }

    function test_send_transfersValueFromTheEnvKey() public {
        H_Send s = new H_Send();
        address signer = vm.addr(PK);
        address to = makeAddr("deployer-to-fund");
        s.setSigner(PK, signer);
        s.setCall(to, 2 ether, "");
        uint64 n0 = vm.getNonce(signer);
        s.run();
        assertEq(to.balance, 2 ether, "value arrived");
        assertEq(vm.getNonce(signer), n0 + 1, "one transaction from the signer");
    }

    function test_send_callsWithData() public {
        H_Send s = new H_Send();
        Sink sink = new Sink();
        s.setSigner(PK, vm.addr(PK));
        s.setCall(address(sink), 1 ether, abi.encodeCall(Sink.poke, (42)));
        s.run();
        assertEq(sink.last(), 42);
        assertEq(address(sink).balance, 1 ether);
    }

    function test_send_refusesWrongKeyAndWrongTarget() public {
        H_Send s = new H_Send();
        Sink sink = new Sink();
        s.setSigner(PK, makeAddr("treasury"));
        s.setCall(makeAddr("x"), 1, "");
        vm.expectRevert(bytes("EnvSigner: PRIVATE_KEY does not belong to EXPECTED_SENDER"));
        s.run();
        s.setSigner(PK, vm.addr(PK));
        s.setCall(address(sink), 1, "");
        vm.expectRevert(bytes("SendWithEnvKey: plain transfer to a contract; pass DATA"));
        s.run();
        s.setCall(makeAddr("eoa"), 0, abi.encodeCall(Sink.poke, (1)));
        vm.expectRevert(bytes("SendWithEnvKey: DATA for an account without code"));
        s.run();
        s.setSigner(0, address(0));
        vm.expectRevert(bytes("SendWithEnvKey: PRIVATE_KEY is required"));
        s.run();
    }
}
