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

/// r1007 option A (fed GO2 sheet section 12; lead 2026-11-11; reviews by Matr0xshka and
/// BerryManifold on env-key-signing @ 3f51a658). The 14 post-genesis (D2) scripts broadcast from
/// a key held only in the environment. For each script this checks that:
/// - the env-key path creates the r1007 nonce table's count at the signer's consecutive
///   CREATE addresses;
/// - each created contract's CODEHASH equals the CLI-wallet path's, after mapping the env
///   signer to the CLI sender and each env-created address to its CLI twin, so a different
///   governance or deployer baked into the bytecode fails;
/// - `governance()` and `owner()`, where a contract has them, agree under the same mapping;
/// - the guards hold:
///   - a key that does not belong to EXPECTED_SENDER is refused;
///   - a key with no EXPECTED_SENDER is refused;
///   - a run whose msg.sender (`forge --sender`) differs from EXPECTED_SENDER is refused;
///   - in ScriptEnv scripts, EXPECTED_SENDER must equal deployerAddress();
///   - on 40204, ROOT_GOVERNANCE must be set and must not be the sender.
/// Keys, deployer and governance come through virtual hooks, not vm.setEnv, because the env is
/// process-global and other suites run in parallel. The env values set here match the ones
/// PBA_R2_DeployScripts sets.
interface IH {
    function setSigner(uint256 key, address expected) external;
    function setDeployer(address deployer_) external;
    function setGovernance(address gov) external;
}

contract H_DeployDpf02Rbac is DeployDpf02Rbac {
    uint256 internal k;
    address internal e;
    address internal d;
    address internal g;
    function setSigner(uint256 key, address expected) external { k = key; e = expected; }
    function setDeployer(address deployer_) external { d = deployer_; }
    function setGovernance(address gov) external { g = gov; }
    function _envSignerKey() internal view override returns (uint256) { return k; }
    function _envExpectedSender() internal view override returns (address) { return e; }
    function _governance() internal view override returns (address) { return g == address(0) ? msg.sender : g; }
}

contract H_DeployDpf06Suppliers is DeployDpf06Suppliers {
    uint256 internal k;
    address internal e;
    address internal d;
    address internal g;
    function setSigner(uint256 key, address expected) external { k = key; e = expected; }
    function setDeployer(address deployer_) external { d = deployer_; }
    function setGovernance(address gov) external { g = gov; }
    function _envSignerKey() internal view override returns (uint256) { return k; }
    function _envExpectedSender() internal view override returns (address) { return e; }
    function _governance() internal view override returns (address) { return g == address(0) ? msg.sender : g; }
}

contract H_DeployDpf07FL is DeployDpf07FL {
    uint256 internal k;
    address internal e;
    address internal d;
    address internal g;
    function setSigner(uint256 key, address expected) external { k = key; e = expected; }
    function setDeployer(address deployer_) external { d = deployer_; }
    function setGovernance(address gov) external { g = gov; }
    function _envSignerKey() internal view override returns (uint256) { return k; }
    function _envExpectedSender() internal view override returns (address) { return e; }
    function _governance() internal view override returns (address) { return g == address(0) ? msg.sender : g; }
}

contract H_DeployQuorumS6 is DeployQuorumS6 {
    uint256 internal k;
    address internal e;
    address internal d;
    address internal g;
    function setSigner(uint256 key, address expected) external { k = key; e = expected; }
    function setDeployer(address deployer_) external { d = deployer_; }
    function setGovernance(address gov) external { g = gov; }
    function _envSignerKey() internal view override returns (uint256) { return k; }
    function _envExpectedSender() internal view override returns (address) { return e; }
    function _governance() internal view override returns (address) { return g == address(0) ? msg.sender : g; }
}

contract H_DeployDpf05Provenance is DeployDpf05Provenance {
    uint256 internal k;
    address internal e;
    address internal d;
    address internal g;
    function setSigner(uint256 key, address expected) external { k = key; e = expected; }
    function setDeployer(address deployer_) external { d = deployer_; }
    function setGovernance(address gov) external { g = gov; }
    function _envSignerKey() internal view override returns (uint256) { return k; }
    function _envExpectedSender() internal view override returns (address) { return e; }
    function _governance() internal view override returns (address) { return g == address(0) ? msg.sender : g; }
}

contract H_DeployDpf09AppsContracts is DeployDpf09AppsContracts {
    uint256 internal k;
    address internal e;
    address internal d;
    address internal g;
    function setSigner(uint256 key, address expected) external { k = key; e = expected; }
    function setDeployer(address deployer_) external { d = deployer_; }
    function setGovernance(address gov) external { g = gov; }
    function _envSignerKey() internal view override returns (uint256) { return k; }
    function _envExpectedSender() internal view override returns (address) { return e; }
    function deployerAddress() internal view override returns (address) { return d; }
}

contract H_DeployDpf10Assistant is DeployDpf10Assistant {
    uint256 internal k;
    address internal e;
    address internal d;
    address internal g;
    function setSigner(uint256 key, address expected) external { k = key; e = expected; }
    function setDeployer(address deployer_) external { d = deployer_; }
    function setGovernance(address gov) external { g = gov; }
    function _envSignerKey() internal view override returns (uint256) { return k; }
    function _envExpectedSender() internal view override returns (address) { return e; }
    function deployerAddress() internal view override returns (address) { return d; }
}

contract H_DeployDpf11Governance is DeployDpf11Governance {
    uint256 internal k;
    address internal e;
    address internal d;
    address internal g;
    function setSigner(uint256 key, address expected) external { k = key; e = expected; }
    function setDeployer(address deployer_) external { d = deployer_; }
    function setGovernance(address gov) external { g = gov; }
    function _envSignerKey() internal view override returns (uint256) { return k; }
    function _envExpectedSender() internal view override returns (address) { return e; }
    function deployerAddress() internal view override returns (address) { return d; }
}

contract H_DeployDpf12Ontology is DeployDpf12Ontology {
    uint256 internal k;
    address internal e;
    address internal d;
    address internal g;
    function setSigner(uint256 key, address expected) external { k = key; e = expected; }
    function setDeployer(address deployer_) external { d = deployer_; }
    function setGovernance(address gov) external { g = gov; }
    function _envSignerKey() internal view override returns (uint256) { return k; }
    function _envExpectedSender() internal view override returns (address) { return e; }
    function deployerAddress() internal view override returns (address) { return d; }
}

contract H_DeployDpf13Procurement is DeployDpf13Procurement {
    uint256 internal k;
    address internal e;
    address internal d;
    address internal g;
    function setSigner(uint256 key, address expected) external { k = key; e = expected; }
    function setDeployer(address deployer_) external { d = deployer_; }
    function setGovernance(address gov) external { g = gov; }
    function _envSignerKey() internal view override returns (uint256) { return k; }
    function _envExpectedSender() internal view override returns (address) { return e; }
    function deployerAddress() internal view override returns (address) { return d; }
}

contract H_DeployDpf14InterOrg is DeployDpf14InterOrg {
    uint256 internal k;
    address internal e;
    address internal d;
    address internal g;
    function setSigner(uint256 key, address expected) external { k = key; e = expected; }
    function setDeployer(address deployer_) external { d = deployer_; }
    function setGovernance(address gov) external { g = gov; }
    function _envSignerKey() internal view override returns (uint256) { return k; }
    function _envExpectedSender() internal view override returns (address) { return e; }
    function deployerAddress() internal view override returns (address) { return d; }
}

contract H_DeployDpf15Compliance is DeployDpf15Compliance {
    uint256 internal k;
    address internal e;
    address internal d;
    address internal g;
    function setSigner(uint256 key, address expected) external { k = key; e = expected; }
    function setDeployer(address deployer_) external { d = deployer_; }
    function setGovernance(address gov) external { g = gov; }
    function _envSignerKey() internal view override returns (uint256) { return k; }
    function _envExpectedSender() internal view override returns (address) { return e; }
    function deployerAddress() internal view override returns (address) { return d; }
}

contract H_DeployDpf16Sponsor is DeployDpf16Sponsor {
    uint256 internal k;
    address internal e;
    address internal d;
    address internal g;
    function setSigner(uint256 key, address expected) external { k = key; e = expected; }
    function setDeployer(address deployer_) external { d = deployer_; }
    function setGovernance(address gov) external { g = gov; }
    function _envSignerKey() internal view override returns (uint256) { return k; }
    function _envExpectedSender() internal view override returns (address) { return e; }
    function deployerAddress() internal view override returns (address) { return d; }
}

contract H_DeployDpf17Release is DeployDpf17Release {
    uint256 internal k;
    address internal e;
    address internal d;
    address internal g;
    function setSigner(uint256 key, address expected) external { k = key; e = expected; }
    function setDeployer(address deployer_) external { d = deployer_; }
    function setGovernance(address gov) external { g = gov; }
    function _envSignerKey() internal view override returns (uint256) { return k; }
    function _envExpectedSender() internal view override returns (address) { return e; }
    function deployerAddress() internal view override returns (address) { return d; }
}

contract H_Send is SendWithEnvKey {
    uint256 internal k;
    address internal e;
    address internal t;
    uint256 internal v;
    bytes internal dd;
    function setSigner(uint256 key, address expected) external { k = key; e = expected; }
    function setCall(address to, uint256 value, bytes calldata data) external { t = to; v = value; dd = data; }
    function _envSignerKey() internal view override returns (uint256) { return k; }
    function _envExpectedSender() internal view override returns (address) { return e; }
    function _to() internal view override returns (address) { return t; }
    function _value() internal view override returns (uint256) { return v; }
    function _data() internal view override returns (bytes memory) { return dd; }
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

    function _creations(address by) internal returns (address[] memory out) {
        VmSafe.AccountAccess[] memory acc = vm.stopAndReturnStateDiff();
        uint256 n;
        for (uint256 i; i < acc.length; i++) {
            if (acc[i].kind == VmSafe.AccountAccessKind.Create && acc[i].accessor == by) n++;
        }
        out = new address[](n);
        n = 0;
        for (uint256 i; i < acc.length; i++) {
            if (acc[i].kind == VmSafe.AccountAccessKind.Create && acc[i].accessor == by) out[n++] = acc[i].account;
        }
    }

    function _run(address h, address caller) internal {
        vm.prank(caller, caller);
        (bool ok, bytes memory ret) = h.call(abi.encodeWithSignature("run()"));
        if (!ok) {
            assembly { revert(add(ret, 32), mload(ret)) }
        }
    }

    /// Replace every occurrence of each `from[i]` (20 bytes) in `code` with `to[i]`.
    function _map(bytes memory code, address[] memory from, address[] memory to) internal pure returns (bytes memory) {
        for (uint256 m; m < from.length; m++) {
            bytes20 f = bytes20(from[m]);
            bytes20 t = bytes20(to[m]);
            if (code.length < 20) break;
            for (uint256 i; i + 20 <= code.length; i++) {
                bool hit = true;
                for (uint256 j; j < 20; j++) {
                    if (code[i + j] != f[j]) { hit = false; break; }
                }
                if (hit) {
                    for (uint256 j; j < 20; j++) code[i + j] = t[j];
                    i += 19;
                }
            }
        }
        return code;
    }

    function _view(address c, string memory sig) internal view returns (bool ok, address v) {
        bytes memory r;
        (ok, r) = c.staticcall(abi.encodeWithSignature(sig));
        if (ok && r.length == 32) v = abi.decode(r, (address));
        else ok = false;
    }

    function _translate(address v, address[] memory from, address[] memory to) internal pure returns (address) {
        for (uint256 i; i < from.length; i++) if (v == from[i]) return to[i];
        return v;
    }

    /// The CLI-wallet path first (forge's default sender), then the env-key path from a
    /// different account. Each path's creations come from its own sender's nonces.
    function _same(address envH, address cliH, uint256 count) internal {
        address signer = vm.addr(PK);
        IH(cliH).setSigner(0, address(0));
        IH(cliH).setDeployer(SENDER);
        IH(cliH).setGovernance(multisig);
        vm.startStateDiffRecording();
        _run(cliH, SENDER);
        address[] memory b = _creations(SENDER);
        assertEq(b.length, count, "creations from the CLI wallet");

        IH(envH).setSigner(PK, signer);
        IH(envH).setDeployer(signer);
        IH(envH).setGovernance(multisig);
        uint64 n0 = vm.getNonce(signer);
        vm.startStateDiffRecording();
        _run(envH, signer);
        address[] memory a = _creations(signer);
        assertEq(a.length, count, "creations from the env key");

        address[] memory from = new address[](count + 1);
        address[] memory to = new address[](count + 1);
        from[0] = signer;
        to[0] = SENDER;
        for (uint256 i; i < count; i++) {
            from[i + 1] = a[i];
            to[i + 1] = b[i];
        }
        for (uint256 i; i < count; i++) {
            assertEq(a[i], vm.computeCreateAddress(signer, n0 + i), "CREATE address at the next nonce");
            assertEq(keccak256(_map(a[i].code, from, to)), b[i].codehash, "same codehash once the sender and created addresses are mapped");
            string[2] memory sigs = ["governance()", "owner()"];
            for (uint256 s; s < 2; s++) {
                (bool oka, address va) = _view(a[i], sigs[s]);
                (bool okb, address vb) = _view(b[i], sigs[s]);
                assertEq(oka, okb, sigs[s]);
                if (oka) assertEq(_translate(va, from, to), vb, sigs[s]);
            }
        }
    }

    function test_DeployDpf02Rbac_envKey_sameContractsAsBefore() public { _same(address(new H_DeployDpf02Rbac()), address(new H_DeployDpf02Rbac()), 6); }
    function test_DeployDpf06Suppliers_envKey_sameContractsAsBefore() public { _same(address(new H_DeployDpf06Suppliers()), address(new H_DeployDpf06Suppliers()), 2); }
    function test_DeployDpf07FL_envKey_sameContractsAsBefore() public { _same(address(new H_DeployDpf07FL()), address(new H_DeployDpf07FL()), 1); }
    function test_DeployQuorumS6_envKey_sameContractsAsBefore() public { _same(address(new H_DeployQuorumS6()), address(new H_DeployQuorumS6()), 8); }
    function test_DeployDpf05Provenance_envKey_sameContractsAsBefore() public { _same(address(new H_DeployDpf05Provenance()), address(new H_DeployDpf05Provenance()), 1); }
    function test_DeployDpf09AppsContracts_envKey_sameContractsAsBefore() public { _same(address(new H_DeployDpf09AppsContracts()), address(new H_DeployDpf09AppsContracts()), 2); }
    function test_DeployDpf10Assistant_envKey_sameContractsAsBefore() public { _same(address(new H_DeployDpf10Assistant()), address(new H_DeployDpf10Assistant()), 1); }
    function test_DeployDpf11Governance_envKey_sameContractsAsBefore() public { _same(address(new H_DeployDpf11Governance()), address(new H_DeployDpf11Governance()), 2); }
    function test_DeployDpf12Ontology_envKey_sameContractsAsBefore() public { _same(address(new H_DeployDpf12Ontology()), address(new H_DeployDpf12Ontology()), 1); }
    function test_DeployDpf13Procurement_envKey_sameContractsAsBefore() public { _same(address(new H_DeployDpf13Procurement()), address(new H_DeployDpf13Procurement()), 1); }
    function test_DeployDpf14InterOrg_envKey_sameContractsAsBefore() public { _same(address(new H_DeployDpf14InterOrg()), address(new H_DeployDpf14InterOrg()), 1); }
    function test_DeployDpf15Compliance_envKey_sameContractsAsBefore() public { _same(address(new H_DeployDpf15Compliance()), address(new H_DeployDpf15Compliance()), 1); }
    function test_DeployDpf16Sponsor_envKey_sameContractsAsBefore() public { _same(address(new H_DeployDpf16Sponsor()), address(new H_DeployDpf16Sponsor()), 1); }
    function test_DeployDpf17Release_envKey_sameContractsAsBefore() public { _same(address(new H_DeployDpf17Release()), address(new H_DeployDpf17Release()), 1); }

    function test_wrongKey_isRefused() public {
        H_DeployDpf13Procurement h = new H_DeployDpf13Procurement();
        h.setSigner(PK, makeAddr("someone-else"));
        h.setDeployer(makeAddr("someone-else"));
        vm.expectRevert(bytes("EnvSigner: PRIVATE_KEY does not belong to EXPECTED_SENDER"));
        vm.prank(makeAddr("someone-else"), makeAddr("someone-else"));
        h.run();
    }

    function test_keyWithoutExpectedSender_isRefused() public {
        H_DeployDpf02Rbac h = new H_DeployDpf02Rbac();
        h.setSigner(PK, address(0));
        h.setGovernance(multisig);
        vm.expectRevert(bytes("EnvSigner: PRIVATE_KEY is set but EXPECTED_SENDER is not"));
        h.run();
    }

    function test_aSenderOtherThanExpected_isRefused() public {
        H_DeployDpf02Rbac h = new H_DeployDpf02Rbac();
        address signer = vm.addr(PK);
        h.setSigner(PK, signer);
        h.setGovernance(multisig);
        vm.expectRevert(bytes("EnvSigner: run forge with --sender EXPECTED_SENDER"));
        vm.prank(SENDER, SENDER);
        h.run();
    }

    function test_scriptEnv_expectedSenderMustBeTheDeployer() public {
        H_DeployDpf13Procurement h = new H_DeployDpf13Procurement();
        address signer = vm.addr(PK);
        h.setSigner(PK, signer);
        h.setDeployer(SENDER);
        vm.expectRevert(bytes("EnvSigner: EXPECTED_SENDER is not the script's deployer"));
        vm.prank(signer, signer);
        h.run();
    }

    function test_rootGovernance_mustBeSetAndNotTheSenderOn40204() public {
        vm.chainId(40204);
        H_DeployDpf02Rbac h = new H_DeployDpf02Rbac();
        address signer = vm.addr(PK);
        h.setSigner(PK, signer);
        h.setGovernance(address(0)); // unset: the old fallback to msg.sender
        vm.expectRevert(bytes("ROOT_GOVERNANCE must be set to a non-deployer address on 40204"));
        vm.prank(signer, signer);
        h.run();
        H_DeployDpf02Rbac h2 = new H_DeployDpf02Rbac();
        h2.setSigner(PK, signer);
        h2.setGovernance(signer);
        vm.expectRevert(bytes("ROOT_GOVERNANCE must be set to a non-deployer address on 40204"));
        vm.prank(signer, signer);
        h2.run();
    }

    function test_send_transfersValueFromTheEnvKey() public {
        H_Send s = new H_Send();
        address signer = vm.addr(PK);
        address to = makeAddr("deployer-to-fund");
        s.setSigner(PK, signer);
        s.setCall(to, 2 ether, "");
        uint64 n0 = vm.getNonce(signer);
        vm.prank(signer, signer);
        s.run();
        assertEq(to.balance, 2 ether, "value arrived");
        assertEq(vm.getNonce(signer), n0 + 1, "one transaction from the signer");
    }

    function test_send_callsWithData() public {
        H_Send s = new H_Send();
        Sink sink = new Sink();
        s.setSigner(PK, vm.addr(PK));
        s.setCall(address(sink), 1 ether, abi.encodeCall(Sink.poke, (42)));
        vm.prank(vm.addr(PK), vm.addr(PK));
        s.run();
        assertEq(sink.last(), 42);
        assertEq(address(sink).balance, 1 ether);
    }

    function test_send_refusesWrongKeyWrongSenderAndWrongTarget() public {
        H_Send s = new H_Send();
        Sink sink = new Sink();
        address signer = vm.addr(PK);
        s.setSigner(PK, makeAddr("treasury"));
        s.setCall(makeAddr("x"), 1, "");
        vm.expectRevert(bytes("EnvSigner: PRIVATE_KEY does not belong to EXPECTED_SENDER"));
        vm.prank(makeAddr("treasury"), makeAddr("treasury"));
        s.run();
        s.setSigner(PK, signer);
        vm.expectRevert(bytes("EnvSigner: run forge with --sender EXPECTED_SENDER"));
        vm.prank(SENDER, SENDER);
        s.run();
        s.setCall(address(sink), 1, "");
        vm.expectRevert(bytes("SendWithEnvKey: plain transfer to a contract; pass DATA"));
        vm.prank(signer, signer);
        s.run();
        s.setCall(makeAddr("eoa"), 0, abi.encodeCall(Sink.poke, (1)));
        vm.expectRevert(bytes("SendWithEnvKey: DATA for an account without code"));
        vm.prank(signer, signer);
        s.run();
        s.setSigner(0, address(0));
        vm.expectRevert(bytes("SendWithEnvKey: PRIVATE_KEY is required"));
        s.run();
    }
}
