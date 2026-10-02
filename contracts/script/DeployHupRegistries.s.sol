// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "./ScriptEnv.sol";
import "./Salts.sol";

import {InitialAdmin} from "../src/lib/InitialAdmin.sol";
import "../src/cit_agent/MultisigTimelock2of3.sol";
import "../src/cit_agent/OrganizationSBT.sol";
import "../src/cit_agent/AgentSBT.sol";
import "../src/cit_agent/CapsuleRegistry.sol";
import "../src/cit_agent/AnchorRegistry.sol";
import "../src/cit_agent/BenchmarkRegistry.sol";
import "../src/SkillRegistry.sol";

/// @title DeployHupRegistries: HUP-S7.1 / federation F-4 redeploy set
/// @notice Deploys the registries the Citrate Core "Hermes upskill" features read,
///         deterministically, through the genesis Arachnid CREATE2 factory:
///
///           OrganizationSBT, AgentSBT, CapsuleRegistry   (admin-gated, born owned by ADMIN)
///           AnchorRegistry, BenchmarkRegistry, SkillRegistry  (no admin)
///
///         and checks that the registries owned by the main ceremony (`DeployAll`,
///         `DeployDpf02Rbac`, `RedeployIPFSIncentivesV3`) are present in the book with
///         code: ModelRegistry, InferenceRouter, LoRAFactory, X402Facilitator,
///         IPFSIncentivesV3, AgentDecisionRegistryV2. This script never deploys those.
///
///         Every address is keccak256(0xff ++ 0x4e59… ++ Salts.salt(name) ++
///         keccak256(init_code))[12:], so a rerun over a chain where a registry already
///         has code at its projection skips it (idempotent), and the same build lands the
///         same addresses on every rehearsal.
///
/// ADMIN. The admin-gated contracts take their owner as a constructor argument
/// (PBA-L2-002), so the deployer never holds admin and no ownership transfer is
/// needed. ADMIN is either
///   * `HUP_REGISTRY_ADMIN`, an existing multisig/timelock (on 40204 it must have
///     code and must not be the deployer), or
///   * a MultisigTimelock2of3 this script deploys by CREATE2 at
///     `Salts.salt("CitAgentTimelock")` from `HUP_TIMELOCK_OWNER_{0,1,2}` and
///     `HUP_TIMELOCK_DELAY` (default 2 days).
///
/// Signing comes from the forge CLI only (ScriptEnv). Operator usage is in
/// docs/ops/HUP_REGISTRY_REDEPLOY_RUNBOOK.md. The anvil rehearsal is
/// scripts/ops/hup-redeploy-dryrun.sh.
contract DeployHupRegistries is ScriptEnv {
    /// Genesis-allocated Arachnid deterministic deployer (EIP-2470 style).
    address public constant ARACHNID_FACTORY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    /// Default minimum delay for a timelock this script deploys.
    uint256 public constant DEFAULT_TIMELOCK_DELAY = 2 days;

    struct Config {
        address deployer;
        /// Existing admin. Zero means "deploy the CitAgentTimelock from timelockOwners".
        address admin;
        address[3] timelockOwners;
        uint256 timelockDelay;
        /// Book consulted for the ceremony-owned registries ("" skips the check off 40204).
        string bookPath;
    }

    struct Deployed {
        address admin;
        bool adminDeployedHere;
        address organizationSBT;
        address agentSBT;
        address capsuleRegistry;
        address anchorRegistry;
        address benchmarkRegistry;
        address skillRegistry;
    }

    /// Registries the HUP features read that the main ceremony deploys.
    function ceremonyOwnedNames() public pure returns (string[6] memory) {
        return [
            "ModelRegistry",
            "InferenceRouter",
            "LoRAFactory",
            "X402Facilitator",
            "IPFSIncentivesV3",
            "AgentDecisionRegistryV2"
        ];
    }

    // ── init codes + projections (pure: the book tool and the tests share these) ──

    function timelockInitCode(address[3] memory owners, uint256 delay) public pure returns (bytes memory) {
        return abi.encodePacked(type(MultisigTimelock2of3).creationCode, abi.encode(owners, delay));
    }

    function organizationInitCode(address admin) public pure returns (bytes memory) {
        return abi.encodePacked(type(OrganizationSBT).creationCode, abi.encode(admin));
    }

    function agentInitCode(address admin, address org) public pure returns (bytes memory) {
        return abi.encodePacked(type(AgentSBT).creationCode, abi.encode(admin, org));
    }

    function capsuleInitCode(address admin) public pure returns (bytes memory) {
        return abi.encodePacked(type(CapsuleRegistry).creationCode, abi.encode(admin));
    }

    function anchorInitCode() public pure returns (bytes memory) {
        return type(AnchorRegistry).creationCode;
    }

    function benchmarkInitCode() public pure returns (bytes memory) {
        return type(BenchmarkRegistry).creationCode;
    }

    function skillInitCode() public pure returns (bytes memory) {
        return type(SkillRegistry).creationCode;
    }

    /// CREATE2 projection through the Arachnid factory for a book name.
    function project(string memory name, bytes memory initCode) public pure returns (address) {
        return address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(bytes1(0xff), ARACHNID_FACTORY, Salts.salt(name), keccak256(initCode))
                    )
                )
            )
        );
    }

    /// Projections for a given admin (the CitAgentTimelock projection needs the owners).
    function projectAll(address admin) public pure returns (Deployed memory p) {
        p.admin = admin;
        p.organizationSBT = project("OrganizationSBT", organizationInitCode(admin));
        p.agentSBT = project("AgentSBT", agentInitCode(admin, p.organizationSBT));
        p.capsuleRegistry = project("CapsuleRegistry", capsuleInitCode(admin));
        p.anchorRegistry = project("AnchorRegistry", anchorInitCode());
        p.benchmarkRegistry = project("BenchmarkRegistry", benchmarkInitCode());
        p.skillRegistry = project("SkillRegistry", skillInitCode());
    }

    // ── entry points ─────────────────────────────────────────────────────────────

    function run() external returns (Deployed memory) {
        Config memory cfg;
        cfg.deployer = deployerAddress();
        cfg.admin = envAddressOr("HUP_REGISTRY_ADMIN", address(0));
        cfg.timelockOwners = [
            envAddressOr("HUP_TIMELOCK_OWNER_0", address(0)),
            envAddressOr("HUP_TIMELOCK_OWNER_1", address(0)),
            envAddressOr("HUP_TIMELOCK_OWNER_2", address(0))
        ];
        cfg.timelockDelay = envUintOr("HUP_TIMELOCK_DELAY", DEFAULT_TIMELOCK_DELAY);
        cfg.bookPath = vm.envOr("HUP_BOOK_PATH", string("addresses/40204.json"));
        return deployWith(cfg);
    }

    /// Env-free entry point (tests and the rehearsal call this directly).
    function deployWith(Config memory cfg) public returns (Deployed memory d) {
        require(cfg.deployer != address(0), "deployer required");
        bool live = block.chainid == 40204;

        console.log("=== HUP registry redeploy (HUP-S7.1) ===");
        console.log("chain id        :", block.chainid);
        console.log("deployer        :", cfg.deployer);
        require(ARACHNID_FACTORY.code.length != 0, "Arachnid CREATE2 factory has no code on this chain");

        if (live) _requireCeremonySet(cfg.bookPath);
        else if (bytes(cfg.bookPath).length != 0) _reportCeremonySet(cfg.bookPath);

        vm.startBroadcast(cfg.deployer);

        // 1. Admin.
        if (cfg.admin != address(0)) {
            d.admin = cfg.admin;
        } else {
            for (uint256 i = 0; i < 3; i++) {
                require(cfg.timelockOwners[i] != address(0), "set HUP_REGISTRY_ADMIN or HUP_TIMELOCK_OWNER_{0,1,2}");
            }
            bytes memory tlCode = timelockInitCode(cfg.timelockOwners, cfg.timelockDelay);
            address tl = project("CitAgentTimelock", tlCode);
            if (tl.code.length == 0) {
                address got = address(
                    new MultisigTimelock2of3{salt: Salts.salt("CitAgentTimelock")}(cfg.timelockOwners, cfg.timelockDelay)
                );
                require(got == tl, "CitAgentTimelock landed off its CREATE2 projection");
                d.adminDeployedHere = true;
            }
            d.admin = tl;
        }
        InitialAdmin.check(d.admin);
        require(!live || d.admin != cfg.deployer, "admin must not be the deployer on 40204");
        require(!live || d.admin.code.length != 0, "admin must be a deployed multisig on 40204");

        Deployed memory p = projectAll(d.admin);

        // 2. Admin-gated registries, born owned by the admin.
        if (p.organizationSBT.code.length == 0) {
            new OrganizationSBT{salt: Salts.salt("OrganizationSBT")}(d.admin);
        }
        if (p.agentSBT.code.length == 0) {
            new AgentSBT{salt: Salts.salt("AgentSBT")}(d.admin, OrganizationSBT(p.organizationSBT));
        }
        if (p.capsuleRegistry.code.length == 0) {
            new CapsuleRegistry{salt: Salts.salt("CapsuleRegistry")}(d.admin);
        }
        // 3. Append-anyone registries.
        if (p.anchorRegistry.code.length == 0) {
            new AnchorRegistry{salt: Salts.salt("AnchorRegistry")}();
        }
        if (p.benchmarkRegistry.code.length == 0) {
            new BenchmarkRegistry{salt: Salts.salt("BenchmarkRegistry")}();
        }
        if (p.skillRegistry.code.length == 0) {
            new SkillRegistry{salt: Salts.salt("SkillRegistry")}();
        }

        vm.stopBroadcast();

        d.organizationSBT = p.organizationSBT;
        d.agentSBT = p.agentSBT;
        d.capsuleRegistry = p.capsuleRegistry;
        d.anchorRegistry = p.anchorRegistry;
        d.benchmarkRegistry = p.benchmarkRegistry;
        d.skillRegistry = p.skillRegistry;

        verify(d);
        _printBook(d);
    }

    /// Read-only post-deploy checks (also the smoke read per contract). Reverts on any miss.
    function verify(Deployed memory d) public view {
        require(d.organizationSBT.code.length != 0, "OrganizationSBT has no code");
        require(d.agentSBT.code.length != 0, "AgentSBT has no code");
        require(d.capsuleRegistry.code.length != 0, "CapsuleRegistry has no code");
        require(d.anchorRegistry.code.length != 0, "AnchorRegistry has no code");
        require(d.benchmarkRegistry.code.length != 0, "BenchmarkRegistry has no code");
        require(d.skillRegistry.code.length != 0, "SkillRegistry has no code");

        require(OrganizationSBT(d.organizationSBT).owner() == d.admin, "OrganizationSBT owner != admin");
        require(AgentSBT(d.agentSBT).owner() == d.admin, "AgentSBT owner != admin");
        require(CapsuleRegistry(d.capsuleRegistry).owner() == d.admin, "CapsuleRegistry owner != admin");
        require(address(AgentSBT(d.agentSBT).orgContract()) == d.organizationSBT, "AgentSBT.orgContract mismatch");

        // Smoke reads: each call must decode (a wrong contract at the address reverts here).
        OrganizationSBT(d.organizationSBT).nextTokenId();
        AgentSBT(d.agentSBT).nextTokenId();
        CapsuleRegistry(d.capsuleRegistry).isRevoked(0);
        AnchorRegistry(d.anchorRegistry).rootCountByKind(AnchorRegistry.AnchorKind.NightlyMerkle);
        AnchorRegistry(d.anchorRegistry).rootsByKind(AnchorRegistry.AnchorKind.NightlyMerkle, 0, type(uint256).max);
        BenchmarkRegistry(d.benchmarkRegistry).metricCount(address(0), 0, bytes32(0), bytes32(0));
        SkillRegistry(d.skillRegistry).totalSkills();
        require(
            SkillRegistry(d.skillRegistry).skillHashOf(address(1), "probe", "1.0.0")
                == keccak256(abi.encode(address(1), "probe", "1.0.0")),
            "SkillRegistry is not the abi.encode version"
        );
    }

    // ── ceremony-owned set ───────────────────────────────────────────────────────

    function _bookAddress(string memory json, string memory name) internal view returns (address a) {
        string memory key = string.concat(".contracts.", name);
        if (!vm.keyExistsJson(json, key)) return address(0);
        return vm.parseJsonAddress(json, key);
    }

    function _requireCeremonySet(string memory bookPath) internal view {
        require(bytes(bookPath).length != 0, "HUP_BOOK_PATH required on 40204");
        string memory json = vm.readFile(bookPath);
        require(vm.parseJsonUint(json, ".chainId") == 40204, "book is not the 40204 book");
        string[6] memory names = ceremonyOwnedNames();
        string memory missing;
        for (uint256 i = 0; i < names.length; i++) {
            address a = _bookAddress(json, names[i]);
            if (a == address(0) || a.code.length == 0) missing = string.concat(missing, " ", names[i]);
        }
        require(
            bytes(missing).length == 0,
            string.concat("run the main ceremony and regenerate the book first; missing or no code:", missing)
        );
        console.log("ceremony-owned registries: all present with code");
    }

    function _reportCeremonySet(string memory bookPath) internal view {
        try vm.readFile(bookPath) returns (string memory json) {
            string[6] memory names = ceremonyOwnedNames();
            for (uint256 i = 0; i < names.length; i++) {
                address a = _bookAddress(json, names[i]);
                console.log(
                    string.concat("  ", names[i], a != address(0) && a.code.length != 0 ? ": has code" : ": absent here")
                );
            }
        } catch {
            console.log("book not readable; ceremony-owned check skipped (not chain 40204)");
        }
    }

    function _printBook(Deployed memory d) internal pure {
        console.log("");
        console.log("=== BOOK PINS (contracts/addresses/40204.json .contracts) ===");
        console.log("admin             :", d.admin);
        console.log("OrganizationSBT   :", d.organizationSBT);
        console.log("AgentSBT          :", d.agentSBT);
        console.log("CapsuleRegistry   :", d.capsuleRegistry);
        console.log("AnchorRegistry    :", d.anchorRegistry);
        console.log("BenchmarkRegistry :", d.benchmarkRegistry);
        console.log("SkillRegistry     :", d.skillRegistry);
        console.log("Next: scripts/ops/hup-book-update.py (see the runbook).");
    }
}
