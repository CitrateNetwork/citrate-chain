// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "../../script/Salts.sol";
import {DeployEntryPoint} from "../../script/aa/DeployEntryPoint.s.sol";

import {EntryPoint} from "@account-abstraction/core/EntryPoint.sol";
import {IEntryPoint as IAaEntryPoint} from "@account-abstraction/interfaces/IEntryPoint.sol";
import {IEntryPoint as IKernelEntryPoint} from "@kernel/interfaces/IEntryPoint.sol";
import {GuardianRecoveryModule} from "../../src/aa/recovery/GuardianRecoveryModule.sol";
import {CitrateWallet} from "../../src/aa/wallet/CitrateWallet.sol";
import {CitrateWalletFactory} from "../../src/aa/factory/CitrateWalletFactory.sol";
import {CitratePaymaster} from "../../src/aa/paymaster/CitratePaymaster.sol";

/**
 * @title AaDeterminismTest — WS-3 CI teeth for a reroll-STABLE AA stack
 * @notice Proves the whole AA cascade deploys via CREATE2 with the canonical
 *         Salts, so each address is a pure function of (salt, init_code,
 *         deployer) and is INDEPENDENT of the broadcaster's nonce / deploy
 *         order. The cascade EMBEDS the EntryPoint:
 *
 *             EntryPoint  ── (address) ──►  CitrateWallet (walletImpl)
 *             walletImpl  ── (address) ──►  CitrateWalletFactory
 *             EntryPoint + factory ──────►  CitratePaymaster
 *
 *         so once the EntryPoint is deterministic (WS-3: DeployEntryPoint via
 *         `new EntryPoint{salt: Salts.salt("EntryPoint")}()`), the factory,
 *         paymaster and walletImpl are deterministic too — they move exactly
 *         ONCE, to new permanent addresses, at this reroll.
 *
 * REGRESSION TEETH: if anyone reverts a `new X{salt: …}(…)` back to a plain
 * `new X(…)` (nonce-deploy), the resulting CREATE address stops matching
 * `computeCreate2Address`, and these asserts fail — so "the AA stack scrambles
 * every reroll" cannot silently come back.
 *
 * NB: in a forge TEST, `new X{salt:}` uses CREATE2 from `address(this)` (the
 * test contract), not the genesis Arachnid 0x4e59… factory that forge SCRIPTS
 * use. The determinism PROPERTY is identical either way; only the deployer
 * differs. The property asserts use `address(this)`; the PRODUCTION address
 * projection (test_report_production_addresses) uses `CREATE2_FACTORY` (0x4e59…)
 * — those logged values are what every consumer re-pins ONCE.
 */
contract AaDeterminismTest is Test {
    // Canonical constructor args for chain 40204 (from .env.testnet /
    // scripts/ops/post-reroll-redeploy.sh). The factory + paymaster addresses
    // are a function of these, so they are pinned here to compute the real
    // production addresses.
    address internal constant IDENTITY_SIGNER = 0x8A9062625E98666Fc0072Ee2E7CB8AB08Bd1b651;
    address internal constant OWNER = 0x4250675F9015E65fC866F3a373F82bb9DFc000c6; // = DEPLOYER_ADDRESS default
    address internal constant SPONSOR_SIGNER = 0x03067c230C3a13F801B2C285f43D1C6264d6b2a4;

    // Paymaster caps — DeployAA defaults (no env override on 40204).
    uint256 internal constant DAILY_CAP = 0.01 ether;
    uint256 internal constant RECOVERY_CAP = 0.01 ether;
    uint256 internal constant FIRST_OP_CAP = 0.02 ether;
    uint256 internal constant MAX_FEE_CEIL = 20 gwei;
    uint256 internal constant GLOBAL_CAP = 5 ether;

    function _assertCreate2FromHere(address deployed, bytes32 salt, bytes memory initCode) internal view {
        address expected = vm.computeCreate2Address(salt, keccak256(initCode), address(this));
        assertEq(deployed, expected, "deploy is not CREATE2 / wrong salt");
    }

    /// CREATE2 address as produced through the Arachnid factory (0x4e59…) that
    /// forge SCRIPTS route `new X{salt:}` through — i.e. the real on-chain
    /// address a reroll ceremony yields.
    function _projectProd(bytes32 salt, bytes memory initCode) internal pure returns (address) {
        return address(
            uint160(
                uint256(keccak256(abi.encodePacked(bytes1(0xff), CREATE2_FACTORY, salt, keccak256(initCode))))
            )
        );
    }

    /// The EntryPoint deploys deterministically and lands at its projection.
    function test_entryPoint_is_create2() public {
        EntryPoint ep = new EntryPoint{salt: Salts.salt("EntryPoint")}();
        _assertCreate2FromHere(address(ep), Salts.salt("EntryPoint"), type(EntryPoint).creationCode);
    }

    /// The DeployEntryPoint script's pure `projectedEntryPoint()` helper agrees
    /// with the canonical Arachnid-deployer CREATE2 formula.
    function test_projectedEntryPoint_helper_matches_arachnid_formula() public {
        DeployEntryPoint dep = new DeployEntryPoint();
        address expected = _projectProd(Salts.salt("EntryPoint"), type(EntryPoint).creationCode);
        assertEq(dep.projectedEntryPoint(), expected, "projectedEntryPoint() != 0x4e59 CREATE2 projection");
    }

    /// The full embedded cascade is CREATE2 end-to-end: EntryPoint → walletImpl
    /// → factory → paymaster, plus the standalone guardian module.
    function test_full_cascade_is_create2() public {
        EntryPoint ep = new EntryPoint{salt: Salts.salt("EntryPoint")}();
        _assertCreate2FromHere(address(ep), Salts.salt("EntryPoint"), type(EntryPoint).creationCode);

        GuardianRecoveryModule guardian = new GuardianRecoveryModule{salt: Salts.salt("GuardianRecoveryModule")}();
        _assertCreate2FromHere(
            address(guardian), Salts.salt("GuardianRecoveryModule"), type(GuardianRecoveryModule).creationCode
        );

        CitrateWallet walletImpl = new CitrateWallet{salt: Salts.salt("CitrateWallet")}(IKernelEntryPoint(address(ep)));
        _assertCreate2FromHere(
            address(walletImpl),
            Salts.salt("CitrateWallet"),
            abi.encodePacked(type(CitrateWallet).creationCode, abi.encode(address(ep)))
        );

        CitrateWalletFactory factory =
            new CitrateWalletFactory{salt: Salts.salt("CitrateWalletFactory")}(address(walletImpl), IDENTITY_SIGNER, OWNER);
        _assertCreate2FromHere(
            address(factory),
            Salts.salt("CitrateWalletFactory"),
            abi.encodePacked(
                type(CitrateWalletFactory).creationCode, abi.encode(address(walletImpl), IDENTITY_SIGNER, OWNER)
            )
        );

        CitratePaymaster paymaster = new CitratePaymaster{salt: Salts.salt("CitratePaymaster")}(
            IAaEntryPoint(address(ep)),
            OWNER,
            address(factory),
            SPONSOR_SIGNER,
            DAILY_CAP,
            RECOVERY_CAP,
            FIRST_OP_CAP,
            MAX_FEE_CEIL,
            GLOBAL_CAP
        );
        _assertCreate2FromHere(
            address(paymaster),
            Salts.salt("CitratePaymaster"),
            abi.encodePacked(
                type(CitratePaymaster).creationCode,
                abi.encode(
                    address(ep),
                    OWNER,
                    address(factory),
                    SPONSOR_SIGNER,
                    DAILY_CAP,
                    RECOVERY_CAP,
                    FIRST_OP_CAP,
                    MAX_FEE_CEIL,
                    GLOBAL_CAP
                )
            )
        );
    }

    /// The cascade address must not depend on the deployer's nonce.
    function test_cascade_addresses_are_nonce_independent() public {
        bytes32 s = Salts.salt("EntryPoint");
        bytes32 h = keccak256(type(EntryPoint).creationCode);
        address a0 = vm.computeCreate2Address(s, h, CREATE2_FACTORY);
        vm.setNonce(address(this), 98765);
        address a1 = vm.computeCreate2Address(s, h, CREATE2_FACTORY);
        assertEq(a0, a1, "CREATE2 address must not depend on nonce");
    }

    /// Distinct salts for distinct contracts (no accidental collision).
    function test_aa_salts_are_distinct() public pure {
        bytes32[5] memory salts = [
            Salts.salt("EntryPoint"),
            Salts.salt("GuardianRecoveryModule"),
            Salts.salt("CitrateWallet"),
            Salts.salt("CitrateWalletFactory"),
            Salts.salt("CitratePaymaster")
        ];
        for (uint256 i = 0; i < salts.length; i++) {
            for (uint256 j = i + 1; j < salts.length; j++) {
                assertTrue(salts[i] != salts[j], "AA salt collision");
            }
        }
    }

    /// REPORT: the permanent production addresses (Arachnid 0x4e59… deployer)
    /// every consumer re-pins ONCE this reroll. Logged with `-vv`.
    function test_report_production_addresses() public pure {
        address ep = _projectProd(Salts.salt("EntryPoint"), type(EntryPoint).creationCode);
        address guardian =
            _projectProd(Salts.salt("GuardianRecoveryModule"), type(GuardianRecoveryModule).creationCode);
        address walletImpl = _projectProd(
            Salts.salt("CitrateWallet"), abi.encodePacked(type(CitrateWallet).creationCode, abi.encode(ep))
        );
        address factory = _projectProd(
            Salts.salt("CitrateWalletFactory"),
            abi.encodePacked(
                type(CitrateWalletFactory).creationCode, abi.encode(walletImpl, IDENTITY_SIGNER, OWNER)
            )
        );
        address paymaster = _projectProd(
            Salts.salt("CitratePaymaster"),
            abi.encodePacked(
                type(CitratePaymaster).creationCode,
                abi.encode(
                    ep, OWNER, factory, SPONSOR_SIGNER, DAILY_CAP, RECOVERY_CAP, FIRST_OP_CAP, MAX_FEE_CEIL, GLOBAL_CAP
                )
            )
        );

        console2.log("== WS-3 permanent AA addresses (deployer 0x4e59..4956C) ==");
        console2.log("CITRATE_AA_ENTRY_POINT      = %s", ep);
        console2.log("CITRATE_AA_GUARDIAN_RECOVERY= %s", guardian);
        console2.log("CITRATE_AA_WALLET_IMPL      = %s", walletImpl);
        console2.log("CITRATE_AA_FACTORY          = %s", factory);
        console2.log("CITRATE_AA_PAYMASTER        = %s", paymaster);
    }
}
