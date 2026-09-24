// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {IModelRegistry} from "../src/interfaces/IModelRegistry.sol";

/**
 * @title RegisterStarterModels
 * @notice Batch-registers the curated set of "starter" models + LoRAs on
 *         testnet so a fresh wallet sees real options in
 *         Settings → AI Configuration → Download.
 *
 * Run order:
 *
 *  1. Pin each artifact (full models and LoRAs) to the team's IPFS node
 *     and capture the resulting CIDs.
 *  2. Fill the CID strings into the MODELS / LORAS arrays below.
 *  3. Set REGISTRY_ADDR to the deployed ModelRegistry on the target chain
 *     (testnet-beta, post-2026-06-08-reroll: 0x11a5e6f57751d8fa1c5b58ad2bf13528160985f0).
 *  4. Fund the deployer with at least 0.1 tCTR per artifact (registration
 *     fee is 0.1 ether per registerModel call).
 *  5. Run:
 *
 *       forge script script/RegisterStarterModels.s.sol:RegisterStarterModels \
 *         --rpc-url https://rpc.citrate.ai \
 *         --broadcast --private-key $REGISTRAR_PRIVATE_KEY
 *
 * Re-running is safe — the contract emits "Model already exists" if a
 * duplicate (msg.sender, name, totalModels) collision is detected; we
 * surface that as a console log rather than a revert via try/catch.
 *
 * The wallet's Settings → AI Configuration → Download surfaces every
 * registered model + its IPFS CID; users can then download via IPFS.
 */
contract RegisterStarterModels is Script {
    /// @notice ModelRegistry deployed at this address on chain id 40204.
    /// Bumped here so we don't ask `vm.envAddress` and keep the script
    /// runnable from CI without env wiring.
    /// CREATE2 reroll-stable address book (#41): this is now fixed across
    /// rerolls unless Salts.VERSION is bumped. Source of truth + verify:
    ///   jq -r '.contracts.ModelRegistry' contracts/addresses/40204.json
    address public constant REGISTRY_ADDR = 0xba36fA0Da9327030Bd14351db968c8C43c5a67e4;

    /// @notice Per-call fee charged by ModelRegistry.registerModel.
    uint256 public constant REGISTRATION_FEE = 0.1 ether;

    /// @notice Compact description of one artifact to register. We use this
    ///         shape (rather than the full ModelMetadata struct) because the
    ///         metadata's nested string arrays are awkward to declare inline
    ///         and we want the array of starters readable at a glance.
    struct StarterModel {
        string  name;            // e.g. "gemma-4-E4B-it-Q4_K_M"
        string  framework;       // "llama.cpp" / "transformers" / "ggml"
        string  version;         // upstream version tag
        string  ipfsCID;         // bafy… — fill in after pinning
        uint256 sizeBytes;       // file size (for UI / quota / billing)
        uint256 inferencePrice;  // wei per inference; 0 = free / pay-by-other
        string  description;     // short human-readable
        string  license;         // SPDX-style identifier
        string[] tags;           // ["chat","code","multimodal",…]
    }

    // ──────────────────────────────────────────────────────────────────
    // Curated starter set
    //
    // CIDs are EMPTY here on purpose. Fill them in after pinning each
    // artifact to the team IPFS node. Empty CID → skipped at registration
    // time with a console log, so partial pinning is safe.
    // ──────────────────────────────────────────────────────────────────

    function _models() internal pure returns (StarterModel[] memory list) {
        list = new StarterModel[](5);

        // 1. Default: ships bundled in the wallet installer.
        list[0] = StarterModel({
            name:           "gemma-4-E4B-it-Q4_K_M",
            framework:      "llama.cpp",
            version:        "1.0.0",
            ipfsCID:        "QmS6EeHFQbUudT9HEBYAt5JMwjk5ugGSCvvPFLkxk7rhJ3", // CIDv0 — verified against the droplet's `ipfs add` output 2026-05-31
            sizeBytes:      5335289824,                       // 4.96 GB (5,335,289,824 bytes; sha256 90ce98…0313e9f)
            inferencePrice: 0,
            description:    "Google Gemma 4 E4B-it (4-bit Q4_K_M). Multimodal, 128K ctx, native function-calling. Default chat model bundled with the wallet.",
            license:        "Gemma-Terms-of-Use-2025",
            tags:           _tags3("chat", "multimodal", "default")
        });

        // 2. Smaller, faster fallback for low-spec machines.
        list[1] = StarterModel({
            name:           "qwen2.5-1.5b-instruct-q4_0",
            framework:      "llama.cpp",
            version:        "2.5",
            ipfsCID:        "", // TODO
            sizeBytes:      1075000000,                       // ~1.0 GB
            inferencePrice: 0,
            description:    "Qwen 2.5 1.5B Instruct (4-bit Q4_0). Apache 2.0, multilingual, small footprint.",
            license:        "Apache-2.0",
            tags:           _tags2("chat", "small")
        });

        // 3. Strongest small coder.
        list[2] = StarterModel({
            name:           "phi-3-mini-4k-instruct-q4_k_m",
            framework:      "llama.cpp",
            version:        "3.0",
            ipfsCID:        "", // TODO
            sizeBytes:      2400000000,                       // ~2.2 GB
            inferencePrice: 0,
            description:    "Microsoft Phi-3 Mini 4K Instruct (4-bit Q4_K_M). MIT, strong reasoning + code.",
            license:        "MIT",
            tags:           _tags2("chat", "code")
        });

        // 4. Tiny baseline.
        list[3] = StarterModel({
            name:           "llama-3.2-1b-instruct-q4",
            framework:      "llama.cpp",
            version:        "3.2",
            ipfsCID:        "", // TODO
            sizeBytes:      750000000,                        // ~0.7 GB
            inferencePrice: 0,
            description:    "Meta Llama 3.2 1B Instruct (4-bit). Llama 3.2 Community License, smallest credible chat.",
            license:        "Llama-3.2-Community",
            tags:           _tags2("chat", "small")
        });

        // 5. Truly permissive tiny.
        list[4] = StarterModel({
            name:           "tinyllama-1.1b-chat-q4_k_m",
            framework:      "llama.cpp",
            version:        "1.1",
            ipfsCID:        "", // TODO
            sizeBytes:      700000000,                        // ~0.7 GB
            inferencePrice: 0,
            description:    "TinyLlama 1.1B Chat (4-bit Q4_K_M). Apache 2.0.",
            license:        "Apache-2.0",
            tags:           _tags2("chat", "tiny")
        });
    }

    function _loras() internal pure returns (StarterModel[] memory list) {
        list = new StarterModel[](5);

        // Coding-focused LoRAs. All sizes nominal — replace with actual file
        // sizes after pinning. ipfsCID empty pending team-IPFS pinning.
        list[0] = StarterModel({
            name:           "wizardcoder-1b-lora",
            framework:      "peft",
            version:        "1.0",
            ipfsCID:        "", // TODO
            sizeBytes:      50000000,
            inferencePrice: 0,
            description:    "WizardCoder LoRA adapter targeting general code completion.",
            license:        "Apache-2.0",
            tags:           _tags2("lora", "code")
        });

        list[1] = StarterModel({
            name:           "magicoder-s-ds-lora",
            framework:      "peft",
            version:        "1.0",
            ipfsCID:        "", // TODO
            sizeBytes:      60000000,
            inferencePrice: 0,
            description:    "Magicoder-S-DS LoRA - instruction-tuned coding adapter.",
            license:        "Apache-2.0",
            tags:           _tags2("lora", "code")
        });

        list[2] = StarterModel({
            name:           "codealpaca-lora",
            framework:      "peft",
            version:        "1.0",
            ipfsCID:        "", // TODO
            sizeBytes:      40000000,
            inferencePrice: 0,
            description:    "CodeAlpaca-style instruction-following LoRA.",
            license:        "Apache-2.0",
            tags:           _tags2("lora", "code")
        });

        list[3] = StarterModel({
            name:           "deepseek-coder-1.3b-lora",
            framework:      "peft",
            version:        "1.0",
            ipfsCID:        "", // TODO
            sizeBytes:      55000000,
            inferencePrice: 0,
            description:    "DeepSeek-Coder 1.3B LoRA - compact, code-completion focused.",
            license:        "DeepSeek-License",
            tags:           _tags2("lora", "code")
        });

        list[4] = StarterModel({
            name:           "functionary-agent-lora",
            framework:      "peft",
            version:        "1.0",
            ipfsCID:        "", // TODO
            sizeBytes:      45000000,
            inferencePrice: 0,
            description:    "Functionary/Glaive-style tool-calling agent LoRA.",
            license:        "Apache-2.0",
            tags:           _tags2("lora", "agent")
        });
    }

    // ──────────────────────────────────────────────────────────────────
    // Run
    // ──────────────────────────────────────────────────────────────────

    function run() external {
        vm.startBroadcast();

        IModelRegistry registry = IModelRegistry(REGISTRY_ADDR);

        StarterModel[] memory models = _models();
        StarterModel[] memory loras  = _loras();

        _registerBatch(registry, models, "model");
        _registerBatch(registry, loras,  "lora");

        vm.stopBroadcast();
    }

    function _registerBatch(
        IModelRegistry registry,
        StarterModel[] memory items,
        string memory label
    ) internal {
        for (uint256 i = 0; i < items.length; i++) {
            StarterModel memory m = items[i];

            if (bytes(m.ipfsCID).length == 0) {
                console.log("skip %s [%s]: empty CID - pin to IPFS and edit the script", label, m.name);
                continue;
            }

            // Inline construction of the ModelMetadata struct expected by the
            // registry. inputShape/outputShape stay empty here — they're
            // free-form text fields the wallet UI doesn't depend on yet.
            IModelRegistry.ModelMetadata memory meta = IModelRegistry.ModelMetadata({
                description: m.description,
                inputShape:  new string[](0),
                outputShape: new string[](0),
                parameters:  0,
                license:     m.license,
                tags:        m.tags
            });

            try registry.registerModel{value: REGISTRATION_FEE}(
                m.name,
                m.framework,
                m.version,
                m.ipfsCID,
                m.sizeBytes,
                m.inferencePrice,
                meta
            ) returns (bytes32 modelHash) {
                console.log("registered %s [%s]", label, m.name);
                console.logBytes32(modelHash);
            } catch Error(string memory reason) {
                console.log("FAILED %s [%s]: %s", label, m.name, reason);
            } catch (bytes memory) {
                console.log("FAILED %s [%s]: unknown revert", label, m.name);
            }
        }
    }

    // String-array literals are clunky in Solidity; small helpers keep
    // _models() readable.
    function _tags2(string memory a, string memory b) internal pure returns (string[] memory t) {
        t = new string[](2); t[0] = a; t[1] = b;
    }
    function _tags3(string memory a, string memory b, string memory c) internal pure returns (string[] memory t) {
        t = new string[](3); t[0] = a; t[1] = b; t[2] = c;
    }
}
