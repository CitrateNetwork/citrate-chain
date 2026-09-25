// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.36;

/**
 * @title SkillRegistry
 * @notice Enumerable on-chain registry of Hermes agent skills / capsules on chain 40204.
 *         Its read surface intentionally mirrors ModelRegistry
 *         (`getAllSkillHashes()` + `getSkill(bytes32)`), so the Citrate Core app can read
 *         it with the exact same code path as `model_registry.rs` reads ModelRegistry.
 *
 *         Unlike ModelRegistry this is a PURE registry: no registration fee and no
 *         model precompile call — registering a skill is a plain state write. Anyone can
 *         self-register a skill they own; only the owner can (de)activate or update it.
 *
 *         SECURITY / CONSUMER CONTRACT (PBA-L2-045, pre-bounty audit 2026-09-24):
 *           - Names are NOT unique and NOT authoritative: any address can register any
 *             `name`. Resolve a skill ONLY by `keccak256(abi.encodePacked(trustedOwner,
 *             name, version))` against an owner allowlist the consumer pins — never by
 *             name alone, and never by trusting every entry of `getAllSkillHashes()`.
 *           - Enumeration is unbounded and permissionless (spam can push
 *             `getAllSkillHashes()` past an RPC eth_call gas cap). Page with
 *             `totalSkills()` + the public index getter `allSkillHashes(i)`.
 *         (Documented rather than changed in code: this contract is live at a CREATE2
 *         address that any bytecode change would move, and the fix is consumer-side.)
 *
 *         A "skill" is one Hermes capsule: a canonical name + semver + the IPFS CID of the
 *         capsule bundle/manifest + human metadata. The capsule bytes themselves live on
 *         IPFS; the chain holds the enumerable pointer + provenance.
 */
contract SkillRegistry {
    struct Skill {
        bytes32 skillHash;    // keccak256(owner, name, version) — the stable id
        address owner;        // registrant; the only address that can update/deactivate
        string name;          // canonical skill id, e.g. "hf-model-register"
        string version;       // semver, e.g. "1.0.0"
        string manifestCID;   // IPFS CID of the capsule manifest / wasm bundle ("" = pending pin)
        string description;   // short human-readable
        string[] tags;        // ["model","huggingface",...]
        uint256 createdAt;
        uint256 updatedAt;
        bool isActive;
    }

    mapping(bytes32 => Skill) private skills;
    bytes32[] public allSkillHashes;
    mapping(address => bytes32[]) private ownerSkills;

    event SkillRegistered(bytes32 indexed skillHash, address indexed owner, string name, string version);
    event SkillUpdated(bytes32 indexed skillHash, string manifestCID);
    event SkillActiveSet(bytes32 indexed skillHash, bool isActive);

    /// @notice Register a new skill. Reverts if (msg.sender, name, version) already exists.
    /// @return skillHash the stable id = keccak256(msg.sender, name, version).
    function registerSkill(
        string calldata name,
        string calldata version,
        string calldata manifestCID,
        string calldata description,
        string[] calldata tags
    ) external returns (bytes32 skillHash) {
        require(bytes(name).length != 0, "name required");
        skillHash = keccak256(abi.encodePacked(msg.sender, name, version));
        require(skills[skillHash].createdAt == 0, "skill exists");

        Skill storage s = skills[skillHash];
        s.skillHash = skillHash;
        s.owner = msg.sender;
        s.name = name;
        s.version = version;
        s.manifestCID = manifestCID;
        s.description = description;
        for (uint256 i = 0; i < tags.length; i++) {
            s.tags.push(tags[i]);
        }
        s.createdAt = block.timestamp;
        s.updatedAt = block.timestamp;
        s.isActive = true;

        allSkillHashes.push(skillHash);
        ownerSkills[msg.sender].push(skillHash);
        emit SkillRegistered(skillHash, msg.sender, name, version);
    }

    /// @notice Set (e.g. after pinning) the capsule manifest CID. Owner only.
    function setManifestCID(bytes32 skillHash, string calldata manifestCID) external {
        require(skills[skillHash].owner == msg.sender, "not owner");
        skills[skillHash].manifestCID = manifestCID;
        skills[skillHash].updatedAt = block.timestamp;
        emit SkillUpdated(skillHash, manifestCID);
    }

    /// @notice Activate / deactivate a skill without removing it from the enumeration. Owner only.
    function setActive(bytes32 skillHash, bool isActive) external {
        require(skills[skillHash].owner == msg.sender, "not owner");
        skills[skillHash].isActive = isActive;
        skills[skillHash].updatedAt = block.timestamp;
        emit SkillActiveSet(skillHash, isActive);
    }

    // ── Reads (ModelRegistry-parity) ──────────────────────────────────────────

    /// @notice Every registered skill id, in registration order. Mirrors getAllModelHashes().
    function getAllSkillHashes() external view returns (bytes32[] memory) {
        return allSkillHashes;
    }

    /// @notice Count of registered skills. Mirrors totalModels().
    function totalSkills() external view returns (uint256) {
        return allSkillHashes.length;
    }

    /// @notice Read one skill by id. Mirrors getModel(bytes32)'s flattened return shape.
    function getSkill(bytes32 skillHash)
        external
        view
        returns (
            address owner,
            string memory name,
            string memory version,
            string memory manifestCID,
            string memory description,
            bool isActive
        )
    {
        Skill storage s = skills[skillHash];
        return (s.owner, s.name, s.version, s.manifestCID, s.description, s.isActive);
    }

    /// @notice Tags for a skill (kept separate so getSkill's ABI stays flat & cheap to decode).
    function getSkillTags(bytes32 skillHash) external view returns (string[] memory) {
        return skills[skillHash].tags;
    }

    /// @notice All skill ids registered by one owner. Mirrors getModelsByOwner().
    function getSkillsByOwner(address owner) external view returns (bytes32[] memory) {
        return ownerSkills[owner];
    }
}
