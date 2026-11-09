// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import "forge-std/Script.sol";

interface IValidatorRegistryGenesis {
    function registerValidator(bytes32 proposerPubkey, bytes calldata ed25519Sig) external payable;
    function isActive(bytes32 pubkey) external view returns (bool);
    function activeCount() external view returns (uint256);
    function stakeOf(bytes32 pubkey) external view returns (uint256);
    function pubkeyOfStaker(address staker) external view returns (bytes32);
    function ED25519_VERIFY() external view returns (address);
    function REGISTER_TYPEHASH() external view returns (bytes32);
}

/// @title GenesisValidators: the r1006 producer set as block-0 ValidatorRegistry state
/// @notice r1006's block 0 already has its producers in the ValidatorRegistry's active set.
///         This script computes the registry's storage after registering them, by running
///         the registry's OWN code: the ceremony's registry (runtime code, storage, balance,
///         from the genesis alloc) is etched at its address, each producer's staker calls
///         `registerValidator{value: stake}` at block 0, and every slot the calls wrote is
///         read back. No transaction is sent and nothing is signed.
///
///         Proof of key control: each producer's host signs the registration digest with its
///         proposer key (`citrate registration-proof`). This EVM has no ed25519 precompile
///         (0x0120), so the script stands in for it with a real ed25519 verification of the
///         exact (pubkey, signature, digest) the registry passes (GENESIS_ED25519_VERIFIER,
///         through ffi): a bad signature gets 0 and the registry reverts BadSig, as on chain.
///         The fill also verifies every signature before it runs this. Every other registry
///         check runs as on chain, at chain id 40204.
///
///         Env:
///           GENESIS_VR             the ValidatorRegistry address
///           GENESIS_VR_STATE       JSON {"code":"0x…","balance":"0x…","storage":{"0x<slot>":"0x<value>"}}
///           GENESIS_VALIDATORS     JSON {"count":N,"validators":[{"proposer_pubkey":"0x…","staker":"0x…",
///                                  "stake_wei":"<dec>","registration_sig":"0x<64 bytes>"}]}
///           GENESIS_TIMESTAMP      block-0 timestamp (unix seconds)
///           GENESIS_VALIDATORS_OUT output path (under ./genesis)
///         Output: {"validatorRegistry":"0x…","balance":"<dec wei>","activationEpoch":E,
///                  "storage":{"0x<slot>":"0x<value>"}}  (every slot the registrations wrote)
contract GenesisValidators is Script {
    function run() external {
        address vr = vm.envAddress("GENESIS_VR");
        _load(vr, vm.readFile(vm.envString("GENESIS_VR_STATE")));
        vm.chainId(40204);
        vm.roll(0);
        vm.warp(vm.envUint("GENESIS_TIMESTAMP"));
        uint256 n = _register(vr, vm.readFile(vm.envString("GENESIS_VALIDATORS")));
        _emit(vr);
        console.log("GenesisValidators: registered", n, "producers at block 0 in", vr);
    }

    /// The ceremony's registry: runtime code, balance and every storage slot.
    function _load(address vr, string memory st) internal {
        vm.etch(vr, vm.parseJsonBytes(st, ".code"));
        vm.deal(vr, vm.parseJsonUint(st, ".balance"));
        string[] memory keys = vm.parseJsonKeys(st, ".storage");
        for (uint256 i = 0; i < keys.length; i++) {
            vm.store(vr, vm.parseBytes32(keys[i]), vm.parseJsonBytes32(st, string.concat(".storage.", keys[i])));
        }
    }

    /// Each producer's staker registers with its stake, through the registry's own code.
    function _register(address vr, string memory vs) internal returns (uint256 n) {
        IValidatorRegistryGenesis reg = IValidatorRegistryGenesis(vr);
        require(reg.activeCount() == 0, "GenesisValidators: the ceremony registry already has validators");
        n = vm.parseJsonUint(vs, ".count");
        require(n > 0, "GenesisValidators: no validators");
        vm.record();
        for (uint256 i = 0; i < n; i++) {
            _registerOne(reg, vs, string.concat(".validators[", vm.toString(i), "]"));
        }
        require(reg.activeCount() == n, "GenesisValidators: the active set is not the producer set");
        vm.clearMockedCalls();
    }

    function _registerOne(IValidatorRegistryGenesis reg, string memory vs, string memory k) internal {
        bytes32 pk = vm.parseJsonBytes32(vs, string.concat(k, ".proposer_pubkey"));
        address staker = vm.parseJsonAddress(vs, string.concat(k, ".staker"));
        uint256 stake = vm.parseUint(vm.parseJsonString(vs, string.concat(k, ".stake_wei")));
        bytes memory sig = vm.parseJsonBytes(vs, string.concat(k, ".registration_sig"));
        require(sig.length == 64, "GenesisValidators: a registration signature is not 64 bytes");
        // The digest the registry builds (nonce 0 for a fresh staker).
        bytes32 digest = keccak256(
            abi.encode(reg.REGISTER_TYPEHASH(), block.chainid, address(reg), staker, pk, uint256(0))
        );
        // Stand in for the ed25519 precompile with a REAL verification of this exact input
        // (GENESIS_ED25519_VERIFIER, run through ffi): the registry then sees 1 for a valid
        // signature and 0 for any other, as on chain.
        vm.mockCall(
            reg.ED25519_VERIFY(),
            abi.encodePacked(pk, sig, abi.encodePacked(digest)),
            abi.encode(_ed25519(pk, sig, digest) ? uint256(1) : uint256(0))
        );
        vm.deal(staker, stake);
        vm.prank(staker);
        reg.registerValidator{value: stake}(pk, sig);
        require(reg.isActive(pk), "GenesisValidators: a producer is not active");
        require(reg.stakeOf(pk) == stake, "GenesisValidators: stake mismatch");
        require(reg.pubkeyOfStaker(staker) == pk, "GenesisValidators: staker binding mismatch");
    }

    /// ed25519 verification of (pubkey, signature, 32-byte message) by an external verifier
    /// (`GENESIS_ED25519_VERIFIER`: prints 1 or 0). The EVM here has no 0x0120 precompile.
    function _ed25519(bytes32 pk, bytes memory sig, bytes32 digest) internal returns (bool) {
        string[] memory cmd = new string[](4);
        cmd[0] = vm.envString("GENESIS_ED25519_VERIFIER");
        cmd[1] = vm.toString(pk);
        cmd[2] = vm.toString(sig);
        cmd[3] = vm.toString(digest);
        bytes memory out = vm.ffi(cmd);
        return out.length == 1 && out[0] == 0x01;
    }

    /// Every slot the registrations wrote, with its final value, plus the new balance.
    function _emit(address vr) internal {
        (, bytes32[] memory writes) = vm.accesses(vr);
        string memory sj = "{}";
        for (uint256 i = 0; i < writes.length; i++) {
            sj = vm.serializeBytes32("storage", vm.toString(writes[i]), vm.load(vr, writes[i]));
        }
        vm.serializeAddress("out", "validatorRegistry", vr);
        vm.serializeString("out", "balance", vm.toString(vr.balance));
        vm.serializeUint("out", "activationEpoch", uint256(200) / 1000 + 1);
        string memory json = vm.serializeString("out", "storage", sj);
        vm.writeFile(vm.envString("GENESIS_VALIDATORS_OUT"), json);
    }
}
