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
}

/// @title GenesisValidators: the r1006 producer set as block-0 ValidatorRegistry state
/// @notice r1006's block 0 already has its producers in the ValidatorRegistry's active set.
///         This script computes the registry's storage after registering them, by running
///         the registry's OWN code: the ceremony's registry (runtime code, storage, balance,
///         from the genesis alloc) is etched at its address, each producer's staker calls
///         `registerValidator{value: stake}` at block 0, and every slot the calls wrote is
///         read back. No transaction is sent and nothing is signed.
///
///         The one substitution: the ed25519 proof of key control (precompile 0x0120, which
///         this EVM does not have) is answered "valid". The proposer keys come from each
///         producer host's public identity (`citrate host-identity`, collected by the
///         bring-up), which is the provenance of the set; the registry's every other check
///         (stake >= minStake, one validator per staker, key never used, set size) runs.
///
///         Env:
///           GENESIS_VR             the ValidatorRegistry address
///           GENESIS_VR_STATE       JSON {"code":"0x…","balance":"0x…","storage":{"0x<slot>":"0x<value>"}}
///           GENESIS_VALIDATORS     JSON {"validators":[{"proposer_pubkey":"0x…","staker":"0x…","stake_wei":"<dec>"}]}
///           GENESIS_TIMESTAMP      block-0 timestamp (unix seconds)
///           GENESIS_VALIDATORS_OUT output path (under ./genesis)
///         Output: {"validatorRegistry":"0x…","balance":"<dec wei>","activationEpoch":E,
///                  "storage":{"0x<slot>":"0x<value>"}}  (every slot the registrations wrote)
contract GenesisValidators is Script {
    function run() external {
        address vr = vm.envAddress("GENESIS_VR");
        string memory st = vm.readFile(vm.envString("GENESIS_VR_STATE"));
        string memory vs = vm.readFile(vm.envString("GENESIS_VALIDATORS"));
        uint256 ts = vm.envUint("GENESIS_TIMESTAMP");

        vm.etch(vr, vm.parseJsonBytes(st, ".code"));
        vm.deal(vr, vm.parseJsonUint(st, ".balance"));
        string[] memory keys = vm.parseJsonKeys(st, ".storage");
        for (uint256 i = 0; i < keys.length; i++) {
            bytes32 slot = vm.parseBytes32(keys[i]);
            vm.store(vr, slot, vm.parseJsonBytes32(st, string.concat(".storage.", keys[i])));
        }
        vm.roll(0);
        vm.warp(ts);
        IValidatorRegistryGenesis reg = IValidatorRegistryGenesis(vr);
        vm.mockCall(reg.ED25519_VERIFY(), bytes(""), abi.encode(uint256(1)));

        uint256 before = reg.activeCount();
        require(before == 0, "GenesisValidators: the ceremony registry already has validators");
        uint256 n = vm.parseJsonUint(vs, ".validators.length");
        require(n > 0, "GenesisValidators: no validators");
        vm.record();
        for (uint256 i = 0; i < n; i++) {
            string memory k = string.concat(".validators[", vm.toString(i), "]");
            bytes32 pk = vm.parseJsonBytes32(vs, string.concat(k, ".proposer_pubkey"));
            address staker = vm.parseJsonAddress(vs, string.concat(k, ".staker"));
            uint256 stake = vm.parseUint(vm.parseJsonString(vs, string.concat(k, ".stake_wei")));
            vm.deal(staker, stake);
            vm.prank(staker);
            reg.registerValidator{value: stake}(pk, new bytes(64));
            require(reg.isActive(pk), "GenesisValidators: a producer is not active");
            require(reg.stakeOf(pk) == stake, "GenesisValidators: stake mismatch");
            require(reg.pubkeyOfStaker(staker) == pk, "GenesisValidators: staker binding mismatch");
        }
        require(reg.activeCount() == n, "GenesisValidators: the active set is not the producer set");
        (, bytes32[] memory writes) = vm.accesses(vr);
        vm.clearMockedCalls();

        string memory obj = "storage";
        string memory sj = "{}";
        for (uint256 i = 0; i < writes.length; i++) {
            sj = vm.serializeBytes32(obj, vm.toString(writes[i]), vm.load(vr, writes[i]));
        }
        string memory out = "out";
        vm.serializeAddress(out, "validatorRegistry", vr);
        vm.serializeString(out, "balance", vm.toString(vr.balance));
        vm.serializeUint(out, "activationEpoch", (uint256(0) + 200) / 1000 + 1);
        string memory json = vm.serializeString(out, "storage", sj);
        vm.writeFile(vm.envString("GENESIS_VALIDATORS_OUT"), json);
        console.log("GenesisValidators: registered", n, "producers at block 0 in", vr);
    }
}
