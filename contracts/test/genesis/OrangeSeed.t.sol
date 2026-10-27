// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {OrangeSeedBase} from "./OrangeSeedBase.sol";
import {OrangeSeedV0} from "../../src/genesis/OrangeSeedV0.sol";
import {OrangeSeedV1Fixture} from "./OrangeSeedV1Fixture.sol";
import {GenesisOrangeSeed} from "../../script/GenesisOrangeSeed.s.sol";
import {DeployOrangeSeed} from "../../script/DeployOrangeSeed.s.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";

/// @notice A contract with no `proxiableUUID`: not a valid UUPS upgrade target.
contract NotUups {
    function version() external pure returns (uint256) {
        return 99;
    }
}

contract OrangeSeedTest is OrangeSeedBase {
    string internal constant EXPECTED_STORY =
        "A seed, planted at block zero by the people who tend this orchard. "
        "We grow the patient way: plant, tend, prune what cracks, and keep it all open to be checked. "
        "Fruit carries seeds... when the grove is ready, this one grows into whatever its members decide.";

    OrangeSeedV1Fixture internal v1;

    function setUp() public override {
        super.setUp();
        v1 = new OrangeSeedV1Fixture();
    }

    // ── the seed ─────────────────────────────────────────────────────────────

    function test_story_isTheOrchardMessage() public view {
        assertEq(seed.story(), EXPECTED_STORY);
        assertEq(seed.storyHash(), keccak256(bytes(EXPECTED_STORY)));
        assertEq(seed.version(), 0);
    }

    /// House style: ASCII only (so no em-dash), and one to three sentences.
    function test_story_followsHouseStyle() public view {
        bytes memory s = bytes(seed.story());
        uint256 sentences;
        for (uint256 i = 0; i < s.length; i++) {
            assertLt(uint8(s[i]), 0x80, "story must be ASCII (no em-dash)");
            // A full stop ends a sentence; the house ellipsis ("...") does not.
            bool stop = s[i] == "." && (i + 1 == s.length || s[i + 1] == " ");
            if (stop && !(i > 0 && s[i - 1] == ".")) sentences++;
        }
        assertGe(sentences, 1);
        assertLe(sentences, 3);
    }

    function test_plantingRecord_isBlockZeroAtGenesisTimestamp() public {
        vm.roll(500_000);
        vm.warp(GENESIS_TS + 365 days);
        assertEq(seed.plantedAtBlock(), 0);
        assertEq(seed.plantedAtTimestamp(), GENESIS_TS);
        assertEq(seed.planter(), planter);
        assertEq(seed.governance(), governance);
    }

    function test_germinate_isNotYet() public {
        vm.expectRevert(OrangeSeedV0.NotYetGerminated.selector);
        seed.germinate();
    }

    // ── upgrade authority ───────────────────────────────────────────────────

    function test_governance_canUpgrade() public {
        vm.prank(governance);
        seed.upgradeToAndCall(address(v1), "");
        assertEq(address(uint160(uint256(vm.load(proxyAddr, IMPLEMENTATION_SLOT)))), address(v1));
        assertEq(seed.version(), 1);
    }

    function test_eoa_cannotUpgrade() public {
        address eoa = makeAddr("someone");
        vm.prank(eoa);
        vm.expectRevert(abi.encodeWithSelector(OrangeSeedV0.NotGovernance.selector, eoa));
        seed.upgradeToAndCall(address(v1), "");
    }

    function test_deployer_cannotUpgrade() public {
        vm.prank(deployer);
        vm.expectRevert(abi.encodeWithSelector(OrangeSeedV0.NotGovernance.selector, deployer));
        seed.upgradeToAndCall(address(v1), "");
    }

    function test_planter_cannotUpgrade() public {
        vm.prank(planter);
        vm.expectRevert(abi.encodeWithSelector(OrangeSeedV0.NotGovernance.selector, planter));
        seed.upgradeToAndCall(address(v1), "");
    }

    function testFuzz_nonGovernance_cannotUpgrade(address caller) public {
        vm.assume(caller != governance);
        vm.prank(caller);
        vm.expectRevert(abi.encodeWithSelector(OrangeSeedV0.NotGovernance.selector, caller));
        seed.upgradeToAndCall(address(v1), "");
        assertEq(address(uint160(uint256(vm.load(proxyAddr, IMPLEMENTATION_SLOT)))), implAddr);
    }

    /// Calling the implementation directly (not through the proxy) can never upgrade.
    function test_implementationDirect_cannotUpgrade() public {
        vm.prank(governance);
        vm.expectRevert(UUPSUpgradeable.UUPSUnauthorizedCallContext.selector);
        OrangeSeedV0(implAddr).upgradeToAndCall(address(v1), "");
    }

    function test_upgradeToNonUups_reverts() public {
        NotUups bad = new NotUups();
        vm.prank(governance);
        vm.expectRevert(abi.encodeWithSelector(ERC1967Utils.ERC1967InvalidImplementation.selector, address(bad)));
        seed.upgradeToAndCall(address(bad), "");
        // A target with no code: decoding its empty `proxiableUUID` return reverts (no data).
        address eoaTarget = makeAddr("eoaTarget");
        vm.prank(governance);
        vm.expectRevert();
        seed.upgradeToAndCall(eoaTarget, "");
        assertEq(address(uint160(uint256(vm.load(proxyAddr, IMPLEMENTATION_SLOT)))), implAddr);
    }

    // ── initialization ──────────────────────────────────────────────────────

    function test_implementation_cannotBeInitialized() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        OrangeSeedV0(implAddr).initialize(makeAddr("x"), makeAddr("y"));
    }

    function test_freshImplementation_cannotBeInitialized() public {
        OrangeSeedV0 fresh = new OrangeSeedV0();
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        fresh.initialize(makeAddr("x"), makeAddr("y"));
    }

    function test_proxy_cannotBeReinitialized() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        seed.initialize(makeAddr("x"), makeAddr("y"));
        assertEq(seed.governance(), governance);
    }

    // ── value ───────────────────────────────────────────────────────────────

    function test_plainTransfer_reverts() public {
        vm.deal(address(this), 1 ether);
        (bool ok,) = proxyAddr.call{value: 1 wei}("");
        assertFalse(ok, "proxy accepted a plain transfer");
        (ok,) = implAddr.call{value: 1 wei}("");
        assertFalse(ok, "implementation accepted a plain transfer");
        assertEq(proxyAddr.balance, 0);
        assertEq(implAddr.balance, 0);
    }

    function testFuzz_valueOnAnyCall_reverts(uint96 amount, uint8 which) public {
        vm.assume(amount > 0);
        vm.deal(address(this), amount);
        bytes[6] memory calls = [
            bytes(""),
            abi.encodeCall(OrangeSeedV0.story, ()),
            abi.encodeCall(OrangeSeedV0.germinate, ()),
            abi.encodeCall(OrangeSeedV0.planter, ()),
            abi.encodeCall(OrangeSeedV0.initialize, (governance, planter)),
            abi.encodeWithSelector(bytes4(0xdeadbeef))
        ];
        (bool ok,) = proxyAddr.call{value: amount}(calls[which % 6]);
        assertFalse(ok);
        assertEq(proxyAddr.balance, 0);
    }

    /// OZ's upgradeToAndCall is payable; the seed refuses value even from governance.
    function test_governanceUpgradeWithValue_reverts() public {
        vm.deal(governance, 1 ether);
        vm.prank(governance);
        vm.expectRevert(OrangeSeedV0.ValueNotAccepted.selector);
        seed.upgradeToAndCall{value: 1}(address(v1), abi.encodeCall(OrangeSeedV1Fixture.initializeV1, ("hi")));
        assertEq(proxyAddr.balance, 0);
    }

    // ── storage layout (ERC-7201) ───────────────────────────────────────────

    function test_namespace_isErc7201() public pure {
        assertEq(seedBase(), 0x341195138d1c2c942beec98fd1e2c3287168a3890a2078215c65e5e0c1413000);
    }

    /// Pins the field order of SeedStorage: a reorder or insertion moves these slots.
    function test_storageLayout_rawSlots() public view {
        bytes32 b = seedBase();
        assertEq(vm.load(proxyAddr, b), bytes32(uint256(uint160(planter))), "slot 0 planter");
        assertEq(vm.load(proxyAddr, bytes32(uint256(b) + 1)), bytes32(uint256(uint160(governance))), "slot 1 governance");
        assertEq(vm.load(proxyAddr, bytes32(uint256(b) + 2)), bytes32(0), "slot 2 plantedAtBlock");
        assertEq(vm.load(proxyAddr, bytes32(uint256(b) + 3)), bytes32(GENESIS_TS), "slot 3 plantedAtTimestamp");
        assertEq(vm.load(proxyAddr, bytes32(uint256(b) + 4)), keccak256(bytes(EXPECTED_STORY)), "slot 4 storyHash");
        // Nothing in the conventional slots (a plain state variable would land here).
        for (uint256 i = 0; i < 8; i++) {
            assertEq(vm.load(proxyAddr, bytes32(i)), bytes32(0));
        }
    }

    function test_upgradeToV1_keepsPlantingRecord() public {
        vm.roll(777);
        vm.warp(GENESIS_TS + 30 days);
        vm.prank(governance);
        seed.upgradeToAndCall(address(v1), abi.encodeCall(OrangeSeedV1Fixture.initializeV1, ("first sprout")));
        OrangeSeedV1Fixture grown = OrangeSeedV1Fixture(proxyAddr);

        assertEq(grown.version(), 1);
        assertEq(grown.plantedAtBlock(), 0);
        assertEq(grown.plantedAtTimestamp(), GENESIS_TS);
        assertEq(grown.planter(), planter);
        assertEq(grown.governance(), governance);
        assertEq(grown.storyHash(), keccak256(bytes(EXPECTED_STORY)));
        assertEq(grown.note(), "first sprout");

        grown.germinate();
        grown.germinate();
        assertEq(grown.sprouts(), 2);
        assertEq(grown.plantedAtTimestamp(), GENESIS_TS, "V1 state clobbered V0");

        // V1 keeps the same authority.
        address eoa = makeAddr("someone");
        address next = address(new OrangeSeedV1Fixture());
        vm.prank(eoa);
        vm.expectRevert(abi.encodeWithSelector(OrangeSeedV0.NotGovernance.selector, eoa));
        grown.upgradeToAndCall(next, "");
        // And the V1 reinitializer cannot be replayed.
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        grown.initializeV1("again");
    }

    // ── genesis artifacts ───────────────────────────────────────────────────

    function test_genesis_implementationStorage_isDisabledInitializersOnly() public view {
        assertEq(alloc.implementation.slots.length, 1);
        assertEq(alloc.implementation.slots[0], INITIALIZABLE_SLOT);
        assertEq(alloc.implementation.values[0], bytes32(uint256(type(uint64).max)));
    }

    function test_genesis_proxyStorage_isExact() public view {
        bytes32 b = seedBase();
        // Sorted ascending; plantedAtBlock (0) is the default and so absent.
        bytes32[6] memory slots = [
            b,
            bytes32(uint256(b) + 1),
            bytes32(uint256(b) + 3),
            bytes32(uint256(b) + 4),
            IMPLEMENTATION_SLOT,
            INITIALIZABLE_SLOT
        ];
        bytes32[6] memory values = [
            bytes32(uint256(uint160(planter))),
            bytes32(uint256(uint160(governance))),
            bytes32(GENESIS_TS),
            keccak256(bytes(EXPECTED_STORY)),
            bytes32(uint256(uint160(implAddr))),
            bytes32(uint256(1))
        ];
        assertEq(alloc.proxy.slots.length, 6);
        for (uint256 i = 0; i < 6; i++) {
            assertEq(alloc.proxy.slots[i], slots[i]);
            assertEq(alloc.proxy.values[i], values[i]);
        }
    }

    function test_genesis_codeMatchesCompiledRuntime() public view {
        assertEq(keccak256(alloc.proxy.code), keccak256(proxyAddr.code));
        assertGt(alloc.implementation.code.length, 0);
        assertGt(alloc.proxy.code.length, 0);
    }

    function test_genesis_isDeterministic() public {
        GenesisOrangeSeed other = new GenesisOrangeSeed();
        address p2 = makeAddr("p2");
        address i2 = makeAddr("i2");
        GenesisOrangeSeed.Alloc memory a = other.build(p2, i2, governance, planter, GENESIS_TS);
        GenesisOrangeSeed.Alloc memory b = other.build(makeAddr("p3"), makeAddr("i3"), governance, planter, GENESIS_TS);
        // Proxy runtime is address-independent; the implementation embeds its own address.
        assertEq(keccak256(a.proxy.code), keccak256(alloc.proxy.code));
        assertEq(keccak256(a.proxy.code), keccak256(b.proxy.code));
        assertEq(a.implementation.code.length, b.implementation.code.length);
        assertEq(a.proxy.values[0], alloc.proxy.values[0]);
    }

    /// Negative control for the build method: implementation code constructed at some other
    /// address carries that address as UUPS `__self`, and placed at the predeploy it bricks
    /// every upgrade. The builder constructs at the predeploy address, which is why the
    /// upgrade in `test_governance_canUpgrade` works.
    function test_genesis_negativeControl_implConstructedElsewhereBricksUpgrades() public {
        OrangeSeedV0 elsewhere = new OrangeSeedV0();
        vm.etch(implAddr, address(elsewhere).code);
        vm.prank(governance);
        vm.expectRevert(UUPSUpgradeable.UUPSUnauthorizedCallContext.selector);
        seed.upgradeToAndCall(address(v1), "");
    }

    function test_genesis_refusesBadInputs() public {
        GenesisOrangeSeed g = new GenesisOrangeSeed();
        vm.expectRevert("OrangeSeed: governance is the zero address");
        g.build(makeAddr("a1"), makeAddr("b1"), address(0), planter, GENESIS_TS);
        vm.expectRevert("OrangeSeed: planter is the zero address");
        g.build(makeAddr("a2"), makeAddr("b2"), governance, address(0), GENESIS_TS);
        vm.expectRevert("OrangeSeed: proxy and implementation share an address");
        g.build(makeAddr("a3"), makeAddr("a3"), governance, planter, GENESIS_TS);
        vm.expectRevert("OrangeSeed: predeploy address already has code");
        g.build(proxyAddr, makeAddr("b4"), governance, planter, GENESIS_TS);
    }

    function test_genesis_restoresBlockAndTime() public {
        vm.roll(42);
        vm.warp(GENESIS_TS + 5);
        new GenesisOrangeSeed().build(makeAddr("p5"), makeAddr("i5"), governance, planter, GENESIS_TS);
        assertEq(vm.getBlockNumber(), 42);
        assertEq(vm.getBlockTimestamp(), GENESIS_TS + 5);
    }

    // ── predeploy address ───────────────────────────────────────────────────

    /// The reserved addresses sit outside every Citrate precompile and system range:
    /// the standard precompiles (0x01–0x11), the Citrate families (all addresses whose
    /// first 18 bytes are zero: 0x0100–0x013F, 0x0200–0x0209, 0x1000/0x1002/0x1003), the
    /// block-reward minter, the EIP-4788/2935 system contracts and the Arachnid factory,
    /// and appear nowhere in the 40204 address book.
    function test_predeployAddresses_doNotCollide() public view {
        address[2] memory mine = [proxyAddr, implAddr];
        assertEq(proxyAddr, 0x000000000000000000000000000000c17A7e5EeD);
        address[4] memory system = [
            0x0000000000000000000000000000000050524950, // block-reward minter
            0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02, // EIP-4788 beacon roots
            0x0000F90827F1C53a10cb7A02335B175320002935, // EIP-2935 history storage
            0x4e59b44847b379578588920cA78FbF26c0B4956C // Arachnid CREATE2 factory
        ];
        string memory book = vm.toLowercase(vm.readFile("addresses/40204.json"));
        for (uint256 i = 0; i < 2; i++) {
            assertGt(uint160(mine[i]), 0xFFFF, "inside the precompile prefix (first 18 bytes zero)");
            for (uint256 j = 0; j < system.length; j++) {
                assertTrue(mine[i] != system[j]);
            }
            assertFalse(vm.contains(book, vm.toLowercase(vm.toString(mine[i]))), "address already in the book");
        }
        assertFalse(vm.contains(book, "c17a7e5ee"), "book mentions the seed range");
    }

    // ── local deploy script ─────────────────────────────────────────────────

    function test_deployScript_plantsAtomically() public {
        DeployOrangeSeed d = new DeployOrangeSeed();
        vm.roll(10);
        vm.warp(GENESIS_TS + 100);
        (address p, address i) = d.deploy(governance, planter);
        OrangeSeedV0 s = OrangeSeedV0(p);
        assertEq(s.governance(), governance);
        assertEq(s.planter(), planter);
        assertEq(s.plantedAtBlock(), 10);
        assertEq(s.plantedAtTimestamp(), GENESIS_TS + 100);
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        s.initialize(deployer, deployer);
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        OrangeSeedV0(i).initialize(deployer, deployer);
        // The deploying account holds nothing.
        vm.prank(address(d));
        vm.expectRevert(abi.encodeWithSelector(OrangeSeedV0.NotGovernance.selector, address(d)));
        s.upgradeToAndCall(address(v1), "");
    }

    function test_deployScript_refusesOnCitrate() public {
        DeployOrangeSeed d = new DeployOrangeSeed();
        vm.chainId(40204);
        vm.expectRevert(bytes("OrangeSeed on chain 40204 is the genesis predeploy: use script/GenesisOrangeSeed.s.sol"));
        d.deploy(governance, planter);
    }

    function test_initialize_refusesZeroAddresses() public {
        DeployOrangeSeed d = new DeployOrangeSeed();
        vm.expectRevert(OrangeSeedV0.ZeroAddress.selector);
        d.deploy(address(0), planter);
        vm.expectRevert(OrangeSeedV0.ZeroAddress.selector);
        d.deploy(governance, address(0));
    }
}
