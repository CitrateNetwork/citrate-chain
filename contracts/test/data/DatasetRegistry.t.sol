// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {DatasetRegistry} from "../../src/data/DatasetRegistry.sol";

/// FLM-CON-2 (0.6.0 06 §5/§6). Each rule in the contract's natspec has a test here.
abstract contract DatasetRegistryBase is Test {
    DatasetRegistry internal reg;
    address internal gov = makeAddr("governance-timelock");
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    /// Dataset ids live in the publisher's namespace: the top 20 bytes are the publisher address.
    bytes32 internal ID = _nsId(alice, "dataset/notes");

    function _nsId(address who, string memory name) internal pure returns (bytes32) {
        return bytes32((uint256(uint160(who)) << 96) | uint256(uint96(uint256(keccak256(bytes(name))))));
    }

    function setUp() public virtual {
        reg = new DatasetRegistry(gov);
    }

    function _v(bytes32 manifest, bytes32 prev) internal pure returns (DatasetRegistry.Version memory v) {
        v.manifestHash = manifest;
        v.prev = prev;
        v.cid = "bafyciphertext";
        v.license = "CC-BY-4.0";
        v.privacy = DatasetRegistry.Privacy.Members;
    }

    function _publishV1(address who) internal returns (uint32) {
        vm.prank(who);
        return reg.publish(ID, _v(keccak256("m1"), bytes32(0)));
    }
}

contract DatasetRegistryTest is DatasetRegistryBase {
    // ── license ─────────────────────────────────────────────────────

    function test_publish_refuses_unknown_license() public {
        string[4] memory bad = ["unknown", "UNKNOWN", "Unknown", "uNkNoWn"];
        for (uint256 i = 0; i < bad.length; i++) {
            DatasetRegistry.Version memory v = _v(keccak256("m1"), bytes32(0));
            v.license = bad[i];
            vm.prank(alice);
            vm.expectRevert(DatasetRegistry.BadLicense.selector);
            reg.publish(ID, v);
        }
    }

    function test_publish_refuses_empty_license() public {
        DatasetRegistry.Version memory v = _v(keccak256("m1"), bytes32(0));
        v.license = "";
        vm.prank(alice);
        vm.expectRevert(DatasetRegistry.BadLicense.selector);
        reg.publish(ID, v);
    }

    function test_publish_accepts_license_ref_and_near_misses() public {
        DatasetRegistry.Version memory v = _v(keccak256("m1"), bytes32(0));
        v.license = "unknown2"; // not exactly "unknown"
        vm.prank(alice);
        assertEq(reg.publish(ID, v), 1);
        v = _v(keccak256("m2"), keccak256("m1"));
        v.license = "LicenseRef-citrate-internal";
        vm.prank(alice);
        assertEq(reg.publish(ID, v), 2);
    }

    function test_publish_refuses_long_strings() public {
        DatasetRegistry.Version memory v = _v(keccak256("m1"), bytes32(0));
        v.license = string(new bytes(257));
        vm.prank(alice);
        vm.expectRevert(DatasetRegistry.StringTooLong.selector);
        reg.publish(ID, v);
        v.license = "MIT";
        v.cid = string(new bytes(257));
        vm.prank(alice);
        vm.expectRevert(DatasetRegistry.StringTooLong.selector);
        reg.publish(ID, v);
        v.cid = string(new bytes(256));
        vm.prank(alice);
        assertEq(reg.publish(ID, v), 1);
    }

    // ── ownership and the prev chain ────────────────────────────────

    function test_first_publisher_owns_id() public {
        assertEq(_publishV1(alice), 1);
        assertEq(reg.ownerOf(ID), alice);
        DatasetRegistry.Version memory v2 = _v(keccak256("m2"), keccak256("m1"));
        vm.prank(bob);
        vm.expectRevert(DatasetRegistry.NotDatasetOwner.selector);
        reg.publish(ID, v2);
        vm.prank(gov);
        vm.expectRevert(DatasetRegistry.NotDatasetOwner.selector);
        reg.publish(ID, v2);
        vm.prank(alice);
        assertEq(reg.publish(ID, v2), 2);
        assertEq(reg.ownerOf(ID), alice);
    }

    function test_v1_requires_zero_prev() public {
        vm.prank(alice);
        vm.expectRevert(DatasetRegistry.BadPrev.selector);
        reg.publish(ID, _v(keccak256("m1"), keccak256("x")));
    }

    function test_prev_must_be_latest_manifest() public {
        _publishV1(alice);
        vm.startPrank(alice);
        vm.expectRevert(DatasetRegistry.BadPrev.selector);
        reg.publish(ID, _v(keccak256("m2"), bytes32(0)));
        vm.expectRevert(DatasetRegistry.BadPrev.selector);
        reg.publish(ID, _v(keccak256("m2"), keccak256("other")));
        reg.publish(ID, _v(keccak256("m2"), keccak256("m1")));
        // v3 must chain to v2, not v1
        vm.expectRevert(DatasetRegistry.BadPrev.selector);
        reg.publish(ID, _v(keccak256("m3"), keccak256("m1")));
        assertEq(reg.publish(ID, _v(keccak256("m3"), keccak256("m2"))), 3);
        vm.stopPrank();
        (uint32 n, DatasetRegistry.Version memory last) = reg.latest(ID);
        assertEq(n, 3);
        assertEq(last.prev, keccak256("m2"));
        assertEq(reg.versionCount(ID), 3);
    }

    function test_zero_or_unchanged_manifest_refused() public {
        vm.prank(alice);
        vm.expectRevert(DatasetRegistry.ZeroManifestHash.selector);
        reg.publish(ID, _v(bytes32(0), bytes32(0)));
        _publishV1(alice);
        vm.prank(alice);
        vm.expectRevert(DatasetRegistry.ManifestUnchanged.selector);
        reg.publish(ID, _v(keccak256("m1"), keccak256("m1")));
    }

    // ── reserved fields ─────────────────────────────────────────────

    function test_reserved_fields_must_be_zero_and_are_written_by_contract() public {
        DatasetRegistry.Version memory v = _v(keccak256("m1"), bytes32(0));
        v.publisher = bob;
        vm.prank(alice);
        vm.expectRevert(DatasetRegistry.ReservedFieldSet.selector);
        reg.publish(ID, v);
        v.publisher = address(0);
        v.publishedAt = 1;
        vm.prank(alice);
        vm.expectRevert(DatasetRegistry.ReservedFieldSet.selector);
        reg.publish(ID, v);
        v.publishedAt = 0;
        v.withdrawn = true;
        vm.prank(alice);
        vm.expectRevert(DatasetRegistry.ReservedFieldSet.selector);
        reg.publish(ID, v);

        vm.warp(1_900_000_000);
        _publishV1(alice);
        DatasetRegistry.Version memory got = reg.getVersion(ID, 1);
        assertEq(got.publisher, alice);
        assertEq(got.publishedAt, 1_900_000_000);
        assertFalse(got.withdrawn);
        assertEq(got.manifestHash, keccak256("m1"));
        assertEq(got.license, "CC-BY-4.0");
        assertEq(got.cid, "bafyciphertext");
    }

    // ── privacy labels ──────────────────────────────────────────────

    function test_group_privacy_needs_group_hash_and_others_refuse_it() public {
        DatasetRegistry.Version memory v = _v(keccak256("m1"), bytes32(0));
        v.privacy = DatasetRegistry.Privacy.Group;
        vm.prank(alice);
        vm.expectRevert(DatasetRegistry.BadGroupHash.selector);
        reg.publish(ID, v);
        v.privacy = DatasetRegistry.Privacy.Public;
        v.groupHash = keccak256("mls-group");
        vm.prank(alice);
        vm.expectRevert(DatasetRegistry.BadGroupHash.selector);
        reg.publish(ID, v);
        v.privacy = DatasetRegistry.Privacy.Group;
        vm.prank(alice);
        assertEq(reg.publish(ID, v), 1);
        assertEq(reg.getVersion(ID, 1).groupHash, keccak256("mls-group"));
    }

    function test_index_only_has_no_cid_and_others_need_one() public {
        DatasetRegistry.Version memory v = _v(keccak256("m1"), bytes32(0));
        v.privacy = DatasetRegistry.Privacy.IndexOnly;
        vm.prank(alice);
        vm.expectRevert(DatasetRegistry.BadCid.selector);
        reg.publish(ID, v);
        v.privacy = DatasetRegistry.Privacy.Public;
        v.cid = "";
        vm.prank(alice);
        vm.expectRevert(DatasetRegistry.BadCid.selector);
        reg.publish(ID, v);
        v.privacy = DatasetRegistry.Privacy.IndexOnly;
        vm.prank(alice);
        assertEq(reg.publish(ID, v), 1);
    }

    function test_publish_emits_event() public {
        vm.expectEmit(true, true, false, true, address(reg));
        emit DatasetRegistry.DatasetPublished(ID, 1, alice, DatasetRegistry.Privacy.Members, "CC-BY-4.0");
        _publishV1(alice);
    }

    // ── withdraw / takedown ─────────────────────────────────────────

    function test_publisher_withdraws_with_publisher_code_only() public {
        _publishV1(alice);
        vm.startPrank(alice);
        vm.expectRevert(DatasetRegistry.BadReason.selector);
        reg.withdraw(ID, 1, 0);
        vm.expectRevert(DatasetRegistry.BadReason.selector);
        reg.withdraw(ID, 1, 1000);
        vm.expectEmit(true, false, false, true, address(reg));
        emit DatasetRegistry.DatasetWithdrawn(ID, 1, 7);
        reg.withdraw(ID, 1, 7);
        vm.stopPrank();
        assertTrue(reg.getVersion(ID, 1).withdrawn);
    }

    function test_governance_takedown_only_sets_flag() public {
        _publishV1(alice);
        DatasetRegistry.Version memory before = reg.getVersion(ID, 1);
        vm.prank(gov);
        vm.expectRevert(DatasetRegistry.BadReason.selector);
        reg.withdraw(ID, 1, 999);
        vm.prank(gov);
        reg.withdraw(ID, 1, 1001);
        DatasetRegistry.Version memory after_ = reg.getVersion(ID, 1);
        assertTrue(after_.withdrawn);
        assertEq(after_.publisher, before.publisher);
        assertEq(after_.manifestHash, before.manifestHash);
        assertEq(after_.prev, before.prev);
        assertEq(after_.groupHash, before.groupHash);
        assertEq(after_.cid, before.cid);
        assertEq(after_.license, before.license);
        assertEq(uint8(after_.privacy), uint8(before.privacy));
        assertEq(after_.publishedAt, before.publishedAt);
        assertEq(reg.ownerOf(ID), alice);
        assertEq(reg.versionCount(ID), 1);
    }

    function test_stranger_cannot_withdraw() public {
        _publishV1(alice);
        vm.prank(bob);
        vm.expectRevert(DatasetRegistry.NotAuthorized.selector);
        reg.withdraw(ID, 1, 5);
        vm.prank(bob);
        vm.expectRevert(DatasetRegistry.NotAuthorized.selector);
        reg.withdraw(ID, 1, 1000);
    }

    function test_withdraw_is_sticky() public {
        _publishV1(alice);
        vm.prank(alice);
        reg.withdraw(ID, 1, 3);
        vm.prank(alice);
        vm.expectRevert(DatasetRegistry.AlreadyWithdrawn.selector);
        reg.withdraw(ID, 1, 3);
        // a governance takedown still applies to a version the publisher already withdrew
        vm.prank(gov);
        reg.withdraw(ID, 1, 1000);
        assertTrue(reg.getVersion(ID, 1).withdrawn);
        assertTrue(reg.frozen(ID));
    }

    function test_withdraw_unknown_version_reverts() public {
        vm.prank(gov);
        vm.expectRevert(DatasetRegistry.UnknownVersion.selector);
        reg.withdraw(ID, 1, 1000);
        _publishV1(alice);
        vm.prank(alice);
        vm.expectRevert(DatasetRegistry.UnknownVersion.selector);
        reg.withdraw(ID, 0, 1);
        vm.prank(alice);
        vm.expectRevert(DatasetRegistry.UnknownVersion.selector);
        reg.withdraw(ID, 2, 1);
    }

    /// A publisher withdrawal (1..999) affects one version only: the id stays open and the next
    /// version chains through the withdrawn one. (Before owner decision Q15 this test used a
    /// governance takedown; a takedown now freezes the id, see the freeze tests below.)
    function test_next_version_chains_through_withdrawn_one() public {
        _publishV1(alice);
        vm.prank(alice);
        reg.withdraw(ID, 1, 3);
        assertFalse(reg.frozen(ID));
        vm.prank(alice);
        assertEq(reg.publish(ID, _v(keccak256("m2"), keccak256("m1"))), 2);
        assertTrue(reg.getVersion(ID, 1).withdrawn);
        assertFalse(reg.getVersion(ID, 2).withdrawn);
    }

    // ── Q15/Q16 (owner 2026-11-09): a governance takedown freezes the whole id ──

    function test_governance_takedown_freezes_whole_id() public {
        _publishV1(alice);
        assertFalse(reg.frozen(ID));
        vm.expectEmit(true, false, false, true);
        emit DatasetRegistry.DatasetIdFrozen(ID, 1, 1001);
        vm.prank(gov);
        reg.withdraw(ID, 1, 1001);
        assertTrue(reg.frozen(ID));
        vm.prank(alice);
        vm.expectRevert(DatasetRegistry.DatasetFrozen.selector);
        reg.publish(ID, _v(keccak256("m2"), keccak256("m1")));
        assertEq(reg.versionCount(ID), 1);
        assertEq(reg.ownerOf(ID), alice);
    }

    function test_takedown_of_older_version_freezes_id() public {
        _publishV1(alice);
        vm.prank(alice);
        reg.publish(ID, _v(keccak256("m2"), keccak256("m1")));
        vm.prank(gov);
        reg.withdraw(ID, 1, 1500);
        assertTrue(reg.frozen(ID));
        assertFalse(reg.getVersion(ID, 2).withdrawn);
        vm.prank(alice);
        vm.expectRevert(DatasetRegistry.DatasetFrozen.selector);
        reg.publish(ID, _v(keccak256("m3"), keccak256("m2")));
    }

    function test_frozen_id_still_allows_withdrawals_of_other_versions() public {
        _publishV1(alice);
        vm.prank(alice);
        reg.publish(ID, _v(keccak256("m2"), keccak256("m1")));
        vm.prank(gov);
        reg.withdraw(ID, 1, 1000);
        vm.prank(alice);
        reg.withdraw(ID, 2, 7);
        assertTrue(reg.getVersion(ID, 2).withdrawn);
        assertTrue(reg.frozen(ID));
    }

    function test_freeze_is_per_id() public {
        _publishV1(alice);
        vm.prank(gov);
        reg.withdraw(ID, 1, 1000);
        bytes32 other = _nsId(alice, "dataset/other");
        vm.prank(alice);
        reg.publish(other, _v(keccak256("o1"), bytes32(0)));
        assertFalse(reg.frozen(other));
    }

    function test_governance_withdraw_needs_takedown_code() public {
        _publishV1(alice);
        vm.startPrank(gov);
        vm.expectRevert(DatasetRegistry.BadReason.selector);
        reg.withdraw(ID, 1, 0);
        vm.expectRevert(DatasetRegistry.BadReason.selector);
        reg.withdraw(ID, 1, 999);
        vm.stopPrank();
        assertFalse(reg.frozen(ID));
        assertFalse(reg.getVersion(ID, 1).withdrawn);
    }

    /// forge-config: default.fuzz.runs = 10000
    function testFuzz_frozen_id_never_gains_a_version(uint16 reason, uint8 tries, bytes32 salt) public {
        reason = uint16(bound(reason, 1000, type(uint16).max));
        _publishV1(alice);
        vm.prank(gov);
        reg.withdraw(ID, 1, reason);
        address[3] memory actors = [alice, bob, gov];
        for (uint256 i = 0; i < uint256(tries % 8) + 1; i++) {
            vm.prank(actors[i % 3]);
            try reg.publish(ID, _v(keccak256(abi.encode(salt, i)), keccak256("m1"))) {
                fail();
            } catch {}
        }
        assertEq(reg.versionCount(ID), 1);
        assertTrue(reg.frozen(ID));
    }

    function test_latest_reverts_when_empty() public {
        vm.expectRevert(DatasetRegistry.UnknownVersion.selector);
        reg.latest(ID);
    }

    // ── no funds ────────────────────────────────────────────────────

    function test_holds_no_value() public {
        vm.deal(alice, 1 ether);
        vm.prank(alice);
        (bool ok,) = address(reg).call{value: 1}("");
        assertFalse(ok, "plain transfer must revert");
        vm.prank(alice);
        (ok,) = address(reg).call{value: 1}(abi.encodeCall(reg.publish, (ID, _v(keccak256("m1"), bytes32(0)))));
        assertFalse(ok, "publish must not be payable");
        assertEq(address(reg).balance, 0);
    }

    function test_constructor_refuses_zero_governance() public {
        vm.expectRevert();
        new DatasetRegistry(address(0));
    }

    // ── takedown applies whatever the version's state (Q15) ──────────

    /// The publisher withdrawing a version before a queued takedown executes does not stop the
    /// takedown: the id is frozen and accepts no further version.
    function test_takedown_freezes_after_publisher_withdrew_first() public {
        _publishV1(alice);
        vm.prank(alice);
        reg.withdraw(ID, 1, 1);
        vm.expectEmit(true, false, false, true, address(reg));
        emit DatasetRegistry.DatasetIdFrozen(ID, 1, 1000);
        vm.prank(gov);
        reg.withdraw(ID, 1, 1000);
        assertTrue(reg.frozen(ID));
        assertTrue(reg.getVersion(ID, 1).withdrawn);
        vm.prank(alice);
        vm.expectRevert(DatasetRegistry.DatasetFrozen.selector);
        reg.publish(ID, _v(keccak256("m1-again"), keccak256("m1")));
        assertEq(reg.versionCount(ID), 1);
    }

    /// A repeated takedown (for example a second queued timelock operation) does not revert and
    /// changes nothing.
    function test_repeated_takedown_is_a_noop() public {
        _publishV1(alice);
        vm.prank(gov);
        reg.withdraw(ID, 1, 1000);
        vm.recordLogs();
        vm.prank(gov);
        reg.withdraw(ID, 1, 1200);
        assertEq(vm.getRecordedLogs().length, 0);
        assertTrue(reg.frozen(ID));
        assertTrue(reg.getVersion(ID, 1).withdrawn);
    }

    /// forge-config: default.fuzz.runs = 10000
    function testFuzz_takedown_freezes_regardless_of_version_state(
        uint8 nVersions,
        uint8 target,
        uint256 withdrawnMask,
        uint16 reason
    ) public {
        uint32 n = uint32(nVersions % 6) + 1;
        uint32 t = uint32(target % n) + 1;
        reason = uint16(bound(reason, 1000, type(uint16).max));
        bytes32 prev;
        for (uint32 i = 1; i <= n; i++) {
            bytes32 m = keccak256(abi.encode("m", i));
            vm.prank(alice);
            reg.publish(ID, _v(m, prev));
            prev = m;
            if ((withdrawnMask >> i) & 1 == 1) {
                vm.prank(alice);
                reg.withdraw(ID, i, 1);
            }
        }
        vm.prank(gov);
        reg.withdraw(ID, t, reason);
        assertTrue(reg.frozen(ID));
        assertTrue(reg.getVersion(ID, t).withdrawn);
        vm.prank(alice);
        vm.expectRevert(DatasetRegistry.DatasetFrozen.selector);
        reg.publish(ID, _v(keccak256("next"), prev));
    }

    // ── dataset ids are namespaced by publisher ──────────────────────

    /// Nobody can take a dataset id in another publisher's namespace, so a copied pending v1
    /// transaction cannot claim the id first.
    function test_v1_must_be_in_the_publishers_namespace() public {
        vm.prank(bob);
        vm.expectRevert(DatasetRegistry.NotDatasetOwner.selector);
        reg.publish(ID, _v(keccak256("m1"), bytes32(0)));
        vm.prank(gov);
        vm.expectRevert(DatasetRegistry.NotDatasetOwner.selector);
        reg.publish(ID, _v(keccak256("m1"), bytes32(0)));
        assertEq(reg.versionCount(ID), 0);
        assertEq(_publishV1(alice), 1);
        assertEq(reg.ownerOf(ID), alice);
    }

    /// forge-config: default.fuzz.runs = 10000
    function testFuzz_v1_outside_namespace_refused(address caller, bytes32 id) public {
        vm.assume(address(uint160(uint256(id) >> 96)) != caller);
        vm.prank(caller);
        vm.expectRevert(DatasetRegistry.NotDatasetOwner.selector);
        reg.publish(id, _v(keccak256("m1"), bytes32(0)));
    }

    // ── governance as a dataset owner ────────────────────────────────

    /// Governance publishing its own dataset can still take it down with a takedown code, and
    /// withdraw one version with a publisher code.
    function test_governance_owner_can_take_down_its_own_dataset() public {
        bytes32 gid = _nsId(gov, "dataset/gov");
        vm.startPrank(gov);
        reg.publish(gid, _v(keccak256("g1"), bytes32(0)));
        reg.publish(gid, _v(keccak256("g2"), keccak256("g1")));
        reg.withdraw(gid, 1, 5);
        assertTrue(reg.getVersion(gid, 1).withdrawn);
        assertFalse(reg.frozen(gid));
        reg.withdraw(gid, 2, 1000);
        vm.stopPrank();
        assertTrue(reg.frozen(gid));
        assertTrue(reg.getVersion(gid, 2).withdrawn);
    }

    // ── license placeholders ─────────────────────────────────────────

    function test_publish_refuses_noassertion_and_padded_licenses() public {
        string[9] memory bad =
            ["NOASSERTION", "noassertion", "NoAssertion", " unknown", "unknown ", "\tunknown", " MIT", "MIT\n", " "];
        for (uint256 i = 0; i < bad.length; i++) {
            DatasetRegistry.Version memory v = _v(keccak256("m1"), bytes32(0));
            v.license = bad[i];
            vm.prank(alice);
            vm.expectRevert(DatasetRegistry.BadLicense.selector);
            reg.publish(ID, v);
        }
        DatasetRegistry.Version memory ok = _v(keccak256("m1"), bytes32(0));
        ok.license = "MIT OR Apache-2.0";
        vm.prank(alice);
        assertEq(reg.publish(ID, ok), 1);
    }

    // ── fuzz ────────────────────────────────────────────────────────

    /// A random sequence of publish attempts by random callers: the chain stays linear, the owner is
    /// the first successful publisher, and every stored version has prev = the previous manifest.
    /// forge-config: default.fuzz.runs = 10000
    function testFuzz_publish_sequences(uint8[16] memory who, bytes32[16] memory manifests, bool[16] memory goodPrev)
        public
    {
        address[3] memory actors = [alice, bob, gov];
        bytes32 last;
        address owner_;
        uint32 count;
        for (uint256 i = 0; i < 16; i++) {
            address a = actors[who[i] % 3];
            bytes32 prev = goodPrev[i] ? last : keccak256(abi.encode(last, i));
            DatasetRegistry.Version memory v = _v(manifests[i], prev);
            vm.prank(a);
            try reg.publish(ID, v) returns (uint32 ver) {
                assertTrue(manifests[i] != bytes32(0) && manifests[i] != prev);
                assertEq(prev, last);
                if (count == 0) owner_ = a;
                else assertEq(a, owner_);
                count++;
                assertEq(ver, count);
                last = manifests[i];
            } catch {}
        }
        assertEq(reg.versionCount(ID), count);
        assertEq(reg.ownerOf(ID), owner_);
        for (uint32 k = 2; k <= count; k++) {
            assertEq(reg.getVersion(ID, k).prev, reg.getVersion(ID, k - 1).manifestHash);
        }
    }

    /// forge-config: default.fuzz.runs = 10000
    function testFuzz_license_unknown_any_case(uint8 mask) public {
        bytes memory w = bytes("unknown");
        for (uint256 i = 0; i < 7; i++) {
            if ((mask >> i) & 1 == 1) w[i] = bytes1(uint8(w[i]) - 32);
        }
        DatasetRegistry.Version memory v = _v(keccak256("m1"), bytes32(0));
        v.license = string(w);
        vm.prank(alice);
        vm.expectRevert(DatasetRegistry.BadLicense.selector);
        reg.publish(ID, v);
    }
}

/// Drives publish/withdraw from several actors over a few ids and records ghost state.
contract DatasetRegistryHandler is Test {
    DatasetRegistry public reg;
    address public gov;
    address[3] public actors;
    bytes32[3] public ids;

    mapping(bytes32 => address) public firstOwner;
    mapping(bytes32 => uint32) public maxCount;
    mapping(bytes32 => mapping(uint32 => bool)) public everWithdrawn;
    mapping(bytes32 => bool) public frozenGhost;
    mapping(bytes32 => uint32) public countAtFreeze;
    uint256 public nonce;

    constructor(DatasetRegistry reg_, address gov_) {
        reg = reg_;
        gov = gov_;
        actors = [makeAddr("h-alice"), makeAddr("h-bob"), gov_];
        // one id in each actor's namespace; every actor tries every id
        for (uint256 i = 0; i < 3; i++) {
            ids[i] =
                bytes32((uint256(uint160(actors[i])) << 96) | uint256(uint96(uint256(keccak256(abi.encode("d", i))))));
        }
    }

    function publish(uint256 actorSeed, uint256 idSeed, bool goodPrev, uint8 privacySeed) external {
        address a = actors[actorSeed % 3];
        bytes32 id = ids[idSeed % 3];
        uint32 n = reg.versionCount(id);
        bytes32 prev;
        if (n > 0) {
            (, DatasetRegistry.Version memory last) = reg.latest(id);
            prev = goodPrev ? last.manifestHash : keccak256(abi.encode(nonce));
        }
        DatasetRegistry.Version memory v;
        v.manifestHash = keccak256(abi.encode("m", nonce++));
        v.prev = prev;
        v.license = "MIT";
        v.privacy = DatasetRegistry.Privacy(privacySeed % 4);
        if (v.privacy != DatasetRegistry.Privacy.IndexOnly) v.cid = "bafy";
        if (v.privacy == DatasetRegistry.Privacy.Group) v.groupHash = keccak256("g");
        vm.prank(a);
        try reg.publish(id, v) {
            if (n == 0) firstOwner[id] = a;
            maxCount[id] = n + 1;
        } catch {}
    }

    function withdraw(uint256 actorSeed, uint256 idSeed, uint32 verSeed, uint16 reason) external {
        bytes32 id = ids[idSeed % 3];
        uint32 n = reg.versionCount(id);
        if (n == 0) return;
        uint32 ver = uint32(verSeed % n) + 1;
        address a = actors[actorSeed % 3];
        // bias toward valid codes so takedowns actually happen
        if (reason % 2 == 0) reason = a == gov && reason % 4 == 0 ? 1000 + reason % 1000 : 1 + reason % 999;
        bool takedown = a == gov && reason >= 1000;
        vm.prank(a);
        try reg.withdraw(id, ver, reason) {
            everWithdrawn[id][ver] = true;
        } catch {}
        // Q15: a governance takedown freezes the id whatever the version's state
        if (takedown && !frozenGhost[id]) {
            frozenGhost[id] = true;
            countAtFreeze[id] = n;
        }
    }

    function id(uint256 i) external view returns (bytes32) {
        return ids[i];
    }
}

contract DatasetRegistryInvariantTest is StdInvariant, Test {
    DatasetRegistry internal reg;
    DatasetRegistryHandler internal h;

    function setUp() public {
        reg = new DatasetRegistry(makeAddr("gov"));
        h = new DatasetRegistryHandler(reg, makeAddr("gov"));
        targetContract(address(h));
    }

    /// Versions only grow: the stored count equals the handler's high-water mark.
    function invariant_versions_only_grow() public view {
        for (uint256 i = 0; i < 3; i++) {
            bytes32 id = h.id(i);
            assertEq(reg.versionCount(id), h.maxCount(id));
        }
    }

    /// An id's owner is its first publisher, forever.
    function invariant_owner_never_changes() public view {
        for (uint256 i = 0; i < 3; i++) {
            bytes32 id = h.id(i);
            assertEq(reg.ownerOf(id), h.firstOwner(id));
        }
    }

    /// Withdrawn never flips back.
    function invariant_withdrawn_is_sticky() public view {
        for (uint256 i = 0; i < 3; i++) {
            bytes32 id = h.id(i);
            uint32 n = reg.versionCount(id);
            for (uint32 v = 1; v <= n; v++) {
                if (h.everWithdrawn(id, v)) assertTrue(reg.getVersion(id, v).withdrawn);
            }
        }
    }

    /// Q15: once a governance takedown froze an id, it never gains a version and stays frozen.
    function invariant_frozen_id_never_gains_a_version() public view {
        for (uint256 i = 0; i < 3; i++) {
            bytes32 id = h.id(i);
            if (h.frozenGhost(id)) {
                assertTrue(reg.frozen(id));
                assertEq(reg.versionCount(id), h.countAtFreeze(id));
            } else if (reg.versionCount(id) > 0) {
                assertFalse(reg.frozen(id));
            }
        }
    }

    /// The prev chain is linear and the contract never holds value.
    function invariant_chain_linear_and_no_value() public view {
        assertEq(address(reg).balance, 0);
        for (uint256 i = 0; i < 3; i++) {
            bytes32 id = h.id(i);
            uint32 n = reg.versionCount(id);
            if (n > 0) assertEq(reg.getVersion(id, 1).prev, bytes32(0));
            for (uint32 v = 2; v <= n; v++) {
                assertEq(reg.getVersion(id, v).prev, reg.getVersion(id, v - 1).manifestHash);
            }
        }
    }
}
