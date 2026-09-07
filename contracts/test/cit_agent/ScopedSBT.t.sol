// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {FacilitySBT} from "../../src/cit_agent/FacilitySBT.sol";
import {NetworkSBT} from "../../src/cit_agent/NetworkSBT.sol";
import {OrgScopedSBTUpgradeable} from "../../src/cit_agent/OrgScopedSBTUpgradeable.sol";

/// A trivial "v2" implementation used to prove UUPS upgrade authority.
contract FacilitySBTV2 is FacilitySBT {
    function version() external pure returns (uint256) {
        return 2;
    }
}

contract ScopedSBTTest is Test {
    FacilitySBT fac;
    NetworkSBT net;

    address gov = address(0x6091);
    address minter = address(0x312E7);
    address orgCtl = address(0x0126); // org's own controller
    address holder = address(0x4013);
    address stranger = address(0x57A);

    bytes32 constant DID_A = keccak256("did:citrate:facility:A");
    bytes32 constant DID_B = keccak256("did:citrate:network:B");

    function setUp() public {
        FacilitySBT facImpl = new FacilitySBT();
        fac = FacilitySBT(address(new ERC1967Proxy(
            address(facImpl), abi.encodeCall(FacilitySBT.initialize, (gov, minter))
        )));
        NetworkSBT netImpl = new NetworkSBT();
        net = NetworkSBT(address(new ERC1967Proxy(
            address(netImpl), abi.encodeCall(NetworkSBT.initialize, (gov, minter))
        )));
    }

    function _mintFacility() internal returns (uint256 id) {
        bytes32[] memory overlays = new bytes32[](0);
        vm.prank(minter);
        id = fac.mint(holder, DID_A, 1, orgCtl, overlays);
    }

    // ── issuance + authority ──────────────────────────────────────────────────

    function test_only_minter_can_mint() public {
        bytes32[] memory o = new bytes32[](0);
        vm.expectRevert(); // AccessControl: stranger lacks MINTER_ROLE
        vm.prank(stranger);
        fac.mint(holder, DID_A, 1, orgCtl, o);
    }

    function test_mint_sets_node_and_parent_org() public {
        uint256 id = _mintFacility();
        assertEq(fac.ownerOf(id), holder);
        assertEq(fac.parentOrgOf(id), 1);
        assertTrue(fac.isActive(id));
        assertEq(fac.getNode(id).orgAuthority, orgCtl);
    }

    // ── DID uniqueness (the E09 property, enforced from the start) ─────────────

    function test_did_uniqueness_blocks_double_mint() public {
        _mintFacility();
        bytes32[] memory o = new bytes32[](0);
        vm.expectRevert(OrgScopedSBTUpgradeable.AlreadyMinted.selector);
        vm.prank(minter);
        fac.mint(stranger, DID_A, 2, orgCtl, o);
    }

    function test_zero_did_rejected() public {
        bytes32[] memory o = new bytes32[](0);
        vm.expectRevert(OrgScopedSBTUpgradeable.ZeroDid.selector);
        vm.prank(minter);
        fac.mint(holder, bytes32(0), 1, orgCtl, o);
    }

    // ── soulbound ──────────────────────────────────────────────────────────────

    function test_transfer_reverts_soulbound() public {
        uint256 id = _mintFacility();
        vm.expectRevert(OrgScopedSBTUpgradeable.TransferNotAllowed.selector);
        vm.prank(holder);
        fac.transferFrom(holder, stranger, id);
    }

    // ── per-org configuration (upgradeability's "not stuck in the mud" half) ───

    function test_org_authority_can_set_attribute() public {
        uint256 id = _mintFacility();
        bytes32 key = fac.LOCATION_REF(); // read before prank (an external call would consume it)
        bytes memory val = abi.encode(keccak256("hashed-site-ref"));
        vm.prank(orgCtl);
        fac.setAttribute(id, key, val);
        assertEq(fac.locationRef(id), val);
    }

    function test_stranger_cannot_configure() public {
        uint256 id = _mintFacility();
        vm.expectRevert(OrgScopedSBTUpgradeable.NotOrgAuthorityOrGovernor.selector);
        vm.prank(stranger);
        fac.setAttribute(id, bytes32("k"), hex"01");
    }

    function test_governor_can_configure_any_token() public {
        uint256 id = _mintFacility();
        vm.prank(gov);
        fac.setTokenURI(id, "ipfs://facility-meta");
        assertEq(fac.tokenURI(id), "ipfs://facility-meta");
    }

    function test_overlay_ratchet_appends() public {
        uint256 id = _mintFacility();
        vm.prank(orgCtl);
        fac.activateOverlay(id, keccak256("FedRAMP-Moderate"));
        assertEq(fac.getNode(id).overlays.length, 1);
    }

    function test_network_chain_id_convenience() public {
        bytes32[] memory o = new bytes32[](0);
        vm.prank(minter);
        uint256 id = net.mint(holder, DID_B, 1, orgCtl, o);
        assertEq(net.chainIdOf(id), 0);
        bytes32 key = net.CHAIN_ID(); // read before prank
        vm.prank(orgCtl);
        net.setAttribute(id, key, abi.encode(uint256(40205)));
        assertEq(net.chainIdOf(id), 40205);
    }

    // ── deactivation ───────────────────────────────────────────────────────────

    function test_only_governor_deactivates() public {
        uint256 id = _mintFacility();
        vm.expectRevert();
        vm.prank(orgCtl);
        fac.deactivate(id);
        vm.prank(gov);
        fac.deactivate(id);
        assertFalse(fac.isActive(id));
    }

    // ── UUPS upgrade authority ─────────────────────────────────────────────────

    function test_governor_can_upgrade() public {
        uint256 id = _mintFacility();
        FacilitySBTV2 v2 = new FacilitySBTV2();
        vm.prank(gov);
        fac.upgradeToAndCall(address(v2), "");
        assertEq(FacilitySBTV2(address(fac)).version(), 2);
        // state survives the upgrade
        assertEq(fac.ownerOf(id), holder);
    }

    function test_non_governor_cannot_upgrade() public {
        FacilitySBTV2 v2 = new FacilitySBTV2();
        vm.expectRevert();
        vm.prank(stranger);
        fac.upgradeToAndCall(address(v2), "");
    }
}
