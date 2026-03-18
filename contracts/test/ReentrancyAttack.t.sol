// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/WrappedSALT.sol";
import "../src/ModelMarketplace.sol";
import "../src/ModelRegistry.sol";
import "../src/interfaces/IModelRegistry.sol";

/// @title ReentrancyAttacker
/// @notice Malicious contract that attempts to re-enter withdraw() on ETH receive.
contract ReentrancyAttacker {
    WrappedSALT public target;
    uint256 public attackCount;
    bool public reentrancyAttempted;
    bool public reentrancySucceeded;

    constructor(WrappedSALT _target) {
        target = _target;
    }

    /// @notice Deposit ETH into wSALT via this contract.
    function deposit() external payable {
        target.deposit{value: msg.value}();
    }

    /// @notice Trigger withdrawal -- this will cause receive() to fire.
    function attack(uint256 amount) external {
        attackCount = 0;
        reentrancyAttempted = false;
        reentrancySucceeded = false;
        target.withdraw(amount);
    }

    /// @notice Re-enter withdraw() when receiving ETH.
    receive() external payable {
        attackCount++;
        if (attackCount == 1) {
            reentrancyAttempted = true;
            uint256 bal = target.balanceOf(address(this));
            if (bal > 0) {
                // Attempt reentrancy: call withdraw again while inside withdraw
                try target.withdraw(bal) {
                    reentrancySucceeded = true;
                } catch {
                    // Expected: nonReentrant blocks re-entry
                    reentrancySucceeded = false;
                }
            }
        }
    }
}

/// @title MarketplaceReentrancyAttacker
/// @notice Malicious seller contract that attempts to re-enter purchaseAccess
///         when it receives the seller payment via transfer().
contract MarketplaceReentrancyAttacker {
    ModelMarketplace public marketplace;
    bytes32 public modelId;
    bool public attacking;
    bool public reentrancyAttempted;
    bool public reentrancySucceeded;

    constructor(ModelMarketplace _marketplace) {
        marketplace = _marketplace;
    }

    function setModelId(bytes32 _modelId) external {
        modelId = _modelId;
    }

    function enableAttack() external {
        attacking = true;
        reentrancyAttempted = false;
        reentrancySucceeded = false;
    }

    receive() external payable {
        if (attacking) {
            attacking = false; // prevent infinite loop
            reentrancyAttempted = true;
            // Attempt to re-enter purchaseAccess
            try marketplace.purchaseAccess{value: msg.value}(modelId, 1) {
                reentrancySucceeded = true;
            } catch {
                // Expected: reentrant call reverts
                reentrancySucceeded = false;
            }
        }
    }
}

contract ReentrancyAttackTest is Test {
    WrappedSALT public wSALT;
    ModelMarketplace public marketplace;
    ModelRegistry public registry;

    address public alice;
    address public treasury;

    function setUp() public {
        wSALT = new WrappedSALT();
        registry = new ModelRegistry();
        treasury = address(0xFEE);
        marketplace = new ModelMarketplace(address(registry), treasury);

        alice = makeAddr("alice");
        vm.deal(alice, 100 ether);
    }

    // ============================================================
    // 1. wSALT withdraw reentrancy blocked
    // ============================================================

    function test_wSALT_withdraw_reentrancy_blocked() public {
        ReentrancyAttacker attacker = new ReentrancyAttacker(wSALT);
        vm.deal(address(attacker), 10 ether);

        // Attacker deposits 5 ETH into wSALT
        attacker.deposit{value: 5 ether}();
        assertEq(wSALT.balanceOf(address(attacker)), 5 ether);

        // The outer withdraw sends ETH to the attacker contract.
        // The attacker's receive() tries to re-enter withdraw().
        // nonReentrant blocks the inner call, which causes the inner
        // withdraw to revert. The outer withdraw's call{value}
        // returns success=false -> reverts with "native transfer failed".
        //
        // The key assertion: the reentrancy attempt either:
        //   (a) causes the outer tx to revert (blocking the attack), or
        //   (b) the inner call fails and is caught by try/catch
        //
        // With the try/catch approach, the outer withdraw succeeds,
        // the inner attempt is silently caught, and we verify
        // reentrancySucceeded == false.
        attacker.attack(1 ether);

        // Reentrancy was attempted but blocked by nonReentrant
        assertTrue(attacker.reentrancyAttempted(), "Reentrancy should have been attempted");
        assertFalse(attacker.reentrancySucceeded(), "Reentrancy must NOT succeed");

        // Only 1 ETH was withdrawn (not drained)
        assertEq(wSALT.balanceOf(address(attacker)), 4 ether);
    }

    // ============================================================
    // 2. Marketplace purchaseAccess reentrancy blocked
    // ============================================================

    function test_marketplace_purchase_reentrancy_blocked() public {
        MarketplaceReentrancyAttacker sellerAttacker = new MarketplaceReentrancyAttacker(marketplace);
        vm.deal(address(sellerAttacker), 10 ether);

        // Register model with the attacker contract as owner
        vm.startPrank(address(sellerAttacker));

        IModelRegistry.ModelMetadata memory metadata = IModelRegistry.ModelMetadata({
            description: "Attack model",
            inputShape: new string[](1),
            outputShape: new string[](1),
            parameters: 1000,
            license: "MIT",
            tags: new string[](1)
        });
        metadata.inputShape[0] = "1";
        metadata.outputShape[0] = "1";
        metadata.tags[0] = "test";

        bytes32 modelId = registry.registerModel{value: registry.REGISTRATION_FEE()}(
            "AttackModel",
            "PyTorch",
            "1.0.0",
            "QmAttackCID",
            1000,
            0.01 ether,
            metadata
        );

        // List model in marketplace
        marketplace.listModel(
            modelId,
            0.01 ether,    // basePrice
            0.008 ether,   // discountPrice
            10,            // minimumBulkSize
            1,             // category
            "ipfs://attack-meta"
        );
        vm.stopPrank();

        // Configure attacker
        sellerAttacker.setModelId(modelId);
        sellerAttacker.enableAttack();

        // Buyer purchases: marketplace uses transfer() which sends ETH to
        // the seller (attacker). transfer() only forwards 2300 gas which
        // is not enough to re-enter, so the reentrancy attempt reverts.
        // Since transfer() reverts on failure, the entire outer tx reverts too.
        // This means the purchase itself is blocked.
        //
        // Actually: `payable(listing.owner).transfer(sellerAmount)` uses
        // .transfer() which limits gas to 2300. The receive() fallback
        // in the attacker contract tries to call marketplace.purchaseAccess
        // which needs far more gas -> OOG -> transfer fails -> outer reverts.
        //
        // This IS a form of reentrancy protection (gas limit), but it means
        // the purchase transaction reverts entirely.
        vm.prank(alice);
        vm.expectRevert();
        marketplace.purchaseAccess{value: 0.01 ether}(modelId, 1);
    }

    // ============================================================
    // 3. wSALT deposit with zero value via receive()
    // ============================================================

    function test_wSALT_deposit_zero_value() public {
        // Sending 0 ETH to receive(): the nonReentrant version
        // of receive() will run. msg.value = 0 means balance
        // doesn't change but no revert occurs.
        uint256 supplyBefore = wSALT.totalSupply();

        vm.prank(alice);
        (bool success,) = address(wSALT).call{value: 0}("");
        assertTrue(success, "receive() with 0 value should not revert");

        assertEq(wSALT.balanceOf(alice), 0);
        assertEq(wSALT.totalSupply(), supplyBefore);
    }

    // ============================================================
    // 4. Marketplace purchase with max uint256 price
    // ============================================================

    function test_marketplace_purchase_max_uint256_price() public {
        // listModel requires price between MIN_PRICE and MAX_PRICE,
        // so setting type(uint256).max should revert with "Invalid price".
        address seller = makeAddr("seller");
        vm.deal(seller, 10 ether);

        vm.startPrank(seller);

        IModelRegistry.ModelMetadata memory metadata = IModelRegistry.ModelMetadata({
            description: "Max price model",
            inputShape: new string[](1),
            outputShape: new string[](1),
            parameters: 1000,
            license: "MIT",
            tags: new string[](1)
        });
        metadata.inputShape[0] = "1";
        metadata.outputShape[0] = "1";
        metadata.tags[0] = "test";

        bytes32 modelId = registry.registerModel{value: registry.REGISTRATION_FEE()}(
            "MaxPriceModel",
            "PyTorch",
            "1.0.0",
            "QmMaxPriceCID",
            1000,
            0.01 ether,
            metadata
        );

        // Attempt to list with type(uint256).max price -- should revert
        vm.expectRevert("Invalid price");
        marketplace.listModel(
            modelId,
            type(uint256).max,  // basePrice = max
            0.001 ether,        // discountPrice
            1,                  // minimumBulkSize
            1,                  // category
            "ipfs://maxprice"
        );
        vm.stopPrank();
    }
}
