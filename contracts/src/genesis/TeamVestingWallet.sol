// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {InitialAdmin} from "../lib/InitialAdmin.sol";
import {VestingWallet} from "@openzeppelin/contracts/finance/VestingWallet.sol";
import {VestingWalletCliff} from "@openzeppelin/contracts/finance/VestingWalletCliff.sol";

/// @title TeamVestingWallet: the concrete OZ v5.7.0 `VestingWalletCliff` for team SALT (C2 D2 / G2)
/// @notice OZ ships `VestingWalletCliff` abstract; this only fixes the constructor. All vesting,
///         release and ownership logic is the audited OZ code: nothing vests before the cliff,
///         then linearly from `start` to `start + duration`; `release()` (callable by anyone)
///         pays native SALT to `owner()`, which starts as the beneficiary.
/// @dev The beneficiary runs through `InitialAdmin.check`, so a CREATE2-ceremony deploy cannot
///      name the zero address or the Arachnid factory as owner (PBA-L2-002).
contract TeamVestingWallet is VestingWalletCliff {
    constructor(address beneficiary, uint64 startTimestamp, uint64 durationSeconds, uint64 cliffSeconds)
        VestingWallet(InitialAdmin.check(beneficiary), startTimestamp, durationSeconds)
        VestingWalletCliff(cliffSeconds)
    {}
}
