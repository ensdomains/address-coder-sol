// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Base58} from "./utils/Base58.sol";

/// @title TronCoder
/// @notice Tron (coinType 195) address <-> 21 bytes (0x41 ‖ 20-byte account), as used by ENS `addr(node, 195)`.
/// @dev Addresses are Base58Check ("T...").
library TronCoder {
    error UnrecognisedAddressFormat();

    uint256 internal constant COIN_TYPE = 195;

    uint8 internal constant VERSION = 0x41;

    /// @notice 0x41 ‖ 20-byte account -> "T..." address string.
    function encode(bytes memory data) internal pure returns (string memory) {
        if (data.length != 21 || uint8(data[0]) != VERSION) revert UnrecognisedAddressFormat();
        return Base58.encodeCheck(data);
    }

    /// @notice "T..." address string -> 0x41 ‖ 20-byte account.
    function decode(string memory addr) internal pure returns (bytes memory data) {
        data = Base58.decodeCheck(addr);
        if (data.length != 21 || uint8(data[0]) != VERSION) revert UnrecognisedAddressFormat();
    }
}
