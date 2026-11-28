// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Base58} from "./utils/Base58.sol";

/// @title TronCoder
/// @notice Tron (coinType 195) address <-> 21 bytes (0x41 ‖ 20-byte account), as used by ENS `addr(node, 195)`.
/// @dev Addresses are Base58Check ("T...").
///
/// References:
/// - Account address format: https://developers.tron.network/docs/account#account-address-format
/// - Base58Check: https://en.bitcoin.it/wiki/Base58Check_encoding
/// - Reference: https://github.com/ensdomains/address-encoder/blob/main/src/coin/trx.ts
library TronCoder {
    uint256 internal constant COIN_TYPE = 195;

    uint8 internal constant VERSION = 0x41;

    /// @notice 0x41 ‖ 20-byte account -> address string.
    /// @return ok False if `data` is not 21 bytes starting with 0x41.
    function encode(bytes memory data) internal pure returns (bool ok, string memory addr) {
        if (data.length != 21 || uint8(data[0]) != VERSION) return (false, "");
        return (true, Base58.encodeCheck(data));
    }

    /// @notice Address string -> 0x41 ‖ 20-byte account.
    /// @return ok False if `addr` is not Base58Check of 21 bytes starting with VERSION.
    function decode(string memory addr) internal pure returns (bool ok, bytes memory data) {
        (ok, data) = Base58.decodeCheck(addr);
        if (!ok || data.length != 21 || uint8(data[0]) != VERSION) return (false, "");
    }
}
