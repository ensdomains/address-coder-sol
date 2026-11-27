// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BitcoinLike} from "./utils/BitcoinLike.sol";

/// @title LitecoinCoder
/// @notice Litecoin (coinType 2) address <-> scriptPubKey bytes, as used by ENS `addr(node, 2)`.
/// @dev `decode`: "L..." (P2PKH), "M..." or legacy "3..." (P2SH), "ltc1..." (SegWit) -> scriptPubKey.
///      `encode` always emits "M..." for P2SH.
library LitecoinCoder {
    uint256 internal constant COIN_TYPE = 2;

    bytes internal constant HRP = "ltc";
    uint8 internal constant P2PKH_VERSION = 0x30;
    uint8 internal constant P2SH_VERSION = 0x32;
    uint8 internal constant P2SH_LEGACY_VERSION = 0x05;

    /// @notice scriptPubKey -> address string.
    function encode(bytes memory script) internal pure returns (string memory) {
        return BitcoinLike.encode(script, HRP, P2PKH_VERSION, P2SH_VERSION);
    }

    /// @notice Address string -> scriptPubKey.
    function decode(string memory addr) internal pure returns (bytes memory) {
        return BitcoinLike.decode(addr, HRP, P2PKH_VERSION, P2SH_VERSION, P2SH_LEGACY_VERSION);
    }
}
