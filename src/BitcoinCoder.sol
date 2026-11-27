// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BitcoinLike} from "./utils/BitcoinLike.sol";

/// @title BitcoinCoder
/// @notice Bitcoin (coinType 0) address <-> scriptPubKey bytes, as used by ENS `addr(node, 0)`.
/// @dev `decode`: "1...", "3..." or "bc1..." -> scriptPubKey. `encode`: scriptPubKey -> address.
///      Supported scripts: P2PKH, P2SH and SegWit v0-v16 (P2WPKH, P2WSH, P2TR, ...).
library BitcoinCoder {
    uint256 internal constant COIN_TYPE = 0;

    bytes internal constant HRP = "bc";
    uint8 internal constant P2PKH_VERSION = 0x00;
    uint8 internal constant P2SH_VERSION = 0x05;

    /// @notice scriptPubKey -> address string.
    function encode(bytes memory script) internal pure returns (string memory) {
        return BitcoinLike.encode(script, HRP, P2PKH_VERSION, P2SH_VERSION);
    }

    /// @notice Address string -> scriptPubKey.
    function decode(string memory addr) internal pure returns (bytes memory) {
        return BitcoinLike.decode(addr, HRP, P2PKH_VERSION, P2SH_VERSION);
    }
}
