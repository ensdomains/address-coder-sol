// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BitcoinLike} from "./utils/BitcoinLike.sol";

/// @title DogecoinCoder
/// @notice Dogecoin (coinType 3) address <-> scriptPubKey bytes, as used by ENS `addr(node, 3)`.
/// @dev `decode`: "D..." (P2PKH) or "9..."/"A..." (P2SH) -> scriptPubKey. No SegWit.
library DogecoinCoder {
    uint256 internal constant COIN_TYPE = 3;

    uint8 internal constant P2PKH_VERSION = 0x1e;
    uint8 internal constant P2SH_VERSION = 0x16;

    /// @notice scriptPubKey -> address string.
    function encode(bytes memory script) internal pure returns (string memory) {
        return BitcoinLike.encodeLegacy(script, P2PKH_VERSION, P2SH_VERSION);
    }

    /// @notice Address string -> scriptPubKey.
    function decode(string memory addr) internal pure returns (bytes memory) {
        return BitcoinLike.decodeLegacy(addr, P2PKH_VERSION, P2SH_VERSION);
    }
}
