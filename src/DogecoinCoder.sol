// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BitcoinLike} from "./utils/BitcoinLike.sol";

/// @title DogecoinCoder
/// @notice Dogecoin (coinType 3) address <-> scriptPubKey bytes, as used by ENS `addr(node, 3)`.
/// @dev `decode`: "D..." (P2PKH) or "9..."/"A..." (P2SH) -> scriptPubKey. No SegWit.
///
/// References:
/// - Address prefixes (PUBKEY_ADDRESS 30, SCRIPT_ADDRESS 22): https://github.com/dogecoin/dogecoin/blob/master/src/chainparams.cpp
/// - Base58Check: https://en.bitcoin.it/wiki/Base58Check_encoding
/// - Reference: https://github.com/ensdomains/address-encoder/blob/main/src/coin/doge.ts
library DogecoinCoder {
    uint256 internal constant COIN_TYPE = 3;

    uint8 internal constant P2PKH_VERSION = 0x1e;
    uint8 internal constant P2SH_VERSION = 0x16;

    /// @notice scriptPubKey -> address string.
    /// @return ok False if `script` is not P2PKH or P2SH.
    function encode(bytes memory script) internal pure returns (bool ok, string memory addr) {
        return BitcoinLike.encodeLegacy(script, P2PKH_VERSION, P2SH_VERSION);
    }

    /// @notice Address string -> scriptPubKey. Reverts on invalid input.
    function decode(string memory addr) internal pure returns (bytes memory) {
        return BitcoinLike.decodeLegacy(addr, P2PKH_VERSION, P2SH_VERSION);
    }
}
