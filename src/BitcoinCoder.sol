// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BitcoinLike} from "./utils/BitcoinLike.sol";

/// @title BitcoinCoder
/// @notice Bitcoin (coinType 0) address <-> scriptPubKey bytes, as used by ENS `addr(node, 0)`.
/// @dev `decode`: "1...", "3..." or "bc1..." -> scriptPubKey. `encode`: scriptPubKey -> address.
///      Supported scripts: P2PKH, P2SH and SegWit v0-v16 (P2WPKH, P2WSH, P2TR, ...).
///
/// References:
/// - Base58Check: https://en.bitcoin.it/wiki/Base58Check_encoding
/// - BIP-13 (P2SH addresses): https://github.com/bitcoin/bips/blob/master/bip-0013.mediawiki
/// - BIP-141 (witness programs): https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
/// - BIP-173 (bech32): https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
/// - BIP-350 (bech32m): https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
/// - Address prefixes: https://github.com/bitcoin/bitcoin/blob/master/src/kernel/chainparams.cpp
/// - ENSIP-9 (multichain addresses): https://docs.ens.domains/ensip/9
/// - Reference: https://github.com/ensdomains/address-encoder/blob/main/src/coin/btc.ts
library BitcoinCoder {
    uint256 internal constant COIN_TYPE = 0;

    bytes internal constant HRP = "bc";
    uint8 internal constant P2PKH_VERSION = 0x00;
    uint8 internal constant P2SH_VERSION = 0x05;

    /// @notice scriptPubKey -> address string.
    /// @return ok False if `script` is not P2PKH, P2SH or a valid SegWit output.
    function encode(bytes memory script) internal pure returns (bool ok, string memory addr) {
        return BitcoinLike.encode(script, HRP, P2PKH_VERSION, P2SH_VERSION);
    }

    /// @notice Address string -> scriptPubKey.
    /// @return ok False if `addr` is not a valid address.
    function decode(string memory addr) internal pure returns (bool ok, bytes memory data) {
        return BitcoinLike.decode(addr, HRP, P2PKH_VERSION, P2SH_VERSION);
    }
}
