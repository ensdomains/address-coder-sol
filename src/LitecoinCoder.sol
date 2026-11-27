// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BitcoinLike} from "./utils/BitcoinLike.sol";

/// @title LitecoinCoder
/// @notice Litecoin (coinType 2) address <-> scriptPubKey bytes, as used by ENS `addr(node, 2)`.
/// @dev `decode`: "L..." (P2PKH), "M..." or legacy "3..." (P2SH), "ltc1..." (SegWit) -> scriptPubKey.
///      `encode` always emits "M..." for P2SH.
///
/// References:
/// - Address prefixes (PUBKEY_ADDRESS 48, SCRIPT_ADDRESS 5, SCRIPT_ADDRESS2 50, bech32 hrp ltc): https://github.com/litecoin-project/litecoin/blob/master/src/chainparams.cpp
/// - BIP-173 / BIP-350 (SegWit addresses): https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
/// - Reference: https://github.com/ensdomains/address-encoder/blob/main/src/coin/ltc.ts
library LitecoinCoder {
    uint256 internal constant COIN_TYPE = 2;

    bytes internal constant HRP = "ltc";
    uint8 internal constant P2PKH_VERSION = 0x30;
    uint8 internal constant P2SH_VERSION = 0x32;
    uint8 internal constant P2SH_LEGACY_VERSION = 0x05;

    /// @notice scriptPubKey -> address string.
    /// @return ok False if `script` is not P2PKH, P2SH or a valid SegWit output.
    function encode(bytes memory script) internal pure returns (bool ok, string memory addr) {
        return BitcoinLike.encode(script, HRP, P2PKH_VERSION, P2SH_VERSION);
    }

    /// @notice Address string -> scriptPubKey. Reverts on invalid input.
    function decode(string memory addr) internal pure returns (bytes memory) {
        return BitcoinLike.decode(addr, HRP, P2PKH_VERSION, P2SH_VERSION, P2SH_LEGACY_VERSION);
    }
}
