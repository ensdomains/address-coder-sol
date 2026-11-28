// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Bech32} from "./utils/Bech32.sol";

/// @title CosmosCoder
/// @notice Cosmos Hub (coinType 118) address <-> account bytes, as used by ENS `addr(node, 118)`.
/// @dev Addresses are bech32 with human-readable part "cosmos". Accounts are usually 20 bytes
///      (32 for module / interchain accounts); any non-empty length that fits in 90 chars is accepted.
///
/// References:
/// - Addresses: https://docs.cosmos.network/main/learn/beginner/accounts#addresses
/// - BIP-173 (bech32): https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
/// - Reference: https://github.com/ensdomains/address-encoder/blob/main/src/coin/atom.ts
library CosmosCoder {
    uint256 internal constant COIN_TYPE = 118;

    bytes internal constant HRP = "cosmos";

    /// @notice Account bytes -> "cosmos1..." address string.
    /// @return ok False if `data` is empty or too long for a 90-char address (> 48 bytes).
    function encode(bytes memory data) internal pure returns (bool ok, string memory addr) {
        if (data.length == 0) return (false, "");
        return Bech32.encode(HRP, data, Bech32.Variant.Bech32);
    }

    /// @notice "cosmos1..." address string -> account bytes.
    /// @return ok False if `addr` is not a bech32 "cosmos" address of at least 1 byte.
    function decode(string memory addr) internal pure returns (bool ok, bytes memory data) {
        (ok, data) = Bech32.decode(HRP, addr, Bech32.Variant.Bech32);
        if (!ok || data.length == 0) return (false, "");
    }
}
