// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Bech32} from "./utils/Bech32.sol";

/// @title ChiaCoder
/// @notice Chia (coinType 8444) address <-> 32-byte puzzle hash, as used by ENS `addr(node, 8444)`.
/// @dev Addresses are bech32m with human-readable part "xch".
///
/// References:
/// - Chia addresses (bech32m of the puzzle hash): https://docs.chia.net/addresses/
/// - Chia implementation: https://github.com/Chia-Network/chia-blockchain/blob/main/chia/util/bech32m.py
/// - BIP-350 (bech32m): https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
/// - Reference: https://github.com/ensdomains/address-encoder/blob/main/src/coin/xch.ts
library ChiaCoder {
    uint256 internal constant COIN_TYPE = 8444;

    bytes internal constant HRP = "xch";

    /// @notice 32-byte puzzle hash -> "xch1..." address string.
    /// @return ok False if `puzzleHash` is not 32 bytes.
    function encode(bytes memory puzzleHash) internal pure returns (bool ok, string memory addr) {
        if (puzzleHash.length != 32) return (false, "");
        return Bech32.encode(HRP, puzzleHash, Bech32.Variant.Bech32m);
    }

    /// @notice 32-byte puzzle hash -> "xch1..." address string. Always succeeds.
    function encode(bytes32 puzzleHash) internal pure returns (string memory addr) {
        (, addr) = Bech32.encode(HRP, abi.encodePacked(puzzleHash), Bech32.Variant.Bech32m);
    }

    /// @notice "xch1..." address string -> 32-byte puzzle hash.
    /// @return ok False if `addr` is not a bech32m "xch" address of 32 bytes.
    function decode(string memory addr) internal pure returns (bool ok, bytes memory puzzleHash) {
        (ok, puzzleHash) = Bech32.decode(HRP, addr, Bech32.Variant.Bech32m);
        if (!ok || puzzleHash.length != 32) return (false, "");
    }
}
