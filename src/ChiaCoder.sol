// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Bech32} from "./utils/Bech32.sol";

/// @title ChiaCoder
/// @notice Chia (coinType 8444) address <-> 32-byte puzzle hash, as used by ENS `addr(node, 8444)`.
/// @dev Addresses are bech32m with human-readable part "xch".
library ChiaCoder {
    error UnrecognisedAddressFormat();

    uint256 internal constant COIN_TYPE = 8444;

    bytes internal constant HRP = "xch";

    /// @notice 32-byte puzzle hash -> "xch1..." address string.
    function encode(bytes memory puzzleHash) internal pure returns (string memory) {
        if (puzzleHash.length != 32) revert UnrecognisedAddressFormat();
        return Bech32.encode(HRP, puzzleHash, Bech32.Variant.Bech32m);
    }

    /// @notice 32-byte puzzle hash -> "xch1..." address string.
    function encode(bytes32 puzzleHash) internal pure returns (string memory) {
        return Bech32.encode(HRP, abi.encodePacked(puzzleHash), Bech32.Variant.Bech32m);
    }

    /// @notice "xch1..." address string -> 32-byte puzzle hash.
    function decode(string memory addr) internal pure returns (bytes memory puzzleHash) {
        puzzleHash = Bech32.decode(HRP, addr, Bech32.Variant.Bech32m);
        if (puzzleHash.length != 32) revert UnrecognisedAddressFormat();
    }
}
