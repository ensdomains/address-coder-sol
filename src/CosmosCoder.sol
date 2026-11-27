// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Bech32} from "./utils/Bech32.sol";

/// @title CosmosCoder
/// @notice Cosmos Hub (coinType 118) address <-> account bytes, as used by ENS `addr(node, 118)`.
/// @dev Addresses are bech32 with human-readable part "cosmos". Accounts are usually 20 bytes
///      (32 for module / interchain accounts); any non-empty length that fits in 90 chars is accepted.
library CosmosCoder {
    error UnrecognisedAddressFormat();

    uint256 internal constant COIN_TYPE = 118;

    bytes internal constant HRP = "cosmos";

    /// @notice Account bytes -> "cosmos1..." address string.
    function encode(bytes memory data) internal pure returns (string memory) {
        if (data.length == 0) revert UnrecognisedAddressFormat();
        return Bech32.encode(HRP, data, Bech32.Variant.Bech32);
    }

    /// @notice "cosmos1..." address string -> account bytes.
    function decode(string memory addr) internal pure returns (bytes memory data) {
        data = Bech32.decode(HRP, addr, Bech32.Variant.Bech32);
        if (data.length == 0) revert UnrecognisedAddressFormat();
    }
}
