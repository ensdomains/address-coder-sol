// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SS58} from "./utils/SS58.sol";

/// @title KusamaCoder
/// @notice Kusama (coinType 434) SS58 address <-> 32-byte account ID, as used by ENS `addr(node, 434)`.
/// @dev SS58 network prefix 2 ("C..." addresses). Functions are `view`: the checksum uses
///      the EIP-152 BLAKE2b precompile (0x09).
library KusamaCoder {
    uint256 internal constant COIN_TYPE = 434;

    uint8 internal constant SS58_PREFIX = 2;

    /// @notice 32-byte account ID -> SS58 address string.
    function encode(bytes memory account) internal view returns (string memory) {
        return SS58.encode(SS58_PREFIX, account);
    }

    /// @notice SS58 address string -> 32-byte account ID.
    function decode(string memory addr) internal view returns (bytes memory) {
        return SS58.decode(SS58_PREFIX, addr);
    }
}
