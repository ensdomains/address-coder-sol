// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SS58} from "./utils/SS58.sol";

/// @title PolkadotCoder
/// @notice Polkadot (coinType 354) SS58 address <-> 32-byte account ID, as used by ENS `addr(node, 354)`.
/// @dev SS58 network prefix 0 ("1..." addresses). Functions are `view`: the checksum uses
///      the EIP-152 BLAKE2b precompile (0x09).
library PolkadotCoder {
    uint256 internal constant COIN_TYPE = 354;

    uint8 internal constant SS58_PREFIX = 0;

    /// @notice 32-byte account ID -> SS58 address string.
    function encode(bytes memory account) internal view returns (string memory) {
        return SS58.encode(SS58_PREFIX, account);
    }

    /// @notice SS58 address string -> 32-byte account ID.
    function decode(string memory addr) internal view returns (bytes memory) {
        return SS58.decode(SS58_PREFIX, addr);
    }
}
