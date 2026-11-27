// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SS58} from "./utils/SS58.sol";

/// @title KusamaCoder
/// @notice Kusama (coinType 434) SS58 address <-> 32-byte account ID, as used by ENS `addr(node, 434)`.
/// @dev SS58 network prefix 2 ("C..." addresses). Functions are `view`: the checksum uses
///      the EIP-152 BLAKE2b precompile (0x09).
///
/// References:
/// - SS58 address format: https://docs.substrate.io/reference/address-formats/
/// - SS58 network registry: https://github.com/paritytech/ss58-registry/blob/main/ss58-registry.json
/// - EIP-152 (BLAKE2b F precompile): https://eips.ethereum.org/EIPS/eip-152
/// - Reference: https://github.com/ensdomains/address-encoder/blob/main/src/coin/ksm.ts
library KusamaCoder {
    uint256 internal constant COIN_TYPE = 434;

    uint8 internal constant SS58_PREFIX = 2;

    /// @notice 32-byte account ID -> SS58 address string.
    /// @return ok False if `account` is not 32 bytes or the BLAKE2b precompile is unavailable.
    function encode(bytes memory account) internal view returns (bool ok, string memory addr) {
        return SS58.encode(SS58_PREFIX, account);
    }

    /// @notice SS58 address string -> 32-byte account ID. Reverts on invalid input.
    function decode(string memory addr) internal view returns (bytes memory) {
        return SS58.decode(SS58_PREFIX, addr);
    }
}
