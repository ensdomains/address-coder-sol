// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Base58} from "./utils/Base58.sol";

/// @title SolanaCoder
/// @notice Solana (coinType 501) address <-> 32-byte public key, as used by ENS `addr(node, 501)`.
library SolanaCoder {
    error UnrecognisedAddressFormat();

    uint256 internal constant COIN_TYPE = 501;

    /// @notice 32-byte public key -> base58 address string.
    function encode(bytes memory pubkey) internal pure returns (string memory) {
        if (pubkey.length != 32) revert UnrecognisedAddressFormat();
        return Base58.encode(pubkey);
    }

    /// @notice 32-byte public key -> base58 address string.
    function encode(bytes32 pubkey) internal pure returns (string memory) {
        return Base58.encode(abi.encodePacked(pubkey));
    }

    /// @notice Base58 address string -> 32-byte public key.
    function decode(string memory addr) internal pure returns (bytes memory pubkey) {
        uint256 n = bytes(addr).length;
        if (n < 32 || n > 44) revert UnrecognisedAddressFormat();
        pubkey = Base58.decode(addr);
        if (pubkey.length != 32) revert UnrecognisedAddressFormat();
    }
}
