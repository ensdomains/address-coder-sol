// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Base58} from "./utils/Base58.sol";

/// @title SolanaCoder
/// @notice Solana (coinType 501) address <-> 32-byte public key, as used by ENS `addr(node, 501)`.
/// @dev Addresses are the base58 (Bitcoin alphabet) encoding of the 32-byte ed25519 public key.
///
/// References:
/// - Accounts and addresses: https://solana.com/docs/core/accounts
/// - Base58 alphabet: https://en.bitcoin.it/wiki/Base58Check_encoding#Base58_symbol_chart
/// - Reference: https://github.com/ensdomains/address-encoder/blob/main/src/coin/sol.ts
library SolanaCoder {
    uint256 internal constant COIN_TYPE = 501;

    /// @notice 32-byte public key -> base58 address string.
    /// @return ok False if `pubkey` is not 32 bytes.
    function encode(bytes memory pubkey) internal pure returns (bool ok, string memory addr) {
        if (pubkey.length != 32) return (false, "");
        return (true, Base58.encode(pubkey));
    }

    /// @notice 32-byte public key -> base58 address string. Always succeeds.
    function encode(bytes32 pubkey) internal pure returns (string memory) {
        return Base58.encode(abi.encodePacked(pubkey));
    }

    /// @notice Base58 address string -> 32-byte public key.
    /// @return ok False if `addr` is not base58 of 32 bytes.
    function decode(string memory addr) internal pure returns (bool ok, bytes memory pubkey) {
        uint256 n = bytes(addr).length;
        if (n < 32 || n > 44) return (false, "");
        (ok, pubkey) = Base58.decode(addr);
        if (!ok || pubkey.length != 32) return (false, "");
    }
}
