// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Base58} from "./Base58.sol";
import {Blake2b} from "./Blake2b.sol";

/// @title SS58
/// @notice Substrate SS58 addresses for 32-byte account IDs:
///         base58(prefix ‖ account ‖ blake2b-512("SS58PRE" ‖ prefix ‖ account)[:2]).
/// @dev Only single-byte network prefixes (0-63) are supported. `view` because of the blake2b precompile.
library SS58 {
    error InvalidSS58();

    /// @notice 32-byte account ID -> SS58 address string for network `prefix`.
    function encode(uint8 prefix, bytes memory account) internal view returns (string memory) {
        if (prefix > 63 || account.length != 32) revert InvalidSS58();
        bytes memory body = abi.encodePacked(prefix, account);
        return Base58.encode(abi.encodePacked(body, _checksum(body)));
    }

    /// @notice SS58 address string -> 32-byte account ID, requiring network `prefix`.
    function decode(uint8 prefix, string memory addr) internal view returns (bytes memory account) {
        bytes memory raw = Base58.decode(addr);
        if (raw.length != 35 || uint8(raw[0]) != prefix) revert InvalidSS58();
        bytes2 checksum = bytes2(uint16(uint8(raw[33])) << 8 | uint8(raw[34]));
        assembly ("memory-safe") {
            mstore(raw, 33) // truncate to prefix ‖ account
        }
        if (_checksum(raw) != checksum) revert InvalidSS58();
        account = new bytes(32);
        for (uint256 i; i < 32; ++i) {
            account[i] = raw[i + 1];
        }
    }

    function _checksum(bytes memory body) private view returns (bytes2) {
        (bytes32 lo,) = Blake2b.hash512(abi.encodePacked("SS58PRE", body));
        return bytes2(lo);
    }
}
