// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Base32} from "./utils/Base32.sol";

/// @title StellarCoder
/// @notice Stellar (coinType 148) account address <-> 32-byte ed25519 public key,
///         as used by ENS `addr(node, 148)`.
/// @dev StrKey: base32(0x30 ‖ key ‖ crc16-xmodem LE), i.e. "G..." (56 chars).
library StellarCoder {
    error UnrecognisedAddressFormat();

    uint256 internal constant COIN_TYPE = 148;

    uint8 internal constant VERSION = 0x30; // 6 << 3, account ID

    /// @notice 32-byte public key -> "G..." address string.
    function encode(bytes memory pubkey) internal pure returns (string memory) {
        if (pubkey.length != 32) revert UnrecognisedAddressFormat();
        bytes memory payload = abi.encodePacked(VERSION, pubkey);
        uint256 crc = _crc16(payload, 33);
        return Base32.encode(abi.encodePacked(payload, uint8(crc), uint8(crc >> 8)));
    }

    /// @notice 32-byte public key -> "G..." address string.
    function encode(bytes32 pubkey) internal pure returns (string memory) {
        return encode(abi.encodePacked(pubkey));
    }

    /// @notice "G..." address string -> 32-byte public key.
    function decode(string memory addr) internal pure returns (bytes memory pubkey) {
        if (bytes(addr).length != 56) revert UnrecognisedAddressFormat();
        bytes memory raw = Base32.decode(addr);
        if (uint8(raw[0]) != VERSION) revert UnrecognisedAddressFormat();
        uint256 crc = _crc16(raw, 33);
        if (uint8(raw[33]) != uint8(crc) || uint8(raw[34]) != uint8(crc >> 8)) revert UnrecognisedAddressFormat();
        pubkey = new bytes(32);
        for (uint256 i; i < 32; ++i) {
            pubkey[i] = raw[i + 1];
        }
    }

    /// @dev CRC-16/XMODEM (poly 0x1021, init 0) over `data[:n]`.
    function _crc16(bytes memory data, uint256 n) private pure returns (uint256 crc) {
        unchecked {
            for (uint256 i; i < n; ++i) {
                crc ^= uint256(uint8(data[i])) << 8;
                for (uint256 j; j < 8; ++j) {
                    crc = crc & 0x8000 != 0 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
                }
            }
        }
    }
}
