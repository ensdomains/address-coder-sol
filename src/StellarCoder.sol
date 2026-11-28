// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Base32} from "./utils/Base32.sol";

/// @title StellarCoder
/// @notice Stellar (coinType 148) account address <-> 32-byte ed25519 public key,
///         as used by ENS `addr(node, 148)`.
/// @dev StrKey: base32(0x30 ‖ key ‖ crc16-xmodem LE), i.e. "G..." (56 chars).
///
/// References:
/// - SEP-23 (StrKey): https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0023.md
/// - RFC 4648 (base32): https://datatracker.ietf.org/doc/html/rfc4648#section-6
/// - Reference: https://github.com/ensdomains/address-encoder/blob/main/src/coin/xlm.ts
library StellarCoder {
    uint256 internal constant COIN_TYPE = 148;

    uint8 internal constant VERSION = 0x30; // 6 << 3, account ID

    /// @notice 32-byte public key -> "G..." address string.
    /// @return ok False if `pubkey` is not 32 bytes.
    function encode(bytes memory pubkey) internal pure returns (bool ok, string memory addr) {
        if (pubkey.length != 32) return (false, "");
        return (true, _encode(pubkey));
    }

    /// @notice 32-byte public key -> "G..." address string. Always succeeds.
    function encode(bytes32 pubkey) internal pure returns (string memory) {
        return _encode(abi.encodePacked(pubkey));
    }

    /// @notice "G..." address string -> 32-byte public key.
    /// @return ok False if `addr` is not a valid account StrKey.
    function decode(string memory addr) internal pure returns (bool ok, bytes memory pubkey) {
        if (bytes(addr).length != 56) return (false, "");
        bytes memory raw;
        (ok, raw) = Base32.decode(addr);
        if (!ok || uint8(raw[0]) != VERSION) return (false, "");
        uint256 crc = _crc16(raw, 33);
        if (uint8(raw[33]) != uint8(crc) || uint8(raw[34]) != uint8(crc >> 8)) return (false, "");
        pubkey = new bytes(32);
        for (uint256 i; i < 32; ++i) {
            pubkey[i] = raw[i + 1];
        }
    }

    function _encode(bytes memory pubkey) private pure returns (string memory) {
        bytes memory payload = abi.encodePacked(VERSION, pubkey);
        uint256 crc = _crc16(payload, 33);
        return Base32.encode(abi.encodePacked(payload, uint8(crc), uint8(crc >> 8)));
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
