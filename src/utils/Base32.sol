// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Base32
/// @notice Unpadded RFC 4648 base32 ("A-Z2-7").
/// @dev All functions are `internal`, so only the ones you call end up in your bytecode.
library Base32 {
    error InvalidBase32();

    bytes32 private constant ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    /// @notice Encode `data` as unpadded base32.
    function encode(bytes memory data) internal pure returns (string memory) {
        unchecked {
            uint256 n = data.length;
            bytes memory out = new bytes((n * 8 + 4) / 5);
            uint256 pos;
            uint256 acc;
            uint256 bits;
            for (uint256 i; i < n; ++i) {
                acc = ((acc << 8) | uint8(data[i])) & 0xfff;
                bits += 8;
                while (bits >= 5) {
                    bits -= 5;
                    out[pos++] = ALPHABET[(acc >> bits) & 31];
                }
            }
            if (bits != 0) out[pos] = ALPHABET[(acc << (5 - bits)) & 31];
            return string(out);
        }
    }

    /// @notice Decode unpadded base32. Rejects lengths that RFC 4648 can't produce and non-zero padding bits.
    function decode(string memory s) internal pure returns (bytes memory out) {
        bytes memory b = bytes(s);
        unchecked {
            uint256 n = b.length;
            out = new bytes((n * 5) >> 3);
            uint256 pos;
            uint256 acc;
            uint256 bits;
            for (uint256 i; i < n; ++i) {
                uint256 c = uint8(b[i]);
                uint256 w;
                if (c >= 0x41 && c <= 0x5a) w = c - 0x41; // A-Z
                else if (c >= 0x32 && c <= 0x37) w = c - 0x32 + 26; // 2-7
                else revert InvalidBase32();
                acc = ((acc << 5) | w) & 0xfff;
                bits += 5;
                if (bits >= 8) {
                    bits -= 8;
                    out[pos++] = bytes1(uint8(acc >> bits));
                }
            }
            if (bits >= 5 || (acc & ((1 << bits) - 1)) != 0) revert InvalidBase32();
        }
    }
}
