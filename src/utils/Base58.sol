// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Base58
/// @notice Base58 (Bitcoin alphabet) and Base58Check encoding.
/// @dev All functions are `internal`, so only the ones you call end up in your bytecode.
///      The big number is held in 128-bit limbs and processed 10 base58 digits
///      (58^10 < 2^59) at a time, which keeps gas low for address-sized inputs.
library Base58 {
    error InvalidBase58Character(uint256 index);
    error InvalidBase58Checksum();

    bytes32 private constant ALPHABET_LO = "123456789ABCDEFGHJKLMNPQRSTUVWXY";
    bytes32 private constant ALPHABET_HI = "Zabcdefghijkmnopqrstuvwxyz";

    uint256 private constant LIMB_MASK = type(uint128).max;
    uint256 private constant CHUNK_DIGITS = 10;
    uint256 private constant CHUNK_BASE = 430804206899405824; // 58 ** 10

    /// @notice Encode `data` as base58.
    function encode(bytes memory data) internal pure returns (string memory out) {
        unchecked {
            uint256 n = data.length;
            uint256 zeros;
            while (zeros < n && data[zeros] == 0) ++zeros;

            // Load the significant bytes into little-endian 128-bit limbs.
            uint256 m = n - zeros;
            uint256 used = (m + 15) >> 4;
            uint256[] memory limbs = new uint256[](used);
            for (uint256 j; j < m; ++j) {
                uint256 p = m - 1 - j;
                limbs[p >> 4] |= uint256(uint8(data[zeros + j])) << ((p & 15) << 3);
            }

            // log(256)/log(58) < 1.3658, plus room for a final partial chunk.
            uint256 cap = zeros + (m * 1366) / 1000 + 1 + CHUNK_DIGITS;
            bytes memory buf = new bytes(cap);
            uint256 pos = cap;

            while (used != 0) {
                // Divide the number by 58^10, keeping the remainder.
                uint256 rem;
                for (uint256 i = used; i != 0;) {
                    --i;
                    uint256 cur = (rem << 128) | limbs[i];
                    limbs[i] = cur / CHUNK_BASE;
                    rem = cur % CHUNK_BASE;
                }
                while (used != 0 && limbs[used - 1] == 0) --used;
                // Emit 10 digits, or only the significant ones for the most significant chunk.
                for (uint256 k; k < CHUNK_DIGITS; ++k) {
                    buf[--pos] = _char(rem % 58);
                    rem /= 58;
                    if (used == 0 && rem == 0) break;
                }
            }
            for (uint256 k; k < zeros; ++k) {
                buf[--pos] = "1";
            }

            // Return the tail of `buf` in place: buf[pos:cap]. The new length word
            // overlaps only bytes of `buf` that were never written.
            assembly ("memory-safe") {
                out := add(buf, pos)
                mstore(out, sub(cap, pos))
            }
        }
    }

    /// @notice Decode a base58 string.
    function decode(string memory s) internal pure returns (bytes memory out) {
        bytes memory b = bytes(s);
        unchecked {
            uint256 n = b.length;
            uint256 zeros;
            while (zeros < n && b[zeros] == "1") ++zeros;

            // log(58)/log(256) < 0.7323
            uint256 maxBytes = ((n - zeros) * 733) / 1000 + 1;
            uint256[] memory limbs = new uint256[]((maxBytes + 15) >> 4);
            uint256 used;

            for (uint256 i = zeros; i < n;) {
                uint256 end = i + CHUNK_DIGITS;
                if (end > n) end = n;
                uint256 acc;
                uint256 mul = 1;
                for (; i < end; ++i) {
                    uint256 d = _digit(uint8(b[i]));
                    if (d >= 58) revert InvalidBase58Character(i);
                    acc = acc * 58 + d;
                    mul *= 58;
                }
                // limbs = limbs * mul + acc
                uint256 carry = acc;
                for (uint256 j; j < used; ++j) {
                    uint256 t = limbs[j] * mul + carry;
                    limbs[j] = t & LIMB_MASK;
                    carry = t >> 128;
                }
                while (carry != 0) {
                    limbs[used++] = carry & LIMB_MASK;
                    carry >>= 128;
                }
            }

            uint256 sig;
            if (used != 0) {
                uint256 top = limbs[used - 1];
                uint256 topBytes;
                while (top >> (topBytes << 3) != 0) ++topBytes;
                sig = ((used - 1) << 4) + topBytes;
            }
            out = new bytes(zeros + sig);
            for (uint256 q; q < sig; ++q) {
                uint256 p = sig - 1 - q;
                out[zeros + q] = bytes1(uint8(limbs[p >> 4] >> ((p & 15) << 3)));
            }
        }
    }

    /// @notice Encode `payload` as Base58Check (payload ‖ sha256d(payload)[:4]).
    function encodeCheck(bytes memory payload) internal pure returns (string memory) {
        return encode(abi.encodePacked(payload, bytes4(_sha256d(payload))));
    }

    /// @notice Decode a Base58Check string, verifying and stripping the 4-byte checksum.
    function decodeCheck(string memory s) internal pure returns (bytes memory payload) {
        payload = decode(s);
        uint256 n = payload.length;
        if (n < 4) revert InvalidBase58Checksum();
        unchecked {
            n -= 4;
        }
        bytes4 checksum;
        assembly ("memory-safe") {
            checksum := and(mload(add(add(payload, 32), n)), shl(224, 0xffffffff))
            mstore(payload, n) // truncate in place
        }
        if (bytes4(_sha256d(payload)) != checksum) revert InvalidBase58Checksum();
    }

    function _sha256d(bytes memory data) private pure returns (bytes32) {
        return sha256(abi.encodePacked(sha256(data)));
    }

    function _char(uint256 d) private pure returns (bytes1) {
        return d < 32 ? ALPHABET_LO[d] : ALPHABET_HI[d - 32];
    }

    /// @dev Returns 58 for characters outside the alphabet.
    function _digit(uint256 c) private pure returns (uint256) {
        unchecked {
            if (c >= 0x31 && c <= 0x39) return c - 0x31; // 1-9
            if (c >= 0x41 && c <= 0x48) return c - 0x41 + 9; // A-H
            if (c >= 0x4a && c <= 0x4e) return c - 0x4a + 17; // J-N
            if (c >= 0x50 && c <= 0x5a) return c - 0x50 + 22; // P-Z
            if (c >= 0x61 && c <= 0x6b) return c - 0x61 + 33; // a-k
            if (c >= 0x6d && c <= 0x7a) return c - 0x6d + 44; // m-z
            return 58;
        }
    }
}
