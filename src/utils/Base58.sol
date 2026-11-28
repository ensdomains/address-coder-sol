// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Base58
/// @notice Base58 and Base58Check encoding, with the Bitcoin alphabet by default or a custom one.
/// @dev All functions are `internal`, so only the ones you call end up in your bytecode.
///      The big number is held in 128-bit limbs and processed 10 base58 digits
///      (58^10 < 2^59) at a time, which keeps gas low for address-sized inputs.
///
///      A custom alphabet is passed as `Alphabet`: the 58 characters split across two
///      `bytes32` (32 + 26), plus a reverse table of 6-bit digit values for ASCII 0x31-0x7a
///      ('1'-'z'; 42 entries in `revLo`, 32 in `revHi`), where 63 marks invalid characters.
///
/// References:
/// - Base58Check: https://en.bitcoin.it/wiki/Base58Check_encoding
/// - Base58 draft spec: https://datatracker.ietf.org/doc/html/draft-msporny-base58-03
library Base58 {
    struct Alphabet {
        bytes32 lo;
        bytes32 hi;
        uint256 revLo;
        uint256 revHi;
    }

    bytes32 internal constant BITCOIN_LO = "123456789ABCDEFGHJKLMNPQRSTUVWXY";
    bytes32 internal constant BITCOIN_HI = "Zabcdefghijkmnopqrstuvwxyz";
    uint256 internal constant BITCOIN_REV_LO = 0x81f79d71b6996175bf5544d247f40f38d30b289ffffffffffc81c61440c2040;
    uint256 internal constant BITCOIN_REV_HI = 0xe78df6d74cf2c70beeb6cfebaa9a279a59238a1fffffffff;

    uint256 private constant LIMB_MASK = type(uint128).max;
    uint256 private constant CHUNK_DIGITS = 10;
    uint256 private constant CHUNK_BASE = 430804206899405824; // 58 ** 10

    function bitcoin() internal pure returns (Alphabet memory) {
        return Alphabet(BITCOIN_LO, BITCOIN_HI, BITCOIN_REV_LO, BITCOIN_REV_HI);
    }

    // ------------------------------------------------------------------ Bitcoin alphabet

    /// @notice Encode `data` as base58 (Bitcoin alphabet).
    function encode(bytes memory data) internal pure returns (string memory) {
        return encode(data, bitcoin());
    }

    /// @notice Decode a base58 string (Bitcoin alphabet).
    /// @return ok False if `s` has a character outside the alphabet.
    function decode(string memory s) internal pure returns (bool ok, bytes memory data) {
        return decode(s, bitcoin());
    }

    /// @notice Encode `payload` as Base58Check (payload ‖ sha256d(payload)[:4]), Bitcoin alphabet.
    function encodeCheck(bytes memory payload) internal pure returns (string memory) {
        return encodeCheck(payload, bitcoin());
    }

    /// @notice Decode a Base58Check string (Bitcoin alphabet), verifying and stripping the checksum.
    /// @return ok False if `s` is not base58 or the checksum is wrong.
    function decodeCheck(string memory s) internal pure returns (bool ok, bytes memory payload) {
        return decodeCheck(s, bitcoin());
    }

    // ------------------------------------------------------------------ custom alphabet

    /// @notice Encode `payload` as Base58Check (payload ‖ sha256d(payload)[:4]).
    function encodeCheck(bytes memory payload, Alphabet memory a) internal pure returns (string memory) {
        return encode(abi.encodePacked(payload, bytes4(_sha256d(payload))), a);
    }

    /// @notice Decode a Base58Check string, verifying and stripping the 4-byte checksum.
    /// @return ok False if `s` is not base58 or the checksum is wrong.
    function decodeCheck(string memory s, Alphabet memory a) internal pure returns (bool ok, bytes memory payload) {
        (ok, payload) = decode(s, a);
        uint256 n = payload.length;
        if (!ok || n < 4) return (false, "");
        unchecked {
            n -= 4;
        }
        bytes4 checksum;
        assembly ("memory-safe") {
            checksum := and(mload(add(add(payload, 32), n)), shl(224, 0xffffffff))
            mstore(payload, n) // truncate in place
        }
        if (bytes4(_sha256d(payload)) != checksum) return (false, "");
    }

    /// @notice Encode `data` as base58.
    function encode(bytes memory data, Alphabet memory a) internal pure returns (string memory out) {
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
            bytes32 lo = a.lo;
            bytes32 hi = a.hi;

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
                    uint256 d = rem % 58;
                    buf[--pos] = d < 32 ? lo[d] : hi[d - 32];
                    rem /= 58;
                    if (used == 0 && rem == 0) break;
                }
            }
            bytes1 zero = lo[0];
            for (uint256 k; k < zeros; ++k) {
                buf[--pos] = zero;
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
    /// @return ok False if `s` has a character outside the alphabet.
    function decode(string memory s, Alphabet memory a) internal pure returns (bool ok, bytes memory out) {
        bytes memory b = bytes(s);
        unchecked {
            uint256 n = b.length;
            uint256 revLo = a.revLo;
            uint256 revHi = a.revHi;
            bytes1 zero = a.lo[0];
            uint256 zeros;
            while (zeros < n && b[zeros] == zero) ++zeros;

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
                    uint256 d = _digit(uint8(b[i]), revLo, revHi);
                    if (d >= 58) return (false, "");
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
        ok = true;
    }

    function _sha256d(bytes memory data) private pure returns (bytes32) {
        return sha256(abi.encodePacked(sha256(data)));
    }

    /// @dev Returns >= 58 for characters outside the alphabet.
    function _digit(uint256 c, uint256 revLo, uint256 revHi) private pure returns (uint256) {
        unchecked {
            if (c < 0x31 || c > 0x7a) return 63;
            uint256 i = c - 0x31;
            return i < 42 ? (revLo >> (i * 6)) & 63 : (revHi >> ((i - 42) * 6)) & 63;
        }
    }
}
