// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title CashAddr
/// @notice CashAddr encoding (Bitcoin Cash): `prefix ‖ ":" ‖ base32(version ‖ hash) ‖ 40-bit checksum`.
/// @dev All functions are `internal`, so only the ones you call end up in your bytecode.
///      `kind` is the address type from the version byte (0 = P2PKH, 1 = P2SH).
///
/// References:
/// - CashAddr: https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md
library CashAddr {
    error InvalidCashAddr();

    bytes32 private constant CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    /// @dev 6-bit reverse lookup for '0'-'9' then 'a'-'z'; 32 means "not in charset".
    uint256 private constant CHARSET_REV = 0x8418e31c2d00c00604db7d64a05c825935881d14779a51544a80f;

    /// @notice Encode `hash` (20, 24, 28, 32, 40, 48, 56 or 64 bytes) with address type `kind` (0-15).
    /// @param prefix Lowercase network prefix, e.g. "bitcoincash".
    function encode(bytes memory prefix, uint256 kind, bytes memory hash) internal pure returns (string memory) {
        if (kind > 15) revert InvalidCashAddr();
        bytes memory payload = abi.encodePacked(uint8((kind << 3) | _sizeCode(hash.length)), hash);
        unchecked {
            uint256 prefixLen = prefix.length;
            uint256 nWords = (payload.length * 8 + 4) / 5;
            bytes memory out = new bytes(prefixLen + 1 + nWords + 8);

            uint256 chk = _prefixChecksum(prefix);
            for (uint256 i; i < prefixLen; ++i) {
                out[i] = prefix[i];
            }
            uint256 pos = prefixLen;
            out[pos++] = ":";

            uint256 acc;
            uint256 bits;
            for (uint256 i; i < payload.length; ++i) {
                acc = ((acc << 8) | uint8(payload[i])) & 0xfff;
                bits += 8;
                while (bits >= 5) {
                    bits -= 5;
                    uint256 w = (acc >> bits) & 31;
                    out[pos++] = CHARSET[w];
                    chk = _polymodStep(chk, w);
                }
            }
            if (bits != 0) {
                uint256 w = (acc << (5 - bits)) & 31;
                out[pos++] = CHARSET[w];
                chk = _polymodStep(chk, w);
            }

            for (uint256 i; i < 8; ++i) {
                chk = _polymodStep(chk, 0);
            }
            chk ^= 1;
            for (uint256 i; i < 8; ++i) {
                out[pos++] = CHARSET[(chk >> (5 * (7 - i))) & 31];
            }
            return string(out);
        }
    }

    /// @notice Decode a CashAddr string. The `prefix:` part is optional; if present it must match.
    /// @dev Accepts all-lowercase or all-uppercase input.
    /// @param prefix Lowercase network prefix, e.g. "bitcoincash".
    function decode(bytes memory prefix, string memory s) internal pure returns (uint256 kind, bytes memory hash) {
        bytes memory b = bytes(s);
        uint256 n = b.length;
        uint256 prefixLen = prefix.length;
        bool lower;
        bool upper;
        uint256 start;
        unchecked {
            if (n > prefixLen && b[prefixLen] == ":") {
                for (uint256 i; i < prefixLen; ++i) {
                    uint256 c = uint8(b[i]);
                    if (c >= 0x41 && c <= 0x5a) {
                        upper = true;
                        c |= 0x20;
                    } else if (c >= 0x61 && c <= 0x7a) {
                        lower = true;
                    }
                    if (c != uint8(prefix[i])) revert InvalidCashAddr();
                }
                start = prefixLen + 1;
            }
            if (n < start + 8 + 2) revert InvalidCashAddr();

            uint256 end = n - 8; // first checksum word
            bytes memory data = new bytes(((end - start) * 5) >> 3);
            uint256 chk = _prefixChecksum(prefix);
            uint256 pos;
            uint256 acc;
            uint256 bits;
            for (uint256 i = start; i < n; ++i) {
                uint256 c = uint8(b[i]);
                if (c >= 0x41 && c <= 0x5a) {
                    upper = true;
                    c |= 0x20;
                } else if (c >= 0x61 && c <= 0x7a) {
                    lower = true;
                }
                uint256 w = _rev(c);
                chk = _polymodStep(chk, w);
                if (i < end) {
                    acc = ((acc << 5) | w) & 0xfff;
                    bits += 5;
                    if (bits >= 8) {
                        bits -= 8;
                        data[pos++] = bytes1(uint8(acc >> bits));
                    }
                }
            }
            if (lower && upper) revert InvalidCashAddr();
            if (chk != 1) revert InvalidCashAddr();
            if (bits > 4 || (acc & ((1 << bits) - 1)) != 0) revert InvalidCashAddr();

            uint256 version = uint8(data[0]);
            if (version & 0x80 != 0) revert InvalidCashAddr(); // reserved bit
            uint256 size = _size(version & 7);
            if (data.length != size + 1) revert InvalidCashAddr();
            kind = version >> 3;
            hash = new bytes(size);
            for (uint256 i; i < size; ++i) {
                hash[i] = data[i + 1];
            }
        }
    }

    function _size(uint256 code) private pure returns (uint256) {
        // 160, 192, 224, 256, 320, 384, 448, 512 bits
        return code < 4 ? 20 + code * 4 : 40 + (code - 4) * 8;
    }

    function _sizeCode(uint256 len) private pure returns (uint256) {
        for (uint256 code; code < 8; ++code) {
            if (_size(code) == len) return code;
        }
        revert InvalidCashAddr();
    }

    function _prefixChecksum(bytes memory prefix) private pure returns (uint256 chk) {
        chk = 1;
        for (uint256 i; i < prefix.length; ++i) {
            chk = _polymodStep(chk, uint8(prefix[i]) & 31);
        }
        chk = _polymodStep(chk, 0);
    }

    function _polymodStep(uint256 chk, uint256 v) private pure returns (uint256) {
        uint256 b = chk >> 35;
        chk = ((chk & 0x07ffffffff) << 5) ^ v;
        if (b & 1 != 0) chk ^= 0x98f2bc8e61;
        if (b & 2 != 0) chk ^= 0x79b76d99e2;
        if (b & 4 != 0) chk ^= 0xf33e5fb3c4;
        if (b & 8 != 0) chk ^= 0xae2eabe2a8;
        if (b & 16 != 0) chk ^= 0x1e4f43e470;
        return chk;
    }

    /// @dev Lowercase char -> 5-bit value; reverts if not in the charset.
    function _rev(uint256 c) private pure returns (uint256 w) {
        unchecked {
            uint256 idx;
            if (c >= 0x30 && c <= 0x39) idx = c - 0x30;
            else if (c >= 0x61 && c <= 0x7a) idx = c - 0x61 + 10;
            else revert InvalidCashAddr();
            w = (CHARSET_REV >> (idx * 6)) & 63;
            if (w > 31) revert InvalidCashAddr();
        }
    }
}
