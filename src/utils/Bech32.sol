// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Bech32
/// @notice Bech32 (BIP-173) and bech32m (BIP-350) encoding, plus SegWit address helpers.
/// @dev All functions are `internal`, so only the ones you call end up in your bytecode.
///
/// References:
/// - BIP-173 (bech32): https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
/// - BIP-350 (bech32m): https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
/// - BIP-141 (witness programs): https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
library Bech32 {
    enum Variant {
        Bech32,
        Bech32m
    }

    bytes32 private constant CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    /// @dev 6-bit reverse lookup for '0'-'9' then 'a'-'z'; 32 means "not in charset".
    uint256 private constant CHARSET_REV = 0x8418e31c2d00c00604db7d64a05c825935881d14779a51544a80f;

    uint256 private constant BECH32_CONST = 1;
    uint256 private constant BECH32M_CONST = 0x2bc830a3;
    uint256 private constant MAX_LENGTH = 90;
    uint256 private constant NO_VERSION = type(uint256).max;

    // ------------------------------------------------------------------ plain bech32 / bech32m

    /// @notice Encode `data` (8-bit bytes) as `hrp ‖ "1" ‖ words ‖ checksum`.
    /// @param hrp Lowercase human-readable part, e.g. "xch".
    /// @return ok False if the result would be longer than 90 characters (BIP-173).
    function encode(bytes memory hrp, bytes memory data, Variant variant)
        internal
        pure
        returns (bool ok, string memory s)
    {
        return _encode(hrp, NO_VERSION, data, _const(variant), MAX_LENGTH);
    }

    /// @notice Like `encode`, with a custom maximum length instead of 90 (e.g. 104 for Cardano).
    function encode(bytes memory hrp, bytes memory data, Variant variant, uint256 limit)
        internal
        pure
        returns (bool ok, string memory s)
    {
        return _encode(hrp, NO_VERSION, data, _const(variant), limit);
    }

    /// @notice Decode a bech32/bech32m string, requiring human-readable part `hrp` and checksum `variant`.
    /// @dev Accepts all-lowercase or all-uppercase input; at most 90 characters (BIP-173).
    /// @param hrp Lowercase human-readable part, e.g. "xch".
    /// @return ok False if `s` is not valid for `hrp` and `variant`.
    function decode(bytes memory hrp, string memory s, Variant variant)
        internal
        pure
        returns (bool ok, bytes memory data)
    {
        return decode(hrp, s, variant, MAX_LENGTH);
    }

    /// @notice Like `decode`, with a custom maximum length instead of 90 (e.g. 104 for Cardano).
    function decode(bytes memory hrp, string memory s, Variant variant, uint256 limit)
        internal
        pure
        returns (bool ok, bytes memory data)
    {
        uint256 chk;
        (ok,, data, chk) = _decode(hrp, s, false, limit);
        if (!ok || chk != _const(variant)) return (false, "");
    }

    // ------------------------------------------------------------------ SegWit (BIP-173 / BIP-350)

    /// @notice Encode a SegWit address: bech32 for v0, bech32m for v1-v16.
    /// @param hrp Lowercase human-readable part, e.g. "bc".
    /// @param version Witness version, 0-16.
    /// @param program Witness program, 2-40 bytes (20 or 32 for v0).
    /// @return ok False if `version` / `program` are not valid under BIP-141, or the result is over 90 characters.
    function encodeSegwit(bytes memory hrp, uint256 version, bytes memory program)
        internal
        pure
        returns (bool ok, string memory addr)
    {
        if (!isValidWitnessProgram(version, program.length)) return (false, "");
        return _encode(hrp, version, program, version == 0 ? BECH32_CONST : BECH32M_CONST, MAX_LENGTH);
    }

    /// @notice Decode a SegWit address, requiring human-readable part `hrp`.
    /// @dev Enforces the bech32/bech32m checksum variant matching the witness version,
    ///      and BIP-141 program lengths.
    /// @param hrp Lowercase human-readable part, e.g. "bc".
    /// @return ok False if `addr` is not a valid SegWit address for `hrp`.
    function decodeSegwit(bytes memory hrp, string memory addr)
        internal
        pure
        returns (bool ok, uint256 version, bytes memory program)
    {
        uint256 chk;
        (ok, version, program, chk) = _decode(hrp, addr, true, MAX_LENGTH);
        if (
            !ok || chk != (version == 0 ? BECH32_CONST : BECH32M_CONST)
                || !isValidWitnessProgram(version, program.length)
        ) {
            return (false, 0, "");
        }
    }

    /// @notice Whether witness `version` with a `len`-byte program is valid under BIP-141.
    function isValidWitnessProgram(uint256 version, uint256 len) internal pure returns (bool) {
        return version <= 16 && len >= 2 && len <= 40 && (version != 0 || len == 20 || len == 32);
    }

    // ------------------------------------------------------------------ internals

    /// @dev `version` is emitted as a leading 5-bit word unless it is NO_VERSION.
    function _encode(bytes memory hrp, uint256 version, bytes memory data, uint256 checksumConst, uint256 limit)
        private
        pure
        returns (bool, string memory)
    {
        unchecked {
            uint256 hrpLen = hrp.length;
            uint256 nWords = (version == NO_VERSION ? 0 : 1) + (data.length * 8 + 4) / 5;
            if (hrpLen + 1 + nWords + 6 > limit) return (false, "");
            bytes memory out = new bytes(hrpLen + 1 + nWords + 6);

            uint256 chk = _hrpChecksum(hrp);
            for (uint256 i; i < hrpLen; ++i) {
                out[i] = hrp[i];
            }
            uint256 pos = hrpLen;
            out[pos++] = "1";

            if (version != NO_VERSION) {
                out[pos++] = CHARSET[version];
                chk = _polymodStep(chk, version);
            }

            // Regroup 8-bit bytes into 5-bit words, padding the tail with zeros.
            uint256 acc;
            uint256 bits;
            for (uint256 i; i < data.length; ++i) {
                acc = ((acc << 8) | uint8(data[i])) & 0xfff;
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

            for (uint256 i; i < 6; ++i) {
                chk = _polymodStep(chk, 0);
            }
            chk ^= checksumConst;
            for (uint256 i; i < 6; ++i) {
                out[pos++] = CHARSET[(chk >> (5 * (5 - i))) & 31];
            }
            return (true, string(out));
        }
    }

    /// @dev Returns whether `s` is well formed, the leading version word (if `hasVersion`), the
    ///      8-bit payload, and the final polymod value to compare against BECH32_CONST / BECH32M_CONST.
    function _decode(bytes memory hrp, string memory s, bool hasVersion, uint256 limit)
        private
        pure
        returns (bool, uint256 version, bytes memory data, uint256 chk)
    {
        bytes memory b = bytes(s);
        uint256 n = b.length;
        uint256 hrpLen = hrp.length;
        unchecked {
            uint256 skip = hasVersion ? 1 : 0;
            // hrp ‖ "1" ‖ [version] ‖ data ‖ 6 checksum words
            if (n > limit || n < hrpLen + 7 + skip || b[hrpLen] != "1") return (false, 0, "", 0);

            bool lower;
            bool upper;
            for (uint256 i; i < hrpLen; ++i) {
                uint256 c = uint8(b[i]);
                if (c >= 0x41 && c <= 0x5a) {
                    upper = true;
                    c |= 0x20;
                } else if (c >= 0x61 && c <= 0x7a) {
                    lower = true;
                }
                if (c != uint8(hrp[i])) return (false, 0, "", 0);
            }

            chk = _hrpChecksum(hrp);
            uint256 start = hrpLen + 1; // first data word
            uint256 end = n - 6; // first checksum word
            data = new bytes(((end - start - skip) * 5) >> 3);
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
                if (w > 31) return (false, 0, "", 0);
                chk = _polymodStep(chk, w);

                if (hasVersion && i == start) {
                    version = w;
                } else if (i < end) {
                    acc = ((acc << 5) | w) & 0xfff;
                    bits += 5;
                    if (bits >= 8) {
                        bits -= 8;
                        data[pos++] = bytes1(uint8(acc >> bits));
                    }
                }
            }
            if (lower && upper) return (false, 0, "", 0);
            // BIP-173: at most 4 bits of zero padding.
            if (bits > 4 || (acc & ((1 << bits) - 1)) != 0) return (false, 0, "", 0);
        }
        return (true, version, data, chk);
    }

    function _const(Variant variant) private pure returns (uint256) {
        return variant == Variant.Bech32 ? BECH32_CONST : BECH32M_CONST;
    }

    function _hrpChecksum(bytes memory hrp) private pure returns (uint256 chk) {
        chk = 1;
        uint256 n = hrp.length;
        unchecked {
            for (uint256 i; i < n; ++i) {
                chk = _polymodStep(chk, uint8(hrp[i]) >> 5);
            }
            chk = _polymodStep(chk, 0);
            for (uint256 i; i < n; ++i) {
                chk = _polymodStep(chk, uint8(hrp[i]) & 31);
            }
        }
    }

    function _polymodStep(uint256 chk, uint256 v) private pure returns (uint256) {
        uint256 b = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v;
        if (b & 1 != 0) chk ^= 0x3b6a57b2;
        if (b & 2 != 0) chk ^= 0x26508e6d;
        if (b & 4 != 0) chk ^= 0x1ea119fa;
        if (b & 8 != 0) chk ^= 0x3d4233dd;
        if (b & 16 != 0) chk ^= 0x2a1462b3;
        return chk;
    }

    /// @dev Lowercase char -> 5-bit value, or 32 if not in the charset.
    function _rev(uint256 c) private pure returns (uint256) {
        unchecked {
            if (c >= 0x30 && c <= 0x39) return (CHARSET_REV >> ((c - 0x30) * 6)) & 63;
            if (c >= 0x61 && c <= 0x7a) return (CHARSET_REV >> ((c - 0x61 + 10) * 6)) & 63;
            return 32;
        }
    }
}
