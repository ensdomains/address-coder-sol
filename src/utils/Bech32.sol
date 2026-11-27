// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Bech32
/// @notice SegWit address encoding: bech32 (BIP-173) for witness v0, bech32m (BIP-350) for v1-v16.
/// @dev All functions are `internal`, so only the ones you call end up in your bytecode.
library Bech32 {
    error InvalidBech32();
    error InvalidWitnessVersion();
    error InvalidWitnessProgram();

    bytes32 private constant CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    /// @dev 6-bit reverse lookup for '0'-'9' then 'a'-'z'; 32 means "not in charset".
    uint256 private constant CHARSET_REV = 0x8418e31c2d00c00604db7d64a05c825935881d14779a51544a80f;

    uint256 private constant BECH32_CONST = 1;
    uint256 private constant BECH32M_CONST = 0x2bc830a3;
    uint256 private constant MAX_LENGTH = 90;

    /// @notice Encode a SegWit address.
    /// @param hrp Lowercase human-readable part, e.g. "bc".
    /// @param version Witness version, 0-16.
    /// @param program Witness program, 2-40 bytes (20 or 32 for v0).
    function encodeSegwit(bytes memory hrp, uint256 version, bytes memory program)
        internal
        pure
        returns (string memory)
    {
        _checkProgram(version, program.length);
        unchecked {
            uint256 hrpLen = hrp.length;
            uint256 nWords = 1 + (program.length * 8 + 4) / 5;
            bytes memory out = new bytes(hrpLen + 1 + nWords + 6);

            uint256 chk = _hrpChecksum(hrp);
            for (uint256 i; i < hrpLen; ++i) {
                out[i] = hrp[i];
            }
            uint256 pos = hrpLen;
            out[pos++] = "1";

            out[pos++] = CHARSET[version];
            chk = _polymodStep(chk, version);

            // Regroup 8-bit bytes into 5-bit words, padding the tail with zeros.
            uint256 acc;
            uint256 bits;
            for (uint256 i; i < program.length; ++i) {
                acc = ((acc << 8) | uint8(program[i])) & 0xfff;
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
            chk ^= version == 0 ? BECH32_CONST : BECH32M_CONST;
            for (uint256 i; i < 6; ++i) {
                out[pos++] = CHARSET[(chk >> (5 * (5 - i))) & 31];
            }
            return string(out);
        }
    }

    /// @notice Decode a SegWit address, requiring human-readable part `hrp`.
    /// @dev Accepts all-lowercase or all-uppercase input. Enforces the bech32/bech32m
    ///      checksum variant matching the witness version, and BIP-141 program lengths.
    /// @param hrp Lowercase human-readable part, e.g. "bc".
    function decodeSegwit(bytes memory hrp, string memory addr)
        internal
        pure
        returns (uint256 version, bytes memory program)
    {
        bytes memory b = bytes(addr);
        uint256 n = b.length;
        uint256 hrpLen = hrp.length;
        unchecked {
            // hrp ‖ "1" ‖ version ‖ ≥1 data word ‖ 6 checksum words
            if (n > MAX_LENGTH || n < hrpLen + 9 || b[hrpLen] != "1") revert InvalidBech32();

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
                if (c != uint8(hrp[i])) revert InvalidBech32();
            }

            uint256 chk = _hrpChecksum(hrp);
            uint256 nData = n - hrpLen - 1 - 6;
            program = new bytes(((nData - 1) * 5) >> 3);
            uint256 pos;
            uint256 acc;
            uint256 bits;
            for (uint256 i = hrpLen + 1; i < n; ++i) {
                uint256 c = uint8(b[i]);
                if (c >= 0x41 && c <= 0x5a) {
                    upper = true;
                    c |= 0x20;
                } else if (c >= 0x61 && c <= 0x7a) {
                    lower = true;
                }
                uint256 w = _rev(c);
                chk = _polymodStep(chk, w);

                uint256 k = i - hrpLen - 1; // index into the data words
                if (k == 0) {
                    version = w;
                } else if (k <= nData - 1) {
                    acc = ((acc << 5) | w) & 0xfff;
                    bits += 5;
                    if (bits >= 8) {
                        bits -= 8;
                        program[pos++] = bytes1(uint8(acc >> bits));
                    }
                }
            }
            if (lower && upper) revert InvalidBech32();
            // BIP-173: at most 4 bits of zero padding.
            if (bits > 4 || (acc & ((1 << bits) - 1)) != 0) revert InvalidWitnessProgram();
            if (chk != (version == 0 ? BECH32_CONST : BECH32M_CONST)) revert InvalidBech32();
        }
        _checkProgram(version, program.length);
    }

    function _checkProgram(uint256 version, uint256 len) private pure {
        if (version > 16) revert InvalidWitnessVersion();
        if (len < 2 || len > 40 || (version == 0 && len != 20 && len != 32)) {
            revert InvalidWitnessProgram();
        }
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

    /// @dev Lowercase char -> 5-bit value; reverts if not in the charset.
    function _rev(uint256 c) private pure returns (uint256 w) {
        unchecked {
            uint256 idx;
            if (c >= 0x30 && c <= 0x39) idx = c - 0x30;
            else if (c >= 0x61 && c <= 0x7a) idx = c - 0x61 + 10;
            else revert InvalidBech32();
            w = (CHARSET_REV >> (idx * 6)) & 63;
            if (w > 31) revert InvalidBech32();
        }
    }
}
