// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Base58} from "./utils/Base58.sol";
import {Bech32} from "./utils/Bech32.sol";

/// @title CardanoCoder
/// @notice Cardano (coinType 1815) address <-> raw address bytes, as used by ENS `addr(node, 1815)`.
/// @dev Shelley: bech32 "addr1..." (up to 104 chars) of the CIP-19 address bytes. Only mainnet
///      payment addresses: base (57 bytes), pointer (>= 32 bytes) and enterprise (29 bytes).
///      Byron: base58("Ae2..." / "Ddz...") of CBOR `[24(bytes), crc32(bytes)]`; the bytes are the
///      inner CBOR address (which starts with 0x83, header type 8 in CIP-19 terms).
///
/// References:
/// - CIP-19 (address format): https://cips.cardano.org/cip/CIP-0019
/// - Byron address CDDL: https://github.com/cardano-foundation/CIPs/blob/master/CIP-0019/CIP-0019-byron-addresses.cddl
/// - RFC 8949 (CBOR): https://datatracker.ietf.org/doc/html/rfc8949
/// - BIP-173 (bech32): https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
/// - Reference: https://github.com/ensdomains/address-encoder/blob/main/src/coin/ada.ts
library CardanoCoder {
    error UnrecognisedAddressFormat();

    uint256 internal constant COIN_TYPE = 1815;

    bytes internal constant HRP = "addr";
    uint256 internal constant BECH32_LIMIT = 104;

    /// @dev CRC-32 (IEEE, reflected) 4-bit lookup table: entries 0-7 and 8-15, 32 bits each.
    uint256 private constant CRC_LO = 0x5005713c4db261586b6b51f476dc419026d930ac3b6e20c81db7106400000000;
    uint256 private constant CRC_HI = 0xbdbdf21ca00ae27886d3d2d49b64c2b0cb61b38cd6d6a3e8f00f9344edb88320;

    /// @notice Address bytes -> "addr1..." (Shelley) or "Ae2..."/"Ddz..." (Byron) string.
    /// @return ok False if `data` is neither a mainnet CIP-19 payment address nor a Byron address.
    function encode(bytes memory data) internal pure returns (bool ok, string memory addr) {
        if (data.length != 0 && uint8(data[0]) == 0x83) {
            if (data.length >= 0x10000) return (false, "");
            return (true, _encodeByron(data));
        }
        if (!_isShelley(data) || Bech32.encodedLength(HRP.length, data.length) > BECH32_LIMIT) return (false, "");
        return (true, Bech32.encode(HRP, data, Bech32.Variant.Bech32, BECH32_LIMIT));
    }

    /// @notice "addr1..." (Shelley) or Byron base58 string -> address bytes. Reverts on invalid input.
    function decode(string memory addr) internal pure returns (bytes memory data) {
        if (_hasShelleyPrefix(bytes(addr))) {
            data = Bech32.decode(HRP, addr, Bech32.Variant.Bech32, BECH32_LIMIT);
            if (!_isShelley(data)) revert UnrecognisedAddressFormat();
        } else {
            data = _decodeByron(addr);
        }
    }

    // ------------------------------------------------------------------ Shelley

    /// @dev CIP-19 header: type (high nibble) and network (low nibble, 1 = mainnet).
    function _isShelley(bytes memory data) private pure returns (bool) {
        uint256 n = data.length;
        if (n == 0) return false;
        uint256 header = uint8(data[0]);
        uint256 kind = header >> 4;
        if (header & 0x0f != 1) return false;
        if (kind <= 3) return n == 57; // base: payment + stake credential
        if (kind <= 5) return n >= 32; // pointer: payment credential + 3 varints
        if (kind <= 7) return n == 29; // enterprise: payment credential
        return false;
    }

    function _hasShelleyPrefix(bytes memory b) private pure returns (bool) {
        if (b.length < 5 || b[4] != "1") return false;
        for (uint256 i; i < 4; ++i) {
            if ((uint8(b[i]) | 0x20) != uint8(HRP[i])) return false;
        }
        return true;
    }

    // ------------------------------------------------------------------ Byron

    function _encodeByron(bytes memory payload) private pure returns (string memory) {
        uint256 n = payload.length;
        bytes memory len;
        if (n < 24) len = abi.encodePacked(uint8(0x40 + n));
        else if (n < 0x100) len = abi.encodePacked(uint8(0x58), uint8(n));
        else len = abi.encodePacked(uint8(0x59), uint16(n)); // encode() checks n < 0x10000
        // [ 24(bytes), crc32 ]. Not hashed, so packed-encoding collisions don't matter.
        // forge-lint: disable-next-line(encode-packed-collision)
        return Base58.encode(abi.encodePacked(hex"82d818", len, payload, _cborUint(_crc32(payload))));
    }

    function _decodeByron(string memory addr) private pure returns (bytes memory payload) {
        bytes memory raw = Base58.decode(addr);
        uint256 n = raw.length;
        // 0x82 = array(2), 0xd818 = tag(24), then a byte string
        if (n < 5 || raw[0] != 0x82 || raw[1] != 0xd8 || raw[2] != 0x18) revert UnrecognisedAddressFormat();

        uint256 h = uint8(raw[3]);
        uint256 pos;
        uint256 len;
        if (h >= 0x40 && h < 0x58) {
            len = h - 0x40;
            pos = 4;
        } else if (h == 0x58) {
            len = uint8(raw[4]);
            pos = 5;
            if (len < 24) revert UnrecognisedAddressFormat();
        } else if (h == 0x59 && n > 5) {
            len = (uint256(uint8(raw[4])) << 8) | uint8(raw[5]);
            pos = 6;
            if (len < 0x100) revert UnrecognisedAddressFormat();
        } else {
            revert UnrecognisedAddressFormat();
        }
        if (pos + len >= n) revert UnrecognisedAddressFormat();

        payload = new bytes(len);
        for (uint256 i; i < len; ++i) {
            payload[i] = raw[pos + i];
        }
        if (len == 0 || uint8(payload[0]) != 0x83) revert UnrecognisedAddressFormat();

        // The checksum must be the canonical CBOR uint and the last item.
        bytes memory crc = _cborUint(_crc32(payload));
        pos += len;
        if (n - pos != crc.length) revert UnrecognisedAddressFormat();
        for (uint256 i; i < crc.length; ++i) {
            if (raw[pos + i] != crc[i]) revert UnrecognisedAddressFormat();
        }
    }

    /// @dev Canonical (shortest) CBOR encoding of an unsigned integer < 2^32.
    function _cborUint(uint256 v) private pure returns (bytes memory) {
        if (v < 24) return abi.encodePacked(uint8(v));
        if (v < 0x100) return abi.encodePacked(uint8(0x18), uint8(v));
        if (v < 0x10000) return abi.encodePacked(uint8(0x19), uint16(v));
        return abi.encodePacked(uint8(0x1a), uint32(v));
    }

    function _crc32(bytes memory data) private pure returns (uint256 crc) {
        crc = 0xffffffff;
        unchecked {
            for (uint256 i; i < data.length; ++i) {
                crc ^= uint8(data[i]);
                crc = (crc >> 4) ^ _crcNibble(crc & 15);
                crc = (crc >> 4) ^ _crcNibble(crc & 15);
            }
        }
        crc ^= 0xffffffff;
    }

    function _crcNibble(uint256 i) private pure returns (uint256) {
        unchecked {
            return i < 8 ? (CRC_LO >> (i * 32)) & 0xffffffff : (CRC_HI >> ((i - 8) * 32)) & 0xffffffff;
        }
    }
}
