// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Base58} from "./Base58.sol";
import {Bech32} from "./Bech32.sol";

/// @title BitcoinLike
/// @notice Shared address <-> scriptPubKey conversion for Bitcoin-style chains
///         (P2PKH / P2SH via Base58Check, SegWit via bech32/bech32m).
/// @dev Mirrors `createBitcoinEncoder` / `createBitcoinDecoder` from ensdomains/address-encoder.
///      Chains without SegWit should call `encodeLegacy` / `decodeLegacy` directly, so the
///      bech32 code is never compiled in.
///
/// References:
/// - Standard scripts: https://en.bitcoin.it/wiki/Script#Standard_Transaction_to_Bitcoin_address_(pay-to-pubkey-hash)
/// - BIP-13 (P2SH addresses): https://github.com/bitcoin/bips/blob/master/bip-0013.mediawiki
/// - Reference: https://github.com/ensdomains/address-encoder/blob/main/src/utils/bitcoin.ts
library BitcoinLike {
    error UnrecognisedAddressFormat();

    /// @notice Address string -> scriptPubKey bytes (Base58Check or SegWit).
    function decode(string memory addr, bytes memory hrp, uint8 p2pkhVersion, uint8 p2shVersion)
        internal
        pure
        returns (bytes memory)
    {
        return decode(addr, hrp, p2pkhVersion, p2shVersion, p2shVersion);
    }

    /// @notice Like `decode`, but also accepts `p2shAltVersion` for P2SH (e.g. Litecoin's legacy "3..." addresses).
    function decode(string memory addr, bytes memory hrp, uint8 p2pkhVersion, uint8 p2shVersion, uint8 p2shAltVersion)
        internal
        pure
        returns (bytes memory)
    {
        if (_hasSegwitPrefix(bytes(addr), hrp)) {
            (uint256 version, bytes memory program) = Bech32.decodeSegwit(hrp, addr);
            // OP_0 or OP_1..OP_16, then a direct push of the program.
            return abi.encodePacked(uint8(version == 0 ? 0 : version + 0x50), uint8(program.length), program);
        }
        return decodeLegacy(addr, p2pkhVersion, p2shVersion, p2shAltVersion);
    }

    /// @notice scriptPubKey bytes -> address string (Base58Check or SegWit).
    /// @return ok False if `script` is not P2PKH, P2SH or a valid SegWit output.
    function encode(bytes memory script, bytes memory hrp, uint8 p2pkhVersion, uint8 p2shVersion)
        internal
        pure
        returns (bool ok, string memory addr)
    {
        uint256 n = script.length;
        uint8 op = n == 0 ? 0xff : uint8(script[0]);
        if ((op == 0 || (op >= 0x51 && op <= 0x60)) && n >= 2 && uint8(script[1]) == n - 2) {
            uint256 version = op == 0 ? 0 : op - 0x50;
            if (!Bech32.isValidWitnessProgram(version, n - 2)) return (false, "");
            bytes memory program = new bytes(n - 2);
            for (uint256 i; i < n - 2; ++i) {
                program[i] = script[i + 2];
            }
            return (true, Bech32.encodeSegwit(hrp, version, program));
        }
        return encodeLegacy(script, p2pkhVersion, p2shVersion);
    }

    /// @notice Base58Check P2PKH / P2SH address -> scriptPubKey bytes.
    function decodeLegacy(string memory addr, uint8 p2pkhVersion, uint8 p2shVersion)
        internal
        pure
        returns (bytes memory)
    {
        return decodeLegacy(addr, p2pkhVersion, p2shVersion, p2shVersion);
    }

    /// @notice Like `decodeLegacy`, but also accepts `p2shAltVersion` for P2SH.
    function decodeLegacy(string memory addr, uint8 p2pkhVersion, uint8 p2shVersion, uint8 p2shAltVersion)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory payload = Base58.decodeCheck(addr);
        if (payload.length != 21) revert UnrecognisedAddressFormat();
        uint8 v = uint8(payload[0]);
        bytes20 hash = _hash20(payload, 1);
        // OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
        if (v == p2pkhVersion) return abi.encodePacked(hex"76a914", hash, hex"88ac");
        // OP_HASH160 <20> OP_EQUAL
        if (v == p2shVersion || v == p2shAltVersion) return abi.encodePacked(hex"a914", hash, hex"87");
        revert UnrecognisedAddressFormat();
    }

    /// @notice P2PKH / P2SH scriptPubKey bytes -> Base58Check address.
    /// @return ok False if `script` is not P2PKH or P2SH.
    function encodeLegacy(bytes memory script, uint8 p2pkhVersion, uint8 p2shVersion)
        internal
        pure
        returns (bool ok, string memory addr)
    {
        uint256 n = script.length;
        if (
            n == 25 && script[0] == 0x76 && script[1] == 0xa9 && script[2] == 0x14 && script[23] == 0x88
                && script[24] == 0xac
        ) {
            return (true, Base58.encodeCheck(abi.encodePacked(p2pkhVersion, _hash20(script, 3))));
        }
        if (n == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87) {
            return (true, Base58.encodeCheck(abi.encodePacked(p2shVersion, _hash20(script, 2))));
        }
        return (false, "");
    }

    function _hash20(bytes memory b, uint256 offset) private pure returns (bytes20 h) {
        assembly ("memory-safe") {
            h := and(mload(add(add(b, 32), offset)), not(0xffffffffffffffffffffffff))
        }
    }

    /// @dev Case-insensitive check for `hrp ‖ "1"`.
    function _hasSegwitPrefix(bytes memory addr, bytes memory hrp) private pure returns (bool) {
        uint256 n = hrp.length;
        if (addr.length <= n || addr[n] != "1") return false;
        for (uint256 i; i < n; ++i) {
            uint8 c = uint8(addr[i]);
            if (c >= 0x41 && c <= 0x5a) c |= 0x20;
            if (c != uint8(hrp[i])) return false;
        }
        return true;
    }
}
