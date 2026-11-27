// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Base58} from "./Base58.sol";
import {Bech32} from "./Bech32.sol";

/// @title BitcoinLike
/// @notice Shared address <-> scriptPubKey conversion for Bitcoin-style chains
///         (P2PKH / P2SH via Base58Check, SegWit via bech32/bech32m).
/// @dev Mirrors `createBitcoinEncoder` / `createBitcoinDecoder` from ensdomains/address-encoder.
///      Pass an empty `hrp` for chains without SegWit.
library BitcoinLike {
    error UnrecognisedAddressFormat();

    /// @notice Address string -> scriptPubKey bytes.
    function decode(string memory addr, bytes memory hrp, uint8 p2pkhVersion, uint8 p2shVersion)
        internal
        pure
        returns (bytes memory)
    {
        if (hrp.length != 0 && _hasSegwitPrefix(bytes(addr), hrp)) {
            (uint256 version, bytes memory program) = Bech32.decodeSegwit(hrp, addr);
            // OP_0 or OP_1..OP_16, then a direct push of the program.
            return abi.encodePacked(uint8(version == 0 ? 0 : version + 0x50), uint8(program.length), program);
        }

        bytes memory payload = Base58.decodeCheck(addr);
        if (payload.length != 21) revert UnrecognisedAddressFormat();
        uint8 v = uint8(payload[0]);
        bytes20 hash = _hash20(payload, 1);
        // OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
        if (v == p2pkhVersion) return abi.encodePacked(hex"76a914", hash, hex"88ac");
        // OP_HASH160 <20> OP_EQUAL
        if (v == p2shVersion) return abi.encodePacked(hex"a914", hash, hex"87");
        revert UnrecognisedAddressFormat();
    }

    /// @notice scriptPubKey bytes -> address string.
    function encode(bytes memory script, bytes memory hrp, uint8 p2pkhVersion, uint8 p2shVersion)
        internal
        pure
        returns (string memory)
    {
        uint256 n = script.length;
        if (n == 0) revert UnrecognisedAddressFormat();
        uint8 op = uint8(script[0]);

        if (op == 0x76) {
            if (n != 25 || script[1] != 0xa9 || script[2] != 0x14 || script[23] != 0x88 || script[24] != 0xac) {
                revert UnrecognisedAddressFormat();
            }
            return Base58.encodeCheck(abi.encodePacked(p2pkhVersion, _hash20(script, 3)));
        }

        if (op == 0xa9) {
            if (n != 23 || script[1] != 0x14 || script[22] != 0x87) revert UnrecognisedAddressFormat();
            return Base58.encodeCheck(abi.encodePacked(p2shVersion, _hash20(script, 2)));
        }

        if (hrp.length != 0 && (op == 0 || (op >= 0x51 && op <= 0x60)) && n >= 2 && uint8(script[1]) == n - 2) {
            bytes memory program = new bytes(n - 2);
            for (uint256 i; i < n - 2; ++i) {
                program[i] = script[i + 2];
            }
            return Bech32.encodeSegwit(hrp, op == 0 ? 0 : op - 0x50, program);
        }

        revert UnrecognisedAddressFormat();
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
