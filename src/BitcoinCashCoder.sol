// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BitcoinLike} from "./utils/BitcoinLike.sol";
import {CashAddr} from "./utils/CashAddr.sol";

/// @title BitcoinCashCoder
/// @notice Bitcoin Cash (coinType 145) address <-> scriptPubKey bytes, as used by ENS `addr(node, 145)`.
/// @dev `decode` accepts CashAddr ("bitcoincash:q...", "bitcoincash:p...", prefix optional, either case)
///      and legacy Base58Check ("1...", "3..."). `encode` always emits CashAddr with the prefix.
///      Only 20-byte P2PKH / P2SH are supported (not P2SH32).
///
/// References:
/// - CashAddr: https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md
/// - P2SH32 (unsupported): https://gitlab.com/0353F40E/p2sh32
/// - Reference: https://github.com/ensdomains/address-encoder/blob/main/src/coin/bch.ts
library BitcoinCashCoder {
    error UnrecognisedAddressFormat();

    uint256 internal constant COIN_TYPE = 145;

    bytes internal constant PREFIX = "bitcoincash";
    uint8 internal constant P2PKH_VERSION = 0x00;
    uint8 internal constant P2SH_VERSION = 0x05;

    /// @notice scriptPubKey -> "bitcoincash:..." address string.
    /// @return ok False if `script` is not P2PKH or P2SH.
    function encode(bytes memory script) internal pure returns (bool ok, string memory addr) {
        uint256 n = script.length;
        if (
            n == 25 && script[0] == 0x76 && script[1] == 0xa9 && script[2] == 0x14 && script[23] == 0x88
                && script[24] == 0xac
        ) {
            return (true, CashAddr.encode(PREFIX, 0, _slice20(script, 3)));
        }
        if (n == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87) {
            return (true, CashAddr.encode(PREFIX, 1, _slice20(script, 2)));
        }
        return (false, "");
    }

    /// @notice Address string -> scriptPubKey. Reverts on invalid input.
    function decode(string memory addr) internal pure returns (bytes memory) {
        bytes memory b = bytes(addr);
        if (b.length != 0 && (b[0] == "1" || b[0] == "3")) {
            return BitcoinLike.decodeLegacy(addr, P2PKH_VERSION, P2SH_VERSION);
        }
        (uint256 kind, bytes memory hash) = CashAddr.decode(PREFIX, addr);
        if (hash.length != 20) revert UnrecognisedAddressFormat();
        // OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
        if (kind == 0) return abi.encodePacked(hex"76a914", hash, hex"88ac");
        // OP_HASH160 <20> OP_EQUAL
        if (kind == 1) return abi.encodePacked(hex"a914", hash, hex"87");
        revert UnrecognisedAddressFormat();
    }

    function _slice20(bytes memory b, uint256 offset) private pure returns (bytes memory out) {
        out = new bytes(20);
        for (uint256 i; i < 20; ++i) {
            out[i] = b[offset + i];
        }
    }
}
