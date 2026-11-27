// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title EvmCoder
/// @notice Ethereum (coinType 60) and EVM-chain (ENSIP-11, coinType 0x80000000 | chainId) address
///         <-> 20 bytes, as used by ENS `addr(node, coinType)`.
/// @dev `encode` emits EIP-55 mixed-case checksummed hex. `decode` accepts "0x" + 40 hex digits that
///      are all lowercase, all uppercase, or a valid EIP-55 checksum.
///
/// References:
/// - EIP-55 (mixed-case checksum): https://eips.ethereum.org/EIPS/eip-55
/// - ENSIP-9 (multichain addresses): https://docs.ens.domains/ensip/9
/// - ENSIP-11 (EVM chain coin types): https://docs.ens.domains/ensip/11
/// - Reference: https://github.com/ensdomains/address-encoder/blob/main/src/coin/eth.ts
library EvmCoder {
    error UnrecognisedAddressFormat();

    uint256 internal constant COIN_TYPE = 60;

    /// @dev ENSIP-11: EVM chains use coinType = EVM_BIT | chainId (chainId < 2^31).
    uint256 internal constant EVM_BIT = 0x80000000;

    bytes16 private constant HEX = "0123456789abcdef";

    /// @notice Whether `coinType` is Ethereum (60) or an ENSIP-11 EVM coin type.
    function isEvmCoinType(uint256 coinType) internal pure returns (bool) {
        return coinType == COIN_TYPE || (coinType >= EVM_BIT && coinType <= type(uint32).max);
    }

    /// @notice 20 bytes -> EIP-55 checksummed "0x..." string.
    /// @return ok False if `data` is not 20 bytes.
    function encode(bytes memory data) internal pure returns (bool ok, string memory addr) {
        if (data.length != 20) return (false, "");
        return (true, encode(address(bytes20(data))));
    }

    /// @notice Address -> EIP-55 checksummed "0x..." string. Always succeeds.
    function encode(address a) internal pure returns (string memory) {
        bytes memory out = new bytes(42);
        out[0] = "0";
        out[1] = "x";
        uint256 v = uint160(a);
        unchecked {
            for (uint256 i; i < 40; ++i) {
                out[2 + i] = HEX[(v >> (4 * (39 - i))) & 15];
            }
            bytes32 h;
            assembly ("memory-safe") {
                h := keccak256(add(out, 34), 40)
            }
            for (uint256 i; i < 40; ++i) {
                // Uppercase a-f where the matching hash nibble is >= 8.
                if (uint8(out[2 + i]) > 0x39 && (uint256(h) >> (4 * (63 - i))) & 15 >= 8) {
                    out[2 + i] = bytes1(uint8(out[2 + i]) - 0x20);
                }
            }
        }
        return string(out);
    }

    /// @notice "0x..." string -> 20 bytes. Reverts on invalid input or a bad mixed-case checksum.
    function decode(string memory s) internal pure returns (bytes memory) {
        bytes memory b = bytes(s);
        if (b.length != 42 || b[0] != "0" || b[1] != "x") revert UnrecognisedAddressFormat();
        uint256 v;
        bool lower;
        bool upper;
        unchecked {
            for (uint256 i = 2; i < 42; ++i) {
                uint256 c = uint8(b[i]);
                uint256 d;
                if (c >= 0x30 && c <= 0x39) {
                    d = c - 0x30;
                } else if (c >= 0x61 && c <= 0x66) {
                    d = c - 0x61 + 10;
                    lower = true;
                } else if (c >= 0x41 && c <= 0x46) {
                    d = c - 0x41 + 10;
                    upper = true;
                } else {
                    revert UnrecognisedAddressFormat();
                }
                v = (v << 4) | d;
            }
        }
        address a = address(uint160(v));
        if (lower && upper && keccak256(bytes(encode(a))) != keccak256(b)) revert UnrecognisedAddressFormat();
        return abi.encodePacked(a);
    }
}
