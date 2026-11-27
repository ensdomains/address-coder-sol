// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Base58} from "./utils/Base58.sol";

/// @title XrpCoder
/// @notice XRP Ledger (coinType 144) classic address <-> 21 bytes (0x00 ‖ 20-byte account ID),
///         as used by ENS `addr(node, 144)`.
/// @dev Addresses are Base58Check with the XRP alphabet ("r..."). X-addresses are not supported.
library XrpCoder {
    error UnrecognisedAddressFormat();

    uint256 internal constant COIN_TYPE = 144;

    uint8 internal constant VERSION = 0x00;

    bytes32 internal constant ALPHABET_LO = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXY";
    bytes32 internal constant ALPHABET_HI = "Z2bcdeCg65jkm8oFqi1tuvAxyz";
    uint256 internal constant ALPHABET_REV_LO = 0x81f79d70b6996175bf3544d247f40fbce3262b6ffffffffffc8b5ba29547872;
    uint256 internal constant ALPHABET_REV_HI = 0xe78dc9d74cc203006e12cfebab10e71a5923885fffffffff;

    /// @notice 0x00 ‖ 20-byte account ID -> "r..." address string.
    function encode(bytes memory data) internal pure returns (string memory) {
        if (data.length != 21 || uint8(data[0]) != VERSION) revert UnrecognisedAddressFormat();
        return Base58.encodeCheck(data, _alphabet());
    }

    /// @notice "r..." address string -> 0x00 ‖ 20-byte account ID.
    function decode(string memory addr) internal pure returns (bytes memory data) {
        data = Base58.decodeCheck(addr, _alphabet());
        if (data.length != 21 || uint8(data[0]) != VERSION) revert UnrecognisedAddressFormat();
    }

    function _alphabet() private pure returns (Base58.Alphabet memory) {
        return Base58.Alphabet(ALPHABET_LO, ALPHABET_HI, ALPHABET_REV_LO, ALPHABET_REV_HI);
    }
}
