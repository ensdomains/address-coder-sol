// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {EvmCoder} from "./EvmCoder.sol";
import {BitcoinCoder} from "./BitcoinCoder.sol";
import {SolanaCoder} from "./SolanaCoder.sol";
import {BitcoinCashCoder} from "./BitcoinCashCoder.sol";
import {LitecoinCoder} from "./LitecoinCoder.sol";
import {DogecoinCoder} from "./DogecoinCoder.sol";
import {CosmosCoder} from "./CosmosCoder.sol";
import {XrpCoder} from "./XrpCoder.sol";
import {StellarCoder} from "./StellarCoder.sol";
import {TronCoder} from "./TronCoder.sol";
import {PolkadotCoder} from "./PolkadotCoder.sol";
import {KusamaCoder} from "./KusamaCoder.sol";
import {CardanoCoder} from "./CardanoCoder.sol";
import {ChiaCoder} from "./ChiaCoder.sol";

/// @title AddressCoder
/// @notice Dispatches by ENS coinType to every coder in this package.
/// @dev Opt-in convenience: importing this compiles in every coder you call through it. If you only
///      need one chain, import that `<Chain>Coder` directly instead.
///      `view` because Polkadot/Kusama use the BLAKE2b precompile.
///
/// References:
/// - ENSIP-9 (multichain addresses): https://docs.ens.domains/ensip/9
/// - ENSIP-19 (EVM chain coin types): https://docs.ens.domains/ensip/19
/// - SLIP-44 (coin types): https://github.com/satoshilabs/slips/blob/master/slip-0044.md
/// - Reference: https://github.com/ensdomains/address-encoder/blob/main/src/index.ts
library AddressCoder {
    /// @notice Whether `coinType` has a coder.
    function isSupported(uint256 coinType) internal pure returns (bool) {
        return EvmCoder.isEvmCoinType(coinType) || coinType == BitcoinCoder.COIN_TYPE
            || coinType == SolanaCoder.COIN_TYPE || coinType == BitcoinCashCoder.COIN_TYPE
            || coinType == LitecoinCoder.COIN_TYPE || coinType == DogecoinCoder.COIN_TYPE
            || coinType == CosmosCoder.COIN_TYPE || coinType == XrpCoder.COIN_TYPE || coinType == StellarCoder.COIN_TYPE
            || coinType == TronCoder.COIN_TYPE || coinType == PolkadotCoder.COIN_TYPE
            || coinType == KusamaCoder.COIN_TYPE || coinType == CardanoCoder.COIN_TYPE
            || coinType == ChiaCoder.COIN_TYPE;
    }

    /// @notice Address bytes -> address string for `coinType`.
    /// @return ok False if `coinType` is unsupported or `data` is not valid for it. Never reverts.
    function encode(uint256 coinType, bytes memory data) internal view returns (bool ok, string memory addr) {
        if (EvmCoder.isEvmCoinType(coinType)) return EvmCoder.encode(data);
        if (coinType == BitcoinCoder.COIN_TYPE) return BitcoinCoder.encode(data);
        if (coinType == SolanaCoder.COIN_TYPE) return SolanaCoder.encode(data);
        if (coinType == BitcoinCashCoder.COIN_TYPE) return BitcoinCashCoder.encode(data);
        if (coinType == LitecoinCoder.COIN_TYPE) return LitecoinCoder.encode(data);
        if (coinType == DogecoinCoder.COIN_TYPE) return DogecoinCoder.encode(data);
        if (coinType == CosmosCoder.COIN_TYPE) return CosmosCoder.encode(data);
        if (coinType == XrpCoder.COIN_TYPE) return XrpCoder.encode(data);
        if (coinType == StellarCoder.COIN_TYPE) return StellarCoder.encode(data);
        if (coinType == TronCoder.COIN_TYPE) return TronCoder.encode(data);
        if (coinType == PolkadotCoder.COIN_TYPE) return PolkadotCoder.encode(data);
        if (coinType == KusamaCoder.COIN_TYPE) return KusamaCoder.encode(data);
        if (coinType == CardanoCoder.COIN_TYPE) return CardanoCoder.encode(data);
        if (coinType == ChiaCoder.COIN_TYPE) return ChiaCoder.encode(data);
        return (false, "");
    }

    /// @notice Address string -> address bytes for `coinType`.
    /// @return ok False if `coinType` is unsupported or `addr` is not valid for it. Never reverts.
    function decode(uint256 coinType, string memory addr) internal view returns (bool ok, bytes memory data) {
        if (EvmCoder.isEvmCoinType(coinType)) return EvmCoder.decode(addr);
        if (coinType == BitcoinCoder.COIN_TYPE) return BitcoinCoder.decode(addr);
        if (coinType == SolanaCoder.COIN_TYPE) return SolanaCoder.decode(addr);
        if (coinType == BitcoinCashCoder.COIN_TYPE) return BitcoinCashCoder.decode(addr);
        if (coinType == LitecoinCoder.COIN_TYPE) return LitecoinCoder.decode(addr);
        if (coinType == DogecoinCoder.COIN_TYPE) return DogecoinCoder.decode(addr);
        if (coinType == CosmosCoder.COIN_TYPE) return CosmosCoder.decode(addr);
        if (coinType == XrpCoder.COIN_TYPE) return XrpCoder.decode(addr);
        if (coinType == StellarCoder.COIN_TYPE) return StellarCoder.decode(addr);
        if (coinType == TronCoder.COIN_TYPE) return TronCoder.decode(addr);
        if (coinType == PolkadotCoder.COIN_TYPE) return PolkadotCoder.decode(addr);
        if (coinType == KusamaCoder.COIN_TYPE) return KusamaCoder.decode(addr);
        if (coinType == CardanoCoder.COIN_TYPE) return CardanoCoder.decode(addr);
        if (coinType == ChiaCoder.COIN_TYPE) return ChiaCoder.decode(addr);
        return (false, "");
    }
}
