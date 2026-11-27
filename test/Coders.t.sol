// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {BitcoinCoder} from "../src/BitcoinCoder.sol";
import {LitecoinCoder} from "../src/LitecoinCoder.sol";
import {DogecoinCoder} from "../src/DogecoinCoder.sol";
import {BitcoinCashCoder} from "../src/BitcoinCashCoder.sol";
import {SolanaCoder} from "../src/SolanaCoder.sol";
import {ChiaCoder} from "../src/ChiaCoder.sol";
import {XrpCoder} from "../src/XrpCoder.sol";
import {CosmosCoder} from "../src/CosmosCoder.sol";
import {TronCoder} from "../src/TronCoder.sol";
import {StellarCoder} from "../src/StellarCoder.sol";
import {PolkadotCoder} from "../src/PolkadotCoder.sol";
import {KusamaCoder} from "../src/KusamaCoder.sol";
import {CardanoCoder} from "../src/CardanoCoder.sol";
import {Base58} from "../src/utils/Base58.sol";
import {Bech32} from "../src/utils/Bech32.sol";
import {BitcoinLike} from "../src/utils/BitcoinLike.sol";

/// @dev External wrappers, dispatched by coinType, so reverts surface as call failures.
contract Harness {
    error UnknownCoin();

    function encode(uint256 coinType, bytes memory b) external view returns (string memory) {
        if (coinType == BitcoinCoder.COIN_TYPE) return BitcoinCoder.encode(b);
        if (coinType == LitecoinCoder.COIN_TYPE) return LitecoinCoder.encode(b);
        if (coinType == DogecoinCoder.COIN_TYPE) return DogecoinCoder.encode(b);
        if (coinType == BitcoinCashCoder.COIN_TYPE) return BitcoinCashCoder.encode(b);
        if (coinType == SolanaCoder.COIN_TYPE) return SolanaCoder.encode(b);
        if (coinType == ChiaCoder.COIN_TYPE) return ChiaCoder.encode(b);
        if (coinType == XrpCoder.COIN_TYPE) return XrpCoder.encode(b);
        if (coinType == CosmosCoder.COIN_TYPE) return CosmosCoder.encode(b);
        if (coinType == TronCoder.COIN_TYPE) return TronCoder.encode(b);
        if (coinType == StellarCoder.COIN_TYPE) return StellarCoder.encode(b);
        if (coinType == PolkadotCoder.COIN_TYPE) return PolkadotCoder.encode(b);
        if (coinType == KusamaCoder.COIN_TYPE) return KusamaCoder.encode(b);
        if (coinType == CardanoCoder.COIN_TYPE) return CardanoCoder.encode(b);
        revert UnknownCoin();
    }

    function decode(uint256 coinType, string memory s) external view returns (bytes memory) {
        if (coinType == BitcoinCoder.COIN_TYPE) return BitcoinCoder.decode(s);
        if (coinType == LitecoinCoder.COIN_TYPE) return LitecoinCoder.decode(s);
        if (coinType == DogecoinCoder.COIN_TYPE) return DogecoinCoder.decode(s);
        if (coinType == BitcoinCashCoder.COIN_TYPE) return BitcoinCashCoder.decode(s);
        if (coinType == SolanaCoder.COIN_TYPE) return SolanaCoder.decode(s);
        if (coinType == ChiaCoder.COIN_TYPE) return ChiaCoder.decode(s);
        if (coinType == XrpCoder.COIN_TYPE) return XrpCoder.decode(s);
        if (coinType == CosmosCoder.COIN_TYPE) return CosmosCoder.decode(s);
        if (coinType == TronCoder.COIN_TYPE) return TronCoder.decode(s);
        if (coinType == StellarCoder.COIN_TYPE) return StellarCoder.decode(s);
        if (coinType == PolkadotCoder.COIN_TYPE) return PolkadotCoder.decode(s);
        if (coinType == KusamaCoder.COIN_TYPE) return KusamaCoder.decode(s);
        if (coinType == CardanoCoder.COIN_TYPE) return CardanoCoder.decode(s);
        revert UnknownCoin();
    }
}

contract CodersTest is Test {
    Harness h;
    string json;

    function setUp() public {
        h = new Harness();
        json = vm.readFile("test/vectors/vectors.json");
    }

    // ---------------------------------------------------------------- vectors from ensdomains/address-encoder

    function test_btc_vectors() public {
        _checkCoin("btc");
    }

    function test_ltc_vectors() public {
        _checkCoin("ltc");
    }

    function test_doge_vectors() public {
        _checkCoin("doge");
    }

    function test_bch_vectors() public {
        _checkCoin("bch");
    }

    function test_sol_vectors() public {
        _checkCoin("sol");
    }

    function test_xch_vectors() public {
        _checkCoin("xch");
    }

    function test_xrp_vectors() public {
        _checkCoin("xrp");
    }

    function test_atom_vectors() public {
        _checkCoin("atom");
    }

    function test_trx_vectors() public {
        _checkCoin("trx");
    }

    function test_xlm_vectors() public {
        _checkCoin("xlm");
    }

    function test_dot_vectors() public {
        _checkCoin("dot");
    }

    function test_ksm_vectors() public {
        _checkCoin("ksm");
    }

    function test_ada_vectors() public {
        _checkCoin("ada");
    }

    function _checkCoin(string memory coin) internal {
        string memory k = string.concat(".", coin);
        uint256 coinType = vm.parseJsonUint(json, string.concat(k, ".coinType"));

        string[] memory addrs = vm.parseJsonStringArray(json, string.concat(k, ".valid.address"));
        bytes[] memory data = vm.parseJsonBytesArray(json, string.concat(k, ".valid.bytes"));
        assertGt(addrs.length, 0);
        for (uint256 i; i < addrs.length; ++i) {
            assertEq(h.decode(coinType, addrs[i]), data[i], addrs[i]);
            assertEq(h.encode(coinType, data[i]), addrs[i], addrs[i]);
            if (_isBech32(addrs[i])) {
                assertEq(h.decode(coinType, vm.toUppercase(addrs[i])), data[i], "uppercase");
            }
        }

        addrs = vm.parseJsonStringArray(json, string.concat(k, ".decodeOnly.address"));
        data = vm.parseJsonBytesArray(json, string.concat(k, ".decodeOnly.bytes"));
        for (uint256 i; i < addrs.length; ++i) {
            assertEq(h.decode(coinType, addrs[i]), data[i], addrs[i]);
        }

        addrs = vm.parseJsonStringArray(json, string.concat(k, ".invalidAddress.address"));
        string[] memory reasons = vm.parseJsonStringArray(json, string.concat(k, ".invalidAddress.reason"));
        for (uint256 i; i < addrs.length; ++i) {
            try h.decode(coinType, addrs[i]) returns (bytes memory b) {
                emit log_named_bytes(string.concat(coin, " decode accepted: ", reasons[i]), b);
                fail();
            } catch {}
        }

        data = vm.parseJsonBytesArray(json, string.concat(k, ".invalidBytes.bytes"));
        reasons = vm.parseJsonStringArray(json, string.concat(k, ".invalidBytes.reason"));
        for (uint256 i; i < data.length; ++i) {
            try h.encode(coinType, data[i]) returns (string memory s) {
                emit log_named_string(string.concat(coin, " encode accepted: ", reasons[i]), s);
                fail();
            } catch {}
        }
    }

    // ---------------------------------------------------------------- well-known addresses

    function test_btc_genesis() public pure {
        assertEq(
            BitcoinCoder.decode("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
            hex"76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac"
        );
    }

    function test_sol_tokenProgram() public pure {
        assertEq(
            SolanaCoder.decode("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
            hex"06ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a9"
        );
        assertEq(SolanaCoder.decode("11111111111111111111111111111111"), new bytes(32));
    }

    // ---------------------------------------------------------------- specific errors

    function test_errors() public {
        vm.expectRevert(abi.encodeWithSelector(Base58.InvalidBase58Character.selector, 0));
        h.decode(0, "0A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        vm.expectRevert(Base58.InvalidBase58Checksum.selector);
        h.decode(0, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb");
        vm.expectRevert(BitcoinLike.UnrecognisedAddressFormat.selector);
        h.encode(0, hex"6a0401020304");
        vm.expectRevert(Bech32.InvalidWitnessProgram.selector);
        h.encode(0, hex"0015000000000000000000000000000000000000000000");
        vm.expectRevert(BitcoinLike.UnrecognisedAddressFormat.selector);
        h.encode(3, hex"00140000000000000000000000000000000000000000");
        vm.expectRevert(SolanaCoder.UnrecognisedAddressFormat.selector);
        h.encode(501, new bytes(31));
        vm.expectRevert(ChiaCoder.UnrecognisedAddressFormat.selector);
        h.encode(8444, new bytes(31));
        vm.expectRevert(Bech32.InvalidBech32.selector);
        h.decode(8444, "txch1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq2u30kz");
    }

    // ---------------------------------------------------------------- round-trip fuzzing

    function testFuzz_base58_roundtrip(bytes memory data) public pure {
        assertEq(Base58.decode(Base58.encode(data)), data);
    }

    function testFuzz_base58check_roundtrip(bytes memory data) public pure {
        assertEq(Base58.decodeCheck(Base58.encodeCheck(data)), data);
    }

    function testFuzz_bech32_roundtrip(bytes memory data, bool m) public pure {
        data = _resize(data, bound(data.length, 0, 50)); // 90-char limit with a 3-char hrp
        Bech32.Variant v = m ? Bech32.Variant.Bech32m : Bech32.Variant.Bech32;
        assertEq(Bech32.decode("xyz", Bech32.encode("xyz", data, v), v), data);
    }

    function testFuzz_sol_roundtrip(bytes32 key) public pure {
        assertEq(SolanaCoder.decode(SolanaCoder.encode(key)), abi.encodePacked(key));
    }

    function testFuzz_xch_roundtrip(bytes32 puzzleHash) public pure {
        string memory a = ChiaCoder.encode(puzzleHash);
        assertTrue(_startsWith(a, "xch1"));
        assertEq(ChiaCoder.decode(a), abi.encodePacked(puzzleHash));
    }

    function testFuzz_btc_p2pkh(bytes20 hash) public pure {
        bytes memory s = abi.encodePacked(hex"76a914", hash, hex"88ac");
        string memory a = BitcoinCoder.encode(s);
        assertEq(bytes(a)[0], "1");
        assertEq(BitcoinCoder.decode(a), s);
    }

    function testFuzz_btc_p2sh(bytes20 hash) public pure {
        bytes memory s = abi.encodePacked(hex"a914", hash, hex"87");
        string memory a = BitcoinCoder.encode(s);
        assertEq(bytes(a)[0], "3");
        assertEq(BitcoinCoder.decode(a), s);
    }

    function testFuzz_btc_segwit(uint8 version, bytes memory program) public pure {
        version = uint8(bound(version, 0, 16));
        if (version == 0) {
            program = _resize(program, program.length % 2 == 0 ? 20 : 32);
        } else {
            program = _resize(program, bound(program.length, 2, 40));
        }
        bytes memory s = abi.encodePacked(uint8(version == 0 ? 0 : version + 0x50), uint8(program.length), program);
        string memory a = BitcoinCoder.encode(s);
        assertTrue(_startsWith(a, "bc1"));
        assertEq(BitcoinCoder.decode(a), s);
    }

    function testFuzz_doge_p2pkh(bytes20 hash) public pure {
        bytes memory s = abi.encodePacked(hex"76a914", hash, hex"88ac");
        string memory a = DogecoinCoder.encode(s);
        assertEq(bytes(a)[0], "D");
        assertEq(DogecoinCoder.decode(a), s);
    }

    function testFuzz_doge_p2sh(bytes20 hash) public pure {
        bytes memory s = abi.encodePacked(hex"a914", hash, hex"87");
        string memory a = DogecoinCoder.encode(s);
        bytes1 c = bytes(a)[0];
        assertTrue(c == "9" || c == "A");
        assertEq(DogecoinCoder.decode(a), s);
    }

    function testFuzz_ltc_roundtrip(bytes20 hash, bool p2sh) public pure {
        bytes memory s =
            p2sh ? abi.encodePacked(hex"a914", hash, hex"87") : abi.encodePacked(hex"76a914", hash, hex"88ac");
        string memory a = LitecoinCoder.encode(s);
        assertEq(bytes(a)[0], p2sh ? bytes1("M") : bytes1("L"));
        assertEq(LitecoinCoder.decode(a), s);
    }

    function testFuzz_ltc_legacyP2sh(bytes20 hash) public pure {
        string memory legacy = Base58.encodeCheck(abi.encodePacked(uint8(0x05), hash));
        assertEq(LitecoinCoder.decode(legacy), abi.encodePacked(hex"a914", hash, hex"87"));
    }

    function testFuzz_bch_roundtrip(bytes20 hash, bool p2sh) public pure {
        bytes memory s =
            p2sh ? abi.encodePacked(hex"a914", hash, hex"87") : abi.encodePacked(hex"76a914", hash, hex"88ac");
        string memory a = BitcoinCashCoder.encode(s);
        assertTrue(_startsWith(a, p2sh ? "bitcoincash:p" : "bitcoincash:q"));
        assertEq(BitcoinCashCoder.decode(a), s);
        assertEq(BitcoinCashCoder.decode(vm.toUppercase(a)), s);
        // legacy base58 decodes to the same script
        assertEq(BitcoinCashCoder.decode(BitcoinCoder.encode(s)), s);
    }

    function testFuzz_xrp_roundtrip(bytes20 account) public pure {
        bytes memory d = abi.encodePacked(uint8(0), account);
        string memory a = XrpCoder.encode(d);
        assertEq(bytes(a)[0], "r");
        assertEq(XrpCoder.decode(a), d);
    }

    function testFuzz_trx_roundtrip(bytes20 account) public pure {
        bytes memory d = abi.encodePacked(uint8(0x41), account);
        string memory a = TronCoder.encode(d);
        assertEq(bytes(a)[0], "T");
        assertEq(TronCoder.decode(a), d);
    }

    function testFuzz_atom_roundtrip(bytes memory account) public pure {
        account = _resize(account, bound(account.length, 1, 32));
        assertEq(CosmosCoder.decode(CosmosCoder.encode(account)), account);
    }

    function testFuzz_xlm_roundtrip(bytes32 key) public pure {
        string memory a = StellarCoder.encode(key);
        assertEq(bytes(a)[0], "G");
        assertEq(StellarCoder.decode(a), abi.encodePacked(key));
    }

    function testFuzz_dot_roundtrip(bytes32 account) public view {
        bytes memory d = abi.encodePacked(account);
        assertEq(PolkadotCoder.decode(PolkadotCoder.encode(d)), d);
        assertEq(KusamaCoder.decode(KusamaCoder.encode(d)), d);
    }

    function testFuzz_ada_shelley(bytes32 a, bytes32 b, uint8 kind) public pure {
        kind = uint8(bound(kind, 0, 7));
        if (kind == 4 || kind == 5) kind += 2; // pointer addresses are covered by vectors
        bytes memory d = kind <= 3
            ? abi.encodePacked(uint8((kind << 4) | 1), a, bytes24(b))
            : abi.encodePacked(uint8((kind << 4) | 1), bytes28(a));
        string memory s = CardanoCoder.encode(d);
        assertTrue(_startsWith(s, "addr1"));
        assertEq(CardanoCoder.decode(s), d);
    }

    function testFuzz_ada_byron(bytes28 root) public pure {
        bytes memory d = abi.encodePacked(hex"83581c", root, hex"a000"); // Icarus-style
        string memory s = CardanoCoder.encode(d);
        assertTrue(_startsWith(s, "Ae2"));
        assertEq(CardanoCoder.decode(s), d);
    }

    // ---------------------------------------------------------------- helpers

    function _resize(bytes memory b, uint256 n) internal pure returns (bytes memory out) {
        out = new bytes(n);
        for (uint256 i; i < n && i < b.length; ++i) {
            out[i] = b[i];
        }
    }

    function _isBech32(string memory s) internal pure returns (bool) {
        return _startsWith(s, "bc1") || _startsWith(s, "ltc1") || _startsWith(s, "xch1") || _startsWith(s, "cosmos1")
            || _startsWith(s, "addr1") || _startsWith(s, "bitcoincash:");
    }

    function _startsWith(string memory s, string memory prefix) internal pure returns (bool) {
        bytes memory a = bytes(s);
        bytes memory p = bytes(prefix);
        if (a.length < p.length) return false;
        for (uint256 i; i < p.length; ++i) {
            if (a[i] != p[i]) return false;
        }
        return true;
    }
}
