// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {AddressCoder} from "../src/AddressCoder.sol";
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
import {EvmCoder} from "../src/EvmCoder.sol";
import {Base58} from "../src/utils/Base58.sol";
import {Bech32} from "../src/utils/Bech32.sol";

/// @dev External wrappers around AddressCoder, so reverts surface as call failures.
contract Harness {
    function encode(uint256 coinType, bytes memory b) external view returns (bool, string memory) {
        return AddressCoder.encode(coinType, b);
    }

    function decode(uint256 coinType, string memory s) external view returns (bytes memory) {
        return AddressCoder.decode(coinType, s);
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

    function test_eth_vectors() public {
        _checkCoin("eth");
    }

    function test_op_vectors() public {
        _checkCoin("op");
    }

    function _checkCoin(string memory coin) internal {
        string memory k = string.concat(".", coin);
        uint256 coinType = vm.parseJsonUint(json, string.concat(k, ".coinType"));

        string[] memory addrs = vm.parseJsonStringArray(json, string.concat(k, ".valid.address"));
        bytes[] memory data = vm.parseJsonBytesArray(json, string.concat(k, ".valid.bytes"));
        assertGt(addrs.length, 0);
        for (uint256 i; i < addrs.length; ++i) {
            assertEq(h.decode(coinType, addrs[i]), data[i], addrs[i]);
            (bool ok, string memory encoded) = h.encode(coinType, data[i]);
            assertTrue(ok, addrs[i]);
            assertEq(encoded, addrs[i], addrs[i]);
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
            // encode must report failure, not revert
            (bool ok, string memory s) = h.encode(coinType, data[i]);
            if (ok) {
                emit log_named_string(string.concat(coin, " encode accepted: ", reasons[i]), s);
                fail();
            }
            assertEq(s, "");
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
        vm.expectRevert(Bech32.InvalidBech32.selector);
        h.decode(8444, "txch1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq2u30kz");
        vm.expectRevert(EvmCoder.UnrecognisedAddressFormat.selector);
        h.decode(60, "0xd0c18fb5267528929cf8E127b49F2996c1ABC41d"); // bad checksum
        vm.expectRevert(abi.encodeWithSelector(AddressCoder.UnsupportedCoinType.selector, 1));
        h.decode(1, "x");
    }

    function test_encodeFailures() public view {
        bool ok;
        (ok,) = h.encode(0, hex"6a0401020304"); // OP_RETURN
        assertFalse(ok);
        (ok,) = h.encode(0, hex"0015000000000000000000000000000000000000000000"); // v0, 21-byte program
        assertFalse(ok);
        (ok,) = h.encode(3, hex"00140000000000000000000000000000000000000000"); // segwit on doge
        assertFalse(ok);
        (ok,) = h.encode(118, new bytes(49)); // too long for 90 chars
        assertFalse(ok);
        (ok,) = h.encode(1, new bytes(20)); // unsupported coin type
        assertFalse(ok);
        (ok,) = h.encode(0x80000000 - 1, new bytes(20)); // just below the EVM range
        assertFalse(ok);
        (ok,) = h.encode(uint256(type(uint32).max) + 1, new bytes(20)); // above the EVM range
        assertFalse(ok);
    }

    function test_isSupported() public pure {
        uint256[16] memory supported =
            [uint256(0), 2, 3, 60, 118, 144, 145, 148, 195, 354, 434, 501, 1815, 8444, 0x80000000, 0x8000000a];
        for (uint256 i; i < supported.length; ++i) {
            assertTrue(AddressCoder.isSupported(supported[i]));
        }
        assertFalse(AddressCoder.isSupported(1));
        assertFalse(AddressCoder.isSupported(61));
        assertFalse(AddressCoder.isSupported(uint256(type(uint32).max) + 1));
    }

    function test_eth_known() public pure {
        // EIP-55 test vector
        address a = 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed;
        assertEq(EvmCoder.encode(a), "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
        assertEq(EvmCoder.decode("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"), abi.encodePacked(a));
        assertEq(EvmCoder.decode("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"), abi.encodePacked(a));
    }

    // ---------------------------------------------------------------- encode never reverts

    /// @dev Arbitrary bytes, under every supported coin type, must give (false, "") or a valid address.
    function testFuzz_encodeNeverReverts(uint256 pick, bytes memory data) public view {
        uint256 coinType = _coinType(pick);
        (bool ok, string memory s) = h.encode(coinType, data); // reverting fails the test
        if (ok) assertEq(h.decode(coinType, s), data);
        else assertEq(s, "");
    }

    /// @dev Same, but shaped like real inputs (common lengths, valid-looking leading bytes).
    function testFuzz_encodeNeverReverts_shaped(uint256 pick, bytes memory data, uint8 lenPick, uint8 b0, uint8 b1)
        public
        view
    {
        uint8[12] memory lens = [0, 20, 21, 22, 23, 25, 29, 32, 33, 34, 57, 64];
        data = _resize(data, lens[lenPick % lens.length]);
        if (data.length > 0) data[0] = bytes1(b0);
        if (data.length > 1) data[1] = bytes1(b1);
        uint256 coinType = _coinType(pick);
        (bool ok, string memory s) = h.encode(coinType, data);
        if (ok) assertEq(h.decode(coinType, s), data);
        else assertEq(s, "");
    }

    function _coinType(uint256 pick) internal pure returns (uint256) {
        uint256[17] memory types =
            [uint256(0), 2, 3, 60, 118, 144, 145, 148, 195, 354, 434, 501, 1815, 8444, 0x80000000, 0x8000000a, 1];
        return pick < type(uint256).max / 2 ? types[pick % types.length] : pick; // sometimes a random coinType
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
        (bool ok, string memory a) = BitcoinCoder.encode(s);
        assertTrue(ok);
        assertEq(bytes(a)[0], "1");
        assertEq(BitcoinCoder.decode(a), s);
    }

    function testFuzz_btc_p2sh(bytes20 hash) public pure {
        bytes memory s = abi.encodePacked(hex"a914", hash, hex"87");
        (bool ok, string memory a) = BitcoinCoder.encode(s);
        assertTrue(ok);
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
        (bool ok, string memory a) = BitcoinCoder.encode(s);
        assertTrue(ok);
        assertTrue(_startsWith(a, "bc1"));
        assertEq(BitcoinCoder.decode(a), s);
    }

    function testFuzz_doge_p2pkh(bytes20 hash) public pure {
        bytes memory s = abi.encodePacked(hex"76a914", hash, hex"88ac");
        (bool ok, string memory a) = DogecoinCoder.encode(s);
        assertTrue(ok);
        assertEq(bytes(a)[0], "D");
        assertEq(DogecoinCoder.decode(a), s);
    }

    function testFuzz_doge_p2sh(bytes20 hash) public pure {
        bytes memory s = abi.encodePacked(hex"a914", hash, hex"87");
        (bool ok, string memory a) = DogecoinCoder.encode(s);
        assertTrue(ok);
        bytes1 c = bytes(a)[0];
        assertTrue(c == "9" || c == "A");
        assertEq(DogecoinCoder.decode(a), s);
    }

    function testFuzz_ltc_roundtrip(bytes20 hash, bool p2sh) public pure {
        bytes memory s =
            p2sh ? abi.encodePacked(hex"a914", hash, hex"87") : abi.encodePacked(hex"76a914", hash, hex"88ac");
        (bool ok, string memory a) = LitecoinCoder.encode(s);
        assertTrue(ok);
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
        (bool ok, string memory a) = BitcoinCashCoder.encode(s);
        assertTrue(ok);
        assertTrue(_startsWith(a, p2sh ? "bitcoincash:p" : "bitcoincash:q"));
        assertEq(BitcoinCashCoder.decode(a), s);
        assertEq(BitcoinCashCoder.decode(vm.toUppercase(a)), s);
        // legacy base58 decodes to the same script
        (, string memory legacy) = BitcoinCoder.encode(s);
        assertEq(BitcoinCashCoder.decode(legacy), s);
    }

    function testFuzz_xrp_roundtrip(bytes20 account) public pure {
        bytes memory d = abi.encodePacked(uint8(0), account);
        (bool ok, string memory a) = XrpCoder.encode(d);
        assertTrue(ok);
        assertEq(bytes(a)[0], "r");
        assertEq(XrpCoder.decode(a), d);
    }

    function testFuzz_trx_roundtrip(bytes20 account) public pure {
        bytes memory d = abi.encodePacked(uint8(0x41), account);
        (bool ok, string memory a) = TronCoder.encode(d);
        assertTrue(ok);
        assertEq(bytes(a)[0], "T");
        assertEq(TronCoder.decode(a), d);
    }

    function testFuzz_atom_roundtrip(bytes memory account) public pure {
        account = _resize(account, bound(account.length, 1, 32));
        (bool ok, string memory a) = CosmosCoder.encode(account);
        assertTrue(ok);
        assertEq(CosmosCoder.decode(a), account);
    }

    function testFuzz_xlm_roundtrip(bytes32 key) public pure {
        string memory a = StellarCoder.encode(key);
        assertEq(bytes(a)[0], "G");
        assertEq(StellarCoder.decode(a), abi.encodePacked(key));
    }

    function testFuzz_dot_roundtrip(bytes32 account) public view {
        bytes memory d = abi.encodePacked(account);
        (bool ok, string memory a) = PolkadotCoder.encode(d);
        assertTrue(ok);
        assertEq(PolkadotCoder.decode(a), d);
        (ok, a) = KusamaCoder.encode(d);
        assertTrue(ok);
        assertEq(KusamaCoder.decode(a), d);
    }

    function testFuzz_ada_shelley(bytes32 a, bytes32 b, uint8 kind) public pure {
        kind = uint8(bound(kind, 0, 7));
        if (kind == 4 || kind == 5) kind += 2; // pointer addresses are covered by vectors
        bytes memory d = kind <= 3
            ? abi.encodePacked(uint8((kind << 4) | 1), a, bytes24(b))
            : abi.encodePacked(uint8((kind << 4) | 1), bytes28(a));
        (bool ok, string memory s) = CardanoCoder.encode(d);
        assertTrue(ok);
        assertTrue(_startsWith(s, "addr1"));
        assertEq(CardanoCoder.decode(s), d);
    }

    function testFuzz_eth_roundtrip(address a, uint32 chainId) public pure {
        string memory s = EvmCoder.encode(a);
        assertEq(EvmCoder.decode(s), abi.encodePacked(a));
        assertEq(EvmCoder.decode(vm.toLowercase(s)), abi.encodePacked(a));
        assertTrue(EvmCoder.isEvmCoinType(EvmCoder.EVM_BIT | (chainId & 0x7fffffff)));
    }

    function testFuzz_ada_byron(bytes28 root) public pure {
        bytes memory d = abi.encodePacked(hex"83581c", root, hex"a000"); // Icarus-style
        (bool ok, string memory s) = CardanoCoder.encode(d);
        assertTrue(ok);
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
