// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {BitcoinCoder} from "../src/BitcoinCoder.sol";
import {SolanaCoder} from "../src/SolanaCoder.sol";
import {Base58} from "../src/utils/Base58.sol";
import {Bech32} from "../src/utils/Bech32.sol";
import {BitcoinLike} from "../src/utils/BitcoinLike.sol";

/// @dev External wrappers so reverts surface as call failures.
contract Harness {
    function btcEncode(bytes memory b) external pure returns (string memory) {
        return BitcoinCoder.encode(b);
    }

    function btcDecode(string memory s) external pure returns (bytes memory) {
        return BitcoinCoder.decode(s);
    }

    function solEncode(bytes memory b) external pure returns (string memory) {
        return SolanaCoder.encode(b);
    }

    function solDecode(string memory s) external pure returns (bytes memory) {
        return SolanaCoder.decode(s);
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

    function test_btc_vectors() public view {
        string[] memory addrs = vm.parseJsonStringArray(json, ".btc.address");
        bytes[] memory scripts = vm.parseJsonBytesArray(json, ".btc.bytes");
        for (uint256 i; i < addrs.length; ++i) {
            assertEq(BitcoinCoder.decode(addrs[i]), scripts[i], addrs[i]);
            assertEq(BitcoinCoder.encode(scripts[i]), addrs[i], addrs[i]);
            if (_startsWith(addrs[i], "bc1")) {
                assertEq(BitcoinCoder.decode(vm.toUppercase(addrs[i])), scripts[i], "uppercase");
            }
        }
    }

    function test_sol_vectors() public view {
        string[] memory addrs = vm.parseJsonStringArray(json, ".sol.address");
        bytes[] memory keys = vm.parseJsonBytesArray(json, ".sol.bytes");
        for (uint256 i; i < addrs.length; ++i) {
            assertEq(SolanaCoder.decode(addrs[i]), keys[i], addrs[i]);
            assertEq(SolanaCoder.encode(keys[i]), addrs[i], addrs[i]);
            assertEq(SolanaCoder.encode(bytes32(keys[i])), addrs[i], addrs[i]);
        }
    }

    function test_btc_invalidAddresses() public {
        string[] memory addrs = vm.parseJsonStringArray(json, ".invalidBtc.address");
        string[] memory reasons = vm.parseJsonStringArray(json, ".invalidBtc.reason");
        for (uint256 i; i < addrs.length; ++i) {
            try h.btcDecode(addrs[i]) returns (bytes memory b) {
                emit log_named_bytes(reasons[i], b);
                fail();
            } catch {}
        }
    }

    function test_btc_invalidScripts() public {
        bytes[] memory scripts = vm.parseJsonBytesArray(json, ".invalidBtcScripts.bytes");
        string[] memory reasons = vm.parseJsonStringArray(json, ".invalidBtcScripts.reason");
        for (uint256 i; i < scripts.length; ++i) {
            try h.btcEncode(scripts[i]) returns (string memory s) {
                emit log_named_string(reasons[i], s);
                fail();
            } catch {}
        }
    }

    function test_sol_invalidAddresses() public {
        string[] memory addrs = vm.parseJsonStringArray(json, ".invalidSol.address");
        string[] memory reasons = vm.parseJsonStringArray(json, ".invalidSol.reason");
        for (uint256 i; i < addrs.length; ++i) {
            try h.solDecode(addrs[i]) returns (bytes memory b) {
                emit log_named_bytes(reasons[i], b);
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
        h.btcDecode("0A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        vm.expectRevert(Base58.InvalidBase58Checksum.selector);
        h.btcDecode("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb");
        vm.expectRevert(BitcoinLike.UnrecognisedAddressFormat.selector);
        h.btcEncode(hex"6a0401020304");
        vm.expectRevert(Bech32.InvalidWitnessProgram.selector);
        h.btcEncode(hex"0015000000000000000000000000000000000000000000");
        vm.expectRevert(SolanaCoder.UnrecognisedAddressFormat.selector);
        h.solEncode(new bytes(31));
    }

    // ---------------------------------------------------------------- round-trip fuzzing

    function testFuzz_base58_roundtrip(bytes memory data) public pure {
        assertEq(Base58.decode(Base58.encode(data)), data);
    }

    function testFuzz_base58check_roundtrip(bytes memory data) public pure {
        assertEq(Base58.decodeCheck(Base58.encodeCheck(data)), data);
    }

    function testFuzz_sol_roundtrip(bytes32 key) public pure {
        bytes memory b = abi.encodePacked(key);
        assertEq(SolanaCoder.decode(SolanaCoder.encode(key)), b);
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

    // ---------------------------------------------------------------- helpers

    function _resize(bytes memory b, uint256 n) internal pure returns (bytes memory out) {
        out = new bytes(n);
        for (uint256 i; i < n && i < b.length; ++i) {
            out[i] = b[i];
        }
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
