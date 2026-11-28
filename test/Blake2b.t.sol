// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Blake2b} from "../src/utils/Blake2b.sol";
import {PolkadotCoder} from "../src/PolkadotCoder.sol";

contract Blake2bTest is Test {
    function _hex(bytes memory data) internal view returns (bytes memory) {
        (bool ok, bytes32 lo, bytes32 hi) = Blake2b.hash512(data);
        assertTrue(ok);
        return abi.encodePacked(lo, hi);
    }

    function test_vectors() public view {
        // RFC 7693 Appendix A
        assertEq(
            _hex("abc"),
            hex"ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );
        assertEq(
            _hex(""),
            hex"786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
        );
    }

    /// @dev Multi-block inputs; expected values from Python's hashlib.blake2b.
    function test_multiBlock() public view {
        assertEq(
            _hex(_seq(128)),
            hex"2319e3789c47e2daa5fe807f61bec2a1a6537fa03f19ff32e87eecbfd64b7e0e8ccff439ac333b040f19b0c4ddd11a61e24ac1fe0f10a039806c5dcc0da3d115"
        );
        assertEq(
            _hex(_seq(129)),
            hex"f59711d44a031d5f97a9413c065d1e614c417ede998590325f49bad2fd444d3e4418be19aec4e11449ac1a57207898bc57d76a1bcf3566292c20c683a5c4648f"
        );
        assertEq(
            _hex(_seq(256)),
            hex"1ecc896f34d3f9cac484c73f75f6a5fb58ee6784be41b35f46067b9c65c63a6794d3d744112c653f73dd7deb6666204c5a9bfa5b46081fc10fdbe7884fa5cbf8"
        );
        assertEq(
            _hex(_seq(300)),
            hex"d9cf5983dc6b34c0fa1f0226926855ad3eccd2bcdcd8f8053b9a80664d33b5afcc32fd21c70ea14f4ef50ca97c3203c4d1803159f0e01bb6cb1d1c83db52b63c"
        );
    }

    /// @dev A chain without the precompile: the call "succeeds" with no return data.
    function test_missingPrecompile() public {
        (, string memory addr) = PolkadotCoder.encode(new bytes(32));
        vm.mockCall(address(9), bytes(""), bytes(""));
        (bool ok,,) = Blake2b.hash512("abc");
        assertFalse(ok);
        (bool encoded, string memory s) = PolkadotCoder.encode(new bytes(32));
        assertFalse(encoded);
        assertEq(s, "");
        (bool decoded, bytes memory d) = PolkadotCoder.decode(addr);
        assertFalse(decoded);
        assertEq(d, "");
    }

    function _seq(uint256 n) internal pure returns (bytes memory b) {
        b = new bytes(n);
        for (uint256 i; i < n; ++i) {
            b[i] = bytes1(uint8(i));
        }
    }
}
