// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Blake2b
/// @notice BLAKE2b-512 (unkeyed) using the EIP-152 BLAKE2b `F` compression precompile at 0x09.
/// @dev `view` because it calls a precompile. 0x09 exists on Ethereum and most EVM chains, but
///      some L2s / zkEVMs do not implement it.
///
/// References:
/// - RFC 7693 (BLAKE2): https://datatracker.ietf.org/doc/html/rfc7693
/// - EIP-152 (BLAKE2b F precompile): https://eips.ethereum.org/EIPS/eip-152
library Blake2b {
    error Blake2bFailed();

    /// @dev BLAKE2b-512 initial state (IV with h[0] ^= 0x01010040), as 8 little-endian uint64s.
    bytes32 private constant H_LO = 0x48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5;
    bytes32 private constant H_HI = 0xd182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b;

    /// @notice BLAKE2b-512 of `data`, returned as two 32-byte halves.
    /// @dev Reverts if the precompile is unavailable.
    function hash512(bytes memory data) internal view returns (bytes32 lo, bytes32 hi) {
        bool ok;
        (ok, lo, hi) = tryHash512(data);
        if (!ok) revert Blake2bFailed();
    }

    /// @notice Like `hash512`, but returns `ok = false` instead of reverting if the precompile is unavailable.
    function tryHash512(bytes memory data) internal view returns (bool ok, bytes32 lo, bytes32 hi) {
        ok = true;
        assembly ("memory-safe") {
            // F input (213 bytes): rounds[4] ‖ h[64] ‖ m[128] ‖ t[16] ‖ f[1]
            let ptr := mload(0x40)
            mstore(ptr, shl(224, 12))
            mstore(add(ptr, 4), H_LO)
            mstore(add(ptr, 36), H_HI)
            let m := add(ptr, 68)
            let len := mload(data)
            let src := add(data, 32)
            for { let off := 0 } 1 { off := add(off, 128) } {
                let remaining := sub(len, off)
                let last := iszero(gt(remaining, 128))
                let take := 128
                if last { take := remaining }

                // m = data[off:off+take], zero-padded to 128 bytes
                mstore(m, 0)
                mstore(add(m, 32), 0)
                mstore(add(m, 64), 0)
                mstore(add(m, 96), 0)
                for { let i := 0 } lt(i, take) { i := add(i, 32) } {
                    let w := mload(add(src, add(off, i)))
                    let r := sub(take, i)
                    if lt(r, 32) { w := and(w, not(shr(mul(8, r), not(0)))) }
                    mstore(add(m, i), w)
                }

                // t = bytes hashed so far (little-endian), f = final block flag
                let t := add(off, take)
                let tp := add(ptr, 196)
                mstore(tp, 0)
                for { let i := 0 } lt(i, 8) { i := add(i, 1) } {
                    mstore8(add(tp, i), and(shr(mul(8, i), t), 0xff))
                }
                mstore8(add(ptr, 212), last)

                // h = F(h, m, t, f), written back in place. A chain without the precompile
                // "succeeds" with no return data, so check the size too.
                let success := staticcall(gas(), 0x09, ptr, 213, add(ptr, 4), 64)
                if iszero(and(success, eq(returndatasize(), 64))) {
                    ok := 0
                    break
                }
                if last { break }
            }
            lo := mload(add(ptr, 4))
            hi := mload(add(ptr, 36))
        }
    }
}
