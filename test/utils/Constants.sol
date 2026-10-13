// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

/// @dev ENSIP-30 Section 1 scheme-1 record: flag 0x01 (client-side derivation permitted),
///      33-byte compressed spending key, 33-byte compressed viewing key = 67 bytes.
///      Placeholder key material; MockVerifier checks only the length.
bytes constant TEST_META = abi.encodePacked(
    hex"01",
    hex"02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    hex"03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
);
