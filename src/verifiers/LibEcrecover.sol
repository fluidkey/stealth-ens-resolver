// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

/// @title LibEcrecover
/// @notice secp256k1 arithmetic on the `ecrecover` precompile, shared by the scheme verifiers.
/// @dev `ecrecover(h, v, r, s)` returns the address of r⁻¹·(s·R − h·G), where R is the point with
///      x-coordinate r and y parity v − 27. Choosing r = qx, s = b·qx and h = −a·qx makes that
///      a·G + b·Q: one call yields the address of any such combination, never its coordinates.
///      Same construction as Chainlink VRF's `_verifyLinearCombinationWithGenerator`, after
///      https://ethresear.ch/t/you-can-kinda-abuse-ecrecover-to-do-ecmul-in-secp256k1-today/2384;
///      `test/LibEcrecover.t.sol` checks it against Chainlink's code and against direct key
///      derivation.
library LibEcrecover {
    /// @dev The secp256k1 group order.
    uint256 internal constant N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    /// @notice The meta-address is not well formed for the scheme (ENSIP-30 Section 1).
    error MalformedMetaAddress();

    /// @notice The ephemeral private key in `verificationData` is not in [1, n).
    error InvalidVerificationData();

    /// @notice The supplied shared secret point is not the ephemeral key times the key exchanged
    ///         with.
    error InvalidSharedSecret();

    /// @dev address(a·G + b·Q) for the point Q with x-coordinate `qx` (0 < qx < n) and y parity
    ///      `parity`, or zero if there is no such point or the sum is the point at infinity.
    ///      Requires b·qx ≠ 0 mod n: `ecrecover` rejects s = 0.
    function mulAdd(uint256 a, uint256 b, uint256 qx, uint8 parity)
        internal
        pure
        returns (address)
    {
        return ecrecover(
            bytes32((N - mulmod(a, qx, N)) % N), 27 + parity, bytes32(qx), bytes32(mulmod(b, qx, N))
        );
    }

    /// @dev x-coordinate and y parity of a 33-byte compressed key; `ok` is false unless the
    ///      prefix is 0x02 or 0x03 and 0 < x < n (`ecrecover` cannot take x ≥ n, one key in about
    ///      2^128). Whether the point is on the curve shows as a zero address from `mulAdd`.
    function compressedKey(bytes calldata key)
        internal
        pure
        returns (bool ok, uint256 x, uint8 parity)
    {
        if (key.length != 33) return (false, 0, 0);
        uint8 prefix = uint8(key[0]);
        x = uint256(bytes32(key[1:33]));
        ok = (prefix == 2 || prefix == 3) && x != 0 && x < N;
        parity = prefix & 1;
    }

    /// @dev The witness check both verifiers share: `witness` starts with e || S.x || S.y (32 bytes
    ///      each, length checked by the caller), 0 < e < n, and address(S) = address(e·Q) for the
    ///      key Q (x-coordinate `qx`, y parity `parity`). Reverts `MalformedMetaAddress` if Q is
    ///      not on the curve. Hashing S needs its coordinates, which `ecrecover` cannot give, so
    ///      the gateway supplies them and this checks them by address.
    function checkSharedSecret(bytes calldata witness, uint256 qx, uint8 parity) internal pure {
        uint256 e = uint256(bytes32(witness[0:32]));
        if (e == 0 || e >= N) revert InvalidVerificationData();
        // e·Q. Zero only if Q is not on the curve.
        address shared = mulAdd(0, e, qx, parity);
        if (shared == address(0)) revert MalformedMetaAddress();
        if (shared != pointAddress(witness[32:96])) revert InvalidSharedSecret();
    }

    /// @dev The address of the uncompressed point `xy` (64 bytes, x || y).
    function pointAddress(bytes calldata xy) internal pure returns (address) {
        return address(uint160(uint256(keccak256(xy))));
    }
}
