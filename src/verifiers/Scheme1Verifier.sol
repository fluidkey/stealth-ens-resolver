// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IStealthVerifier} from "../interfaces/IStealthVerifier.sol";

/// @title Scheme1Verifier
/// @notice ERC-5564 scheme 1 (secp256k1 with view tags) for ENSIP-30 verifying resolvers.
/// @dev Derivation, as the ScopeLift stealth-address SDK computes it, for meta-address
///      (P_spend, P_view) and ephemeral private key e:
///        S   = e·P_view                               (ECDH)
///        s_h = keccak256(compressed S) mod n          (33 bytes: 0x02/0x03 prefix, x)
///        stealth address = address(P_spend + s_h·G)
///      secp256k1 multiplication runs on `ecrecover`, which yields the address of a·G + b·Q, never
///      coordinates. Hashing S needs its coordinates, so the gateway supplies S and the verifier
///      checks address(S) against address(e·P_view); passing with a wrong S takes a 160-bit
///      second preimage of keccak256. Two `ecrecover` calls, no curve library.
///      `verificationData` = e || S.x || S.y, 32 bytes each.
///      No state and no owner: as immutable as the resolver (ENSIP-30 Section 5).
contract Scheme1Verifier is IStealthVerifier {
    /// @dev The secp256k1 group order.
    uint256 private constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    /// @notice The meta-address is not two compressed secp256k1 keys (ENSIP-30 Section 1).
    error MalformedMetaAddress();

    /// @notice `verificationData` is not an ephemeral private key followed by a point (96 bytes).
    error InvalidVerificationData();

    /// @notice The supplied shared secret point is not the ephemeral key times the viewing key.
    error InvalidSharedSecret();

    /// @inheritdoc IStealthVerifier
    function schemeId() external pure returns (uint256) {
        return 1;
    }

    /// @inheritdoc IStealthVerifier
    /// @dev Unverified mode (empty `metaAddress`): returns `claimed` and checks nothing, so the
    ///      gateway, and for batched lookups the batch gateway, is trusted. Verified mode: `claimed`
    ///      is not read. A key whose x-coordinate is at least n (one in about 2^128) is refused as
    ///      malformed: `ecrecover` cannot take it.
    function verify(
        bytes32,
        uint256,
        bytes calldata metaAddress,
        bytes calldata verificationData,
        address claimed
    ) external pure returns (address) {
        if (metaAddress.length == 0) return claimed;
        if (metaAddress.length != 66) revert MalformedMetaAddress();
        (uint256 spendX, uint8 spendParity) = _key(metaAddress[0:33]);
        (uint256 viewX, uint8 viewParity) = _key(metaAddress[33:66]);

        if (verificationData.length != 96) revert InvalidVerificationData();
        uint256 e = uint256(bytes32(verificationData[0:32]));
        if (e == 0 || e >= N) revert InvalidVerificationData();

        // S = e·P_view. Zero only if the viewing key is not on the curve.
        address shared = _mulAdd(0, e, viewX, viewParity);
        if (shared == address(0)) revert MalformedMetaAddress();
        if (shared != address(uint160(uint256(keccak256(verificationData[32:96]))))) {
            revert InvalidSharedSecret();
        }

        uint256 sy = uint256(bytes32(verificationData[64:96]));
        uint256 sh =
            uint256(keccak256(abi.encodePacked(uint8(2 + (sy & 1)), verificationData[32:64]))) % N;

        // P_spend + s_h·G. Zero if the spending key is not on the curve (or, with negligible
        // probability, the sum is the point at infinity).
        address stealth = _mulAdd(sh, 1, spendX, spendParity);
        if (stealth == address(0)) revert MalformedMetaAddress();
        return stealth;
    }

    /// @dev x-coordinate and y parity of a compressed key; reverts unless the prefix is 0x02 or
    ///      0x03 and 0 < x < n.
    function _key(bytes calldata key) private pure returns (uint256 x, uint8 parity) {
        uint8 prefix = uint8(key[0]);
        if (prefix != 2 && prefix != 3) revert MalformedMetaAddress();
        x = uint256(bytes32(key[1:33]));
        if (x == 0 || x >= N) revert MalformedMetaAddress();
        parity = prefix - 2;
    }

    /// @dev address(a·G + b·Q) for the point Q with x-coordinate `qx` (0 < qx < n) and y parity
    ///      `parity`, or zero if there is no such point or the sum is the point at infinity.
    ///      Requires b·qx ≠ 0 mod n. `ecrecover(h, v, r, s)` is address(r⁻¹·(s·R − h·G)) for R the
    ///      point with x = r and y parity v − 27: r = qx, s = b·qx, h = −a·qx give b·Q + a·G.
    function _mulAdd(uint256 a, uint256 b, uint256 qx, uint8 parity)
        private
        pure
        returns (address)
    {
        return ecrecover(
            bytes32((N - mulmod(a, qx, N)) % N), 27 + parity, bytes32(qx), bytes32(mulmod(b, qx, N))
        );
    }
}
