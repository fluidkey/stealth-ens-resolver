// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

import {IStealthVerifier} from "../interfaces/IStealthVerifier.sol";
import {ICloakedSigners} from "./CloakedSigners.sol";
import {LibEcrecover} from "./LibEcrecover.sol";

/// @title CloakedVerifier
/// @notice The Cloaked stealth EOA scheme for ENSIP-30 verifying resolvers.
/// @dev Derivation, as clkd-stealth 1.1.1 computes it (`genStealthAddress`, `genStealthPrivateKey`),
///      for spending key P_spend and ephemeral key e:
///        S     = e·P_spend                       (ECDH with the spending key)
///        h     = keccak256(S.x || S.y) mod n     (uncompressed point, no prefix)
///        stealth address = address(h·P_spend)    (an EOA; its key is p_spend·h mod n)
///      The same keys as FK1's Safe owner, without the Safe: Cloaked spends from the EOA itself,
///      delegated with EIP-7702 on first use. `genStealthAddress` rejects h ≥ n where
///      `genStealthPrivateKey` reduces it; the verifier reduces, which matches the key (and is never
///      reached in practice, about one key in 2^128).
///      No chain list: both modes carry a Cloaked signature bound to the coin type, so the chains
///      answered for are those Cloaked's gateway signs for, a policy that changes without a
///      redeploy. An EOA has the same address and key on every EVM chain.
///
///      Meta-address (33 bytes) = compressed P_spend. The viewing key is not part of the derivation:
///      Cloaked's server derives `e` from the recipient's child viewing node (m/5564'/0', then
///      m/chainId'/0'/p'/n', `deriveDeterministicEphemeralKey`) and finds payments by regenerating
///      those keys.
///      Verified mode: `verificationData` = e || S.x || S.y || signature (161 bytes). The
///      derivation is checked with two `ecrecover` calls as in `Scheme1Verifier`. Any `e` passes
///      that check, so the signature, an EIP-712 signature by a Cloaked gateway signer over the
///      resolver, node, coin type and derived address, ties the derivation to Cloaked's gateway:
///      a batch gateway answering from its own `e`, which Cloaked cannot regenerate, is refused.
///      It does not expire, since the record fixes the address for each `e`.
///      Unverified mode (no record): `verificationData` = abi.encode(uint64 expires, bytes
///      signature), an EIP-712 signature by a Cloaked gateway signer over the resolver, node,
///      coin type, returned address and expiry, at most `MAX_VALIDITY` ahead. This authenticates
///      the gateway (and defeats a batch gateway substituting the address); it is not
///      verification under ENSIP-30.
///      No owner. The signer set (`SIGNERS`) is Cloaked's: in verified mode a signer can refuse a
///      derivation but cannot make the verifier return an address the record does not derive.
contract CloakedVerifier is IStealthVerifier, EIP712 {
    ////////////////////////////////////////////////////////////////////////
    // Constants
    ////////////////////////////////////////////////////////////////////////

    /// @dev EIP-712 type of a signed verified response: the address derived from the record.
    bytes32 internal constant VERIFIED_STEALTH_RESOLUTION_TYPEHASH = keccak256(
        "VerifiedStealthResolution(address resolver,bytes32 node,uint256 coinType,address stealthAddress)"
    );

    /// @dev EIP-712 type of a signed unverified response.
    bytes32 internal constant STEALTH_RESOLUTION_TYPEHASH = keccak256(
        "StealthResolution(address resolver,bytes32 node,uint256 coinType,address stealthAddress,uint64 expires)"
    );

    /// @notice The longest a signed unverified response stays valid: its `expires` may be at most
    ///         this far after the block's timestamp, which bounds how long a kept response can be
    ///         served again.
    uint256 public constant MAX_VALIDITY = 10 minutes;

    ////////////////////////////////////////////////////////////////////////
    // Immutables
    ////////////////////////////////////////////////////////////////////////

    /// @notice Cloaked gateway signers.
    ICloakedSigners public immutable SIGNERS;

    /// @dev The ERC-5564 scheme ID, fixed at deployment.
    uint256 private immutable _SCHEME_ID;

    ////////////////////////////////////////////////////////////////////////
    // Errors
    ////////////////////////////////////////////////////////////////////////

    /// @notice Scheme ID 0 is not a scheme and 1 is ERC-5564 scheme 1.
    error InvalidSchemeId(uint256 schemeId);

    /// @notice The signer registry must be a contract.
    error InvalidSigners(address signers);

    /// @notice The meta-address is not a compressed secp256k1 key.
    error MalformedMetaAddress();

    /// @notice `verificationData` is not an ephemeral private key, a point and a signature
    ///         (161 bytes).
    error InvalidVerificationData();

    /// @notice The supplied shared secret point is not the ephemeral key times the spending key.
    error InvalidSharedSecret();

    /// @notice The signed response expired. No argument, like the two errors below: in a multicall
    ///         a failed item is returned as data, and a gateway-chosen word (its `expires`, or the
    ///         address of a key it holds) could read as an address to a client that skips the
    ///         error marker.
    error SignatureExpired();

    /// @notice The signed response's `expires` is more than `MAX_VALIDITY` ahead.
    error ExpiryTooFar();

    /// @notice The signature is malformed or its signer is not a Cloaked gateway signer.
    error UnknownSigner();

    ////////////////////////////////////////////////////////////////////////
    // Initialization
    ////////////////////////////////////////////////////////////////////////

    /// @param schemeId_ The ERC-5564 scheme ID of the Cloaked scheme.
    /// @param signers The Cloaked gateway signer registry.
    constructor(uint256 schemeId_, ICloakedSigners signers) EIP712("CloakedVerifier", "1") {
        if (schemeId_ <= 1) revert InvalidSchemeId(schemeId_);
        if (address(signers).code.length == 0) revert InvalidSigners(address(signers));
        _SCHEME_ID = schemeId_;
        SIGNERS = signers;
    }

    /// @inheritdoc IStealthVerifier
    function schemeId() external view returns (uint256) {
        return _SCHEME_ID;
    }

    ////////////////////////////////////////////////////////////////////////
    // Verification
    ////////////////////////////////////////////////////////////////////////

    /// @inheritdoc IStealthVerifier
    /// @dev Verified mode does not read `claimed`. Unverified mode returns it if signed.
    function verify(
        bytes32 node,
        uint256 coinType,
        bytes calldata metaAddress,
        bytes calldata verificationData,
        address claimed
    ) external view returns (address) {
        if (metaAddress.length == 0) {
            return _verifySigned(node, coinType, verificationData, claimed);
        }
        address stealth = _derive(metaAddress, verificationData);
        _checkSigner(
            keccak256(
                abi.encode(
                    VERIFIED_STEALTH_RESOLUTION_TYPEHASH, msg.sender, node, coinType, stealth
                )
            ),
            verificationData[96:161]
        );
        return stealth;
    }

    /// @dev Verified mode: the address derived from `metaAddress` and the e || S.x || S.y that
    ///      `verificationData` starts with, which must also hold a 65-byte signature.
    function _derive(bytes calldata metaAddress, bytes calldata verificationData)
        internal
        pure
        returns (address stealth)
    {
        (bool ok, uint256 spendX, uint8 spendParity) = LibEcrecover.compressedKey(metaAddress);
        if (!ok) revert MalformedMetaAddress();

        if (verificationData.length != 161) revert InvalidVerificationData();
        // S = e·P_spend.
        LibEcrecover.checkSharedSecret(verificationData, spendX, spendParity);

        // h·P_spend. Zero only if h ≡ 0 mod n (negligible).
        uint256 h = uint256(keccak256(verificationData[32:96])) % LibEcrecover.N;
        stealth = LibEcrecover.mulAdd(0, h, spendX, spendParity);
        if (stealth == address(0)) revert InvalidSharedSecret();
    }

    /// @dev Unverified mode: `claimed` if a current Cloaked gateway signer signed it for this
    ///      resolver (`msg.sender`), node and coin type, valid until and including `expires`, at most
    ///      `MAX_VALIDITY` ahead.
    function _verifySigned(
        bytes32 node,
        uint256 coinType,
        bytes calldata verificationData,
        address claimed
    ) internal view returns (address) {
        (uint64 expires, bytes memory signature) = abi.decode(verificationData, (uint64, bytes));
        if (block.timestamp > expires) revert SignatureExpired();
        if (expires > block.timestamp + MAX_VALIDITY) revert ExpiryTooFar();
        _checkSigner(
            keccak256(
                abi.encode(
                    STEALTH_RESOLUTION_TYPEHASH, msg.sender, node, coinType, claimed, expires
                )
            ),
            signature
        );
        return claimed;
    }

    /// @dev Reverts `UnknownSigner` unless a current Cloaked gateway signer signed the EIP-712
    ///      `structHash`. `tryRecover`, not `recover`: OpenZeppelin's errors carry arguments taken
    ///      from the signature (see `SignatureExpired`).
    function _checkSigner(bytes32 structHash, bytes memory signature) internal view {
        (address signer, ECDSA.RecoverError err,) =
            ECDSA.tryRecover(_hashTypedDataV4(structHash), signature);
        if (err != ECDSA.RecoverError.NoError || !SIGNERS.isSigner(signer)) {
            revert UnknownSigner();
        }
    }
}
