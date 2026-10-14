// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

import {IStealthVerifier} from "../interfaces/IStealthVerifier.sol";
import {IFluidkeySigners} from "./FluidkeySigners.sol";
import {LibEcrecover} from "./LibEcrecover.sol";

/// @title FluidkeyVerifier
/// @notice The Fluidkey stealth Safe scheme (FK1) for ENSIP-30 verifying resolvers.
/// @dev Derivation, as fluidkey-stealth-account-kit 1.1.1 computes it (`generateStealthAddresses`,
///      `predictStealthSafeAddressWithBytecode`), for spending key P_spend and ephemeral key e:
///        S     = e·P_spend                       (ECDH with the spending key)
///        h     = keccak256(S.x || S.y) mod n     (uncompressed point, no prefix)
///        owner = address(h·P_spend)              (multiplicative stealth key)
///        stealth address = a counterfactual 1-of-1 Safe 1.3.0 owned by `owner`, at its CREATE2
///        address from the default Safe deployments (the same on every chain).
///      The Safe's setup `to` and `data` follow the Earn module's auto-earn setting: none when
///      `configHash` is 0, otherwise a MultiSend that enables the Earn module and installs
///      `configHash`. They affect control of the Safe, so they are fixed here and selected by the
///      `configHash` in the record (ENSIP-30 Section 5), never by the gateway. A new Earn module or
///      Safe version is a new scheme (FK2).
///
///      Meta-address (65 bytes) = compressed P_spend || configHash (uint256, 0 = auto-earn off).
///      Verified mode: `verificationData` = e || S.x || S.y (96 bytes), checked with two
///      `ecrecover` calls as in `Scheme1Verifier`.
///      Unverified mode (no record): `verificationData` = abi.encode(uint64 expires, bytes
///      signature), an EIP-712 signature by a Fluidkey gateway signer over the resolver, node,
///      coin type, returned address and expiry. This authenticates the gateway (and defeats a
///      batch gateway substituting the address); it is not verification under ENSIP-30.
///      No owner: the signer set lives in `SIGNERS`, which affects unverified mode only.
contract FluidkeyVerifier is IStealthVerifier, EIP712 {
    ////////////////////////////////////////////////////////////////////////
    // Scheme constants (Safe 1.3.0 default deployments, Fluidkey Earn module)
    ////////////////////////////////////////////////////////////////////////

    address internal constant SAFE_PROXY_FACTORY = 0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2;
    address internal constant SAFE_SINGLETON = 0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552;
    address internal constant SAFE_FALLBACK_HANDLER = 0xf48f2B2d2a534e402487b3ee7C18c33Aec0Fe5e4;
    address internal constant SAFE_MULTI_SEND = 0xA238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761;
    address internal constant SAFE_MODULE_SETUP = 0x2dd68b007B46fBe91B9A7c3EDa5A7a1063cB5b47;
    address internal constant EARN_MODULE = 0x3BDb857AFe9b51d8916D80240d2ADe40D4d3f2f9;

    /// @dev keccak256(GnosisSafeProxy creation code || uint256(SAFE_SINGLETON)); the creation code
    ///      is the factory's `proxyCreationCode()`.
    bytes32 internal constant SAFE_PROXY_INIT_CODE_HASH =
        0x56e3081a3d1bb38ed4eed1a39f7729c3cc77c7825794c15bbf326f3047fd779c;

    /// @dev EIP-712 type of a signed unverified response.
    bytes32 internal constant STEALTH_RESOLUTION_TYPEHASH = keccak256(
        "StealthResolution(address resolver,bytes32 node,uint256 coinType,address stealthAddress,uint64 expires)"
    );

    ////////////////////////////////////////////////////////////////////////
    // Immutables
    ////////////////////////////////////////////////////////////////////////

    /// @notice Fluidkey gateway signers, for unverified mode.
    IFluidkeySigners public immutable SIGNERS;

    /// @dev The ERC-5564 scheme ID, fixed at deployment (FK1 = 0x464B31 = 4606769).
    uint256 private immutable _SCHEME_ID;

    ////////////////////////////////////////////////////////////////////////
    // Errors
    ////////////////////////////////////////////////////////////////////////

    /// @notice Scheme ID 0 is not a scheme and 1 is ERC-5564 scheme 1.
    error InvalidSchemeId(uint256 schemeId);

    /// @notice The signer registry must be a contract.
    error InvalidSigners(address signers);

    /// @notice The meta-address is not a compressed secp256k1 key and a configHash.
    error MalformedMetaAddress();

    /// @notice `verificationData` is not an ephemeral private key followed by a point (96 bytes).
    error InvalidVerificationData();

    /// @notice The supplied shared secret point is not the ephemeral key times the spending key.
    error InvalidSharedSecret();

    /// @notice The signed response expired at `expires`.
    error SignatureExpired(uint64 expires);

    /// @notice `signer` is not a Fluidkey gateway signer.
    error UnknownSigner(address signer);

    ////////////////////////////////////////////////////////////////////////
    // Initialization
    ////////////////////////////////////////////////////////////////////////

    /// @param schemeId_ The ERC-5564 scheme ID of FK1.
    /// @param signers The Fluidkey gateway signer registry.
    constructor(uint256 schemeId_, IFluidkeySigners signers) EIP712("FluidkeyVerifier", "1") {
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
        if (metaAddress.length != 65) revert MalformedMetaAddress();
        (bool ok, uint256 spendX, uint8 spendParity) = LibEcrecover.compressedKey(metaAddress[0:33]);
        if (!ok) revert MalformedMetaAddress();
        uint256 configHash = uint256(bytes32(metaAddress[33:65]));

        if (verificationData.length != 96) revert InvalidVerificationData();
        uint256 e = uint256(bytes32(verificationData[0:32]));
        if (e == 0 || e >= LibEcrecover.N) revert InvalidVerificationData();

        // S = e·P_spend. Zero only if the spending key is not on the curve.
        address shared = LibEcrecover.mulAdd(0, e, spendX, spendParity);
        if (shared == address(0)) revert MalformedMetaAddress();
        if (shared != LibEcrecover.pointAddress(verificationData[32:96])) {
            revert InvalidSharedSecret();
        }

        // owner = h·P_spend. Zero only if h ≡ 0 mod n (negligible).
        uint256 h = uint256(keccak256(verificationData[32:96])) % LibEcrecover.N;
        address owner = LibEcrecover.mulAdd(0, h, spendX, spendParity);
        if (owner == address(0)) revert InvalidSharedSecret();
        return safeAddress(owner, configHash);
    }

    /// @notice The CREATE2 address of the 1-of-1 Safe owned by `owner` with the setup for
    ///         `configHash` (0 = auto-earn off).
    function safeAddress(address owner, uint256 configHash) public pure returns (address) {
        address[] memory owners = new address[](1);
        owners[0] = owner;
        (address to, bytes memory data) =
            configHash == 0 ? (address(0), bytes("")) : (SAFE_MULTI_SEND, setupData(configHash));
        bytes memory initializer = abi.encodeWithSelector(
            0xb63e800d, // setup(address[],uint256,address,bytes,address,address,uint256,address)
            owners,
            uint256(1),
            to,
            data,
            SAFE_FALLBACK_HANDLER,
            address(0),
            uint256(0),
            address(0)
        );
        bytes32 salt = keccak256(abi.encodePacked(keccak256(initializer), uint256(0)));
        return address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            bytes1(0xff), SAFE_PROXY_FACTORY, salt, SAFE_PROXY_INIT_CODE_HASH
                        )
                    )
                )
            )
        );
    }

    /// @notice The Safe setup `data` for auto-earn with `configHash`: MultiSend of a delegatecall to
    ///         SafeModuleSetup.enableModules([EARN_MODULE]) and a call to
    ///         EARN_MODULE.onInstall(abi.encode(configHash)).
    function setupData(uint256 configHash) public pure returns (bytes memory) {
        address[] memory modules = new address[](1);
        modules[0] = EARN_MODULE;
        bytes memory enable = abi.encodeWithSelector(0x8d0dc49f, modules); // enableModules(address[])
        bytes memory install = abi.encodeWithSelector(0x6d61fe70, abi.encode(configHash)); // onInstall(bytes)
        bytes memory transactions = abi.encodePacked(
            uint8(1), // delegatecall
            SAFE_MODULE_SETUP,
            uint256(0),
            enable.length,
            enable,
            uint8(0), // call
            EARN_MODULE,
            uint256(0),
            install.length,
            install
        );
        return abi.encodeWithSelector(0x8d80ff0a, transactions); // multiSend(bytes)
    }

    /// @dev Unverified mode: `claimed` if a current Fluidkey gateway signer signed it for this
    ///      resolver (`msg.sender`), node and coin type before `expires`.
    function _verifySigned(
        bytes32 node,
        uint256 coinType,
        bytes calldata verificationData,
        address claimed
    ) internal view returns (address) {
        (uint64 expires, bytes memory signature) = abi.decode(verificationData, (uint64, bytes));
        if (block.timestamp > expires) revert SignatureExpired(expires);
        bytes32 digest = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    STEALTH_RESOLUTION_TYPEHASH, msg.sender, node, coinType, claimed, expires
                )
            )
        );
        address signer = ECDSA.recover(digest, signature);
        if (!SIGNERS.isSigner(signer)) revert UnknownSigner(signer);
        return claimed;
    }
}
