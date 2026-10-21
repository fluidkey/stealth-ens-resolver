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
///        address from the default Safe deployments.
///      The Safe's setup `to` and `data` follow the Earn module's auto-earn setting: none when
///      `configHash` is 0, otherwise a MultiSend that enables the Earn module and installs
///      `configHash`. They affect control of the Safe, so they are fixed here and selected by the
///      `configHash` in the record (ENSIP-30 Section 5), never by the gateway. Any `configHash` is
///      accepted: the record's writer chooses it. A new Earn module or Safe version is a new scheme
///      (FK2).
///      Both modes answer only for the coin types `isSupportedChain` lists: seven chains, and the
///      ENSIP-19 default for authorities that list it.
///
///      Meta-address (65 bytes) = compressed P_spend || configHash (uint256, 0 = auto-earn off).
///      Verified mode: `verificationData` = e || S.x || S.y || signature (161 bytes). The
///      derivation is checked with two `ecrecover` calls as in `Scheme1Verifier`. Any `e` passes
///      that check, so the signature, an EIP-712 signature by a Fluidkey gateway signer over the
///      resolver, node, coin type and derived Safe, ties the derivation to Fluidkey's gateway,
///      whose ephemeral keys Fluidkey regenerates to find payments: a batch gateway answering from
///      its own `e` is refused. It does not expire, since the record fixes the Safe for each `e`.
///      Unverified mode (no record): `verificationData` = abi.encode(uint64 expires, bytes
///      signature), an EIP-712 signature by a Fluidkey gateway signer over the resolver, node,
///      coin type, returned address and expiry, at most `MAX_VALIDITY` ahead. This authenticates
///      the gateway (and defeats a batch gateway substituting the address); it is not
///      verification under ENSIP-30.
///      No owner. The signer set (`SIGNERS`) is Fluidkey's: in verified mode a signer can refuse
///      a derivation but cannot make the verifier return a Safe the record does not derive.
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

    /// @dev EIP-712 type of a signed verified response: the Safe derived from the record.
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

    /// @notice Fluidkey gateway signers.
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

    /// @notice FK1 Safes are not supported on the chain of `coinType`.
    error UnsupportedChain(uint256 coinType);

    /// @notice The meta-address is not a compressed secp256k1 key and a configHash.
    error MalformedMetaAddress();

    /// @notice `verificationData` is not an ephemeral private key, a point and a signature
    ///         (161 bytes).
    error InvalidVerificationData();

    /// @notice The supplied shared secret point is not the ephemeral key times the spending key.
    error InvalidSharedSecret();

    /// @notice The signed response expired at `expires`.
    error SignatureExpired(uint64 expires);

    /// @notice The signed response's `expires` is more than `MAX_VALIDITY` ahead.
    error ExpiryTooFar(uint64 expires);

    /// @notice `signer` is not a Fluidkey gateway signer; zero if the signature is malformed.
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
        if (!isSupportedChain(coinType)) revert UnsupportedChain(coinType);
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

    /// @notice Whether FK1 answers for `coinType` (ENSIP-11, ENSIP-19): Ethereum, Base, OP
    ///         Mainnet, Arbitrum One, Polygon PoS, Gnosis and BNB Smart Chain, and the ENSIP-19
    ///         default. All seven chains have the Safe contracts above; BNB Smart Chain does not
    ///         have the Earn module yet, whose address only Fluidkey can deploy. An answer for the
    ///         default names no chain, so it can be paid on a chain where the Safe is not the
    ///         recipient's (README, "Fluidkey stealth Safe (FK1)").
    function isSupportedChain(uint256 coinType) public pure returns (bool) {
        return coinType == 60 // Ethereum
            || coinType == 0x80002105 // Base (8453)
            || coinType == 0x8000000a // OP Mainnet (10)
            || coinType == 0x8000a4b1 // Arbitrum One (42161)
            || coinType == 0x80000089 // Polygon PoS (137)
            || coinType == 0x80000064 // Gnosis (100)
            || coinType == 0x80000038 // BNB Smart Chain (56)
            || coinType == 0x80000000; // ENSIP-19 default: any EVM chain
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

    /// @dev Verified mode: the Safe derived from `metaAddress` and the e || S.x || S.y that
    ///      `verificationData` starts with, which must also hold a 65-byte signature.
    function _derive(bytes calldata metaAddress, bytes calldata verificationData)
        internal
        pure
        returns (address)
    {
        if (metaAddress.length != 65) revert MalformedMetaAddress();
        (bool ok, uint256 spendX, uint8 spendParity) = LibEcrecover.compressedKey(metaAddress[0:33]);
        if (!ok) revert MalformedMetaAddress();
        uint256 configHash = uint256(bytes32(metaAddress[33:65]));

        if (verificationData.length != 161) revert InvalidVerificationData();
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

    /// @dev Unverified mode: `claimed` if a current Fluidkey gateway signer signed it for this
    ///      resolver (`msg.sender`), node and coin type, valid until `expires`, which is at most
    ///      `MAX_VALIDITY` ahead.
    function _verifySigned(
        bytes32 node,
        uint256 coinType,
        bytes calldata verificationData,
        address claimed
    ) internal view returns (address) {
        (uint64 expires, bytes memory signature) = abi.decode(verificationData, (uint64, bytes));
        if (block.timestamp > expires) revert SignatureExpired(expires);
        if (expires > block.timestamp + MAX_VALIDITY) revert ExpiryTooFar(expires);
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

    /// @dev Reverts unless a current Fluidkey gateway signer signed the EIP-712 `structHash`. A
    ///      malformed signature reverts `UnknownSigner(address(0))`, not OpenZeppelin's errors,
    ///      whose arguments come from the signature: in a multicall the error is returned as data,
    ///      and a gateway-chosen word could read as an address to a client that skips the error
    ///      marker.
    function _checkSigner(bytes32 structHash, bytes memory signature) internal view {
        (address signer, ECDSA.RecoverError err,) =
            ECDSA.tryRecover(_hashTypedDataV4(structHash), signature);
        if (err != ECDSA.RecoverError.NoError || !SIGNERS.isSigner(signer)) {
            revert UnknownSigner(signer);
        }
    }
}
