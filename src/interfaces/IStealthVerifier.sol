// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @title IStealthVerifier
/// @notice Scheme-specific logic a stealth resolver delegates to. Internal to this implementation:
///         the ENSIP defines `IStealthResolver` only. One verifier per ERC-5564 scheme; one resolver
///         deployment per verifier.
interface IStealthVerifier {
    /// @notice The ERC-5564 scheme ID this verifier implements.
    function schemeId() external view returns (uint256);

    /// @notice Derives or accepts the stealth address for one resolution.
    /// @dev Verified mode (`metaAddress` non-empty): returns the address derived from `metaAddress`
    ///      and `verificationData`; the resolver requires it to equal `claimed`. The result must
    ///      not depend on `claimed`. Reverts on a malformed `metaAddress` (ENSIP-30 Section 1,
    ///      failure semantics).
    ///      Unverified mode (`metaAddress` empty, ENSIP-30 Section 4, step 3): the verifier decides
    ///      what, if anything, to check, and returns the address to resolve to. The response may
    ///      have been relayed by a batch gateway (`resolve(name, multicall(...))`), so a verifier
    ///      that checks nothing also trusts that batch gateway; one that authenticates the response
    ///      (e.g. a signature by the stealth gateway) does not.
    ///      `node` and `coinType` identify the resolution so a verifier can bind gateway-supplied
    ///      data to it (e.g. replay protection across names and chains); `msg.sender` is the resolver.
    /// @param node The namehash being resolved.
    /// @param coinType The ENSIP-9 coin type being resolved.
    /// @param metaAddress The scheme-defined meta-address (the ENSIP-30 Section 1 record value
    ///        without its flag byte), or empty in unverified mode.
    /// @param verificationData The scheme-defined verification data supplied by the gateway.
    /// @param claimed The stealth address the gateway returned.
    /// @return The derived (verified mode) or accepted (unverified mode) stealth address.
    function verify(
        bytes32 node,
        uint256 coinType,
        bytes calldata metaAddress,
        bytes calldata verificationData,
        address claimed
    ) external view returns (address);
}
