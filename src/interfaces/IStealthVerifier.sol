// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @title IStealthVerifier
/// @notice Scheme-specific logic a stealth resolver delegates to. Internal to this implementation:
///         the ENSIP defines `IStealthResolver` only. One verifier per ERC-5564 scheme; one resolver
///         deployment per verifier.
/// @dev `metaAddress` is always the scheme-defined meta-address encoding, i.e. the ENSIP-30
///      Section 1 record value without its leading flag byte.
interface IStealthVerifier {
    /// @notice The ERC-5564 scheme ID this verifier implements.
    function schemeId() external view returns (uint256);

    /// @notice Derives the stealth address for `metaAddress` and `verificationData`.
    /// @dev `metaAddress` empty = unverified mode (ENSIP-30 Section 4, step 3); the verifier decides
    ///      what, if anything, to check, and returns the address to resolve to.
    ///      Otherwise the resolver requires the returned address to equal `claimed`.
    /// @param metaAddress The scheme-defined meta-address, or empty in unverified mode.
    /// @param verificationData The scheme-defined verification data supplied by the gateway.
    /// @param claimed The stealth address the gateway returned.
    /// @return The derived (verified mode) or accepted (unverified mode) stealth address.
    function verify(bytes calldata metaAddress, bytes calldata verificationData, address claimed)
        external
        view
        returns (address);

    /// @notice Reverts if `metaAddress` is not a well-formed meta-address for this scheme.
    /// @dev Called by the resolver when the record is written, so malformed records are rejected
    ///      up front (ENSIP-30 Section 1, failure semantics).
    /// @param metaAddress The scheme-defined meta-address encoding.
    function validateMetaAddress(bytes calldata metaAddress) external view;
}
