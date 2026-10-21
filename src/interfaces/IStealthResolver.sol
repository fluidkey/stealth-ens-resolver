// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

// forgefmt: disable-start
/// @title IStealthResolver
/// @notice Verifying resolver interface, ENSIP-30 (Stealth Address Resolution) Section 5.
/// @dev The interface below is copied verbatim from the ENSIP and must stay identical to it;
///      `script/check-ensip-sync.sh` enforces this. ERC-165 interface ID: `0xba4f4bd5`.
///      Spec: https://github.com/ensdomains/ensips/blob/955e104670b5f019cd3b8a5f4a208142818d68bc/ensips/x.md
interface IStealthResolver {
    /// @notice The single ERC-5564 scheme this resolver verifies.
    function schemeId() external view returns (uint256);

    /// @notice Gateway URLs used for ERC-3668 resolution of `node`.
    /// @return An empty array if gateway-based resolution is not configured for `node`.
    function gatewayURLs(bytes32 node) external view returns (string[] memory);

    /// @notice Verifies that `stealthAddress` derives from the meta-address
    ///         registered for `node` and `coinType` under this resolver's scheme.
    /// @return stealthAddress on success; reverts on mismatch or missing record.
    function verifyStealthResolution(
        bytes32 node,
        uint256 coinType,
        address stealthAddress,
        bytes calldata verificationData
    ) external view returns (address);
}
// forgefmt: disable-end
