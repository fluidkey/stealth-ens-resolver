// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IStealthVerifier} from "../../src/interfaces/IStealthVerifier.sol";

/// @dev Deterministic stand-in for a scheme verifier.
///      Verified mode: `address(keccak256(metaAddress, verificationData))`; reverts unless the
///      meta-address is 66 bytes (scheme-1 length).
///      Unverified mode: returns `claimed` unless `verificationData` is "reject".
contract MockVerifier is IStealthVerifier {
    error MalformedMetaAddress();
    error Rejected();

    uint256 public schemeId = 1;
    /// @dev When set, verified mode returns this address instead of the derivation.
    address public overrideAddress;

    function setSchemeId(uint256 id) external {
        schemeId = id;
    }

    function setOverride(address a) external {
        overrideAddress = a;
    }

    function derive(bytes memory metaAddress, bytes memory verificationData)
        public
        pure
        returns (address)
    {
        return address(uint160(uint256(keccak256(abi.encode(metaAddress, verificationData)))));
    }

    function verify(
        bytes32,
        uint256,
        bytes calldata metaAddress,
        bytes calldata verificationData,
        address claimed
    ) external view returns (address) {
        if (metaAddress.length == 0) {
            if (keccak256(verificationData) == keccak256("reject")) revert Rejected();
            return claimed;
        }
        if (metaAddress.length != 66) revert MalformedMetaAddress();
        if (overrideAddress != address(0)) return overrideAddress;
        return derive(metaAddress, verificationData);
    }
}
