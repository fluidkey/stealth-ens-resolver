// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Ownable, Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";

/// @notice Who may sign Fluidkey gateway responses for unverified resolution.
interface IFluidkeySigners {
    function isSigner(address account) external view returns (bool);
}

/// @title FluidkeySigners
/// @notice The Fluidkey gateway signers `FluidkeyVerifier` accepts in unverified mode (ENSIP-30
///         Section 4, step 3: implementation-defined checks). Owned by Fluidkey, so signing keys
///         rotate without redeploying the verifier or repointing names. Has no effect on verified
///         mode: unverified mode already trusts Fluidkey, and the owner is Fluidkey.
contract FluidkeySigners is IFluidkeySigners, Ownable2Step {
    /// @inheritdoc IFluidkeySigners
    mapping(address account => bool) public isSigner;

    /// @notice `signer` was added (`enabled`) or removed.
    event SignerChanged(address indexed signer, bool enabled);

    constructor(address owner) Ownable(owner) {}

    /// @notice Adds or removes a gateway signer.
    function setSigner(address signer, bool enabled) external onlyOwner {
        isSigner[signer] = enabled;
        emit SignerChanged(signer, enabled);
    }
}
