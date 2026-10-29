// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Ownable, Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";

/// @notice Who may sign Cloaked gateway responses.
interface ICloakedSigners {
    function isSigner(address account) external view returns (bool);
}

/// @title CloakedSigners
/// @notice The Cloaked gateway signers `CloakedVerifier` accepts, in both modes. Owned by Cloaked,
///         so signing keys rotate without redeploying the verifier or repointing names. In
///         unverified mode a signer vouches for the address. In verified mode the address is
///         derived from the record, so a signer can refuse a derivation but cannot make the
///         verifier return an address the record does not derive. Ownership can be transferred
///         (two steps) but not renounced, so a leaked key can always be removed. Same contract as
///         `FluidkeySigners`, deployed separately so each gateway's operator owns its own set.
contract CloakedSigners is ICloakedSigners, Ownable2Step {
    /// @inheritdoc ICloakedSigners
    mapping(address account => bool) public isSigner;

    /// @notice `signer` was added (`enabled`) or removed.
    event SignerChanged(address indexed signer, bool enabled);

    /// @notice Renouncing would freeze the signer set, leaked keys included.
    error RenounceDisabled();

    constructor(address owner) Ownable(owner) {}

    /// @notice Adds or removes a gateway signer.
    function setSigner(address signer, bool enabled) external onlyOwner {
        isSigner[signer] = enabled;
        emit SignerChanged(signer, enabled);
    }

    /// @notice Disabled; see `RenounceDisabled`.
    function renounceOwnership() public pure override {
        revert RenounceDisabled();
    }
}
