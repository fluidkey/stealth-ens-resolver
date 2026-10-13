// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IDataResolver} from "@ens/contracts/resolvers/profiles/IDataResolver.sol";
import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";

/// @dev Claims the ENSIP-24 data profile but reverts on every query.
contract MockBrokenDataResolver is ERC165 {
    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return
            interfaceId == type(IDataResolver).interfaceId || super.supportsInterface(interfaceId);
    }

    function data(bytes32, string calldata) external pure returns (bytes memory) {
        revert("broken");
    }
}
