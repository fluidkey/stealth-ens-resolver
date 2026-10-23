// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IExtendedResolver} from "@ens/contracts/resolvers/profiles/IExtendedResolver.sol";
import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";

/// @dev A records resolver whose `resolve(name, data)` executes `data` against itself, as some
///      extended resolvers do, holding one static address for every name.
contract MockExecutingRecords is IExtendedResolver, ERC165 {
    address public constant STATIC = address(0x5747);

    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return
            interfaceId == type(IExtendedResolver).interfaceId
                || super.supportsInterface(interfaceId);
    }

    function resolve(bytes calldata, bytes calldata data) external view returns (bytes memory) {
        (bool ok, bytes memory v) = address(this).staticcall(data);
        if (!ok) {
            assembly {
                revert(add(v, 32), mload(v))
            }
        }
        return v;
    }

    function addr(bytes32) external pure returns (address) {
        return STATIC;
    }
}
