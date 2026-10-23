// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {OffchainLookup} from "@ens/contracts/ccipRead/EIP3668.sol";
import {IExtendedResolver} from "@ens/contracts/resolvers/profiles/IExtendedResolver.sol";
import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";

/// @dev A records resolver that answers every query offchain, like ENS's OffchainResolver
///      (signature checks omitted). The gateway returns the ABI-encoded profile result.
contract MockOffchainRecords is IExtendedResolver, ERC165 {
    string public constant URL = "https://gw.records";

    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return
            interfaceId == type(IExtendedResolver).interfaceId
                || super.supportsInterface(interfaceId);
    }

    function resolve(bytes calldata name, bytes calldata data)
        external
        view
        returns (bytes memory)
    {
        string[] memory urls = new string[](1);
        urls[0] = URL;
        revert OffchainLookup(
            address(this), urls, abi.encode(name, data), this.resolveCallback.selector, ""
        );
    }

    function resolveCallback(bytes calldata response, bytes calldata)
        external
        pure
        returns (bytes memory)
    {
        return response;
    }
}
