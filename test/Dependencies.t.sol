// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test} from "forge-std/Test.sol";

import {PublicResolver} from "@ens/contracts/resolvers/PublicResolver.sol";
import {IDataResolver} from "@ens/contracts/resolvers/profiles/IDataResolver.sol";
import {INameWrapper} from "@ens/contracts/wrapper/INameWrapper.sol";

import {IPermissionedRegistry} from "@ensv2/registry/interfaces/IPermissionedRegistry.sol";
import {PublicResolverV2} from "@ensv2/resolver/PublicResolverV2.sol";
import {IContractNamer} from "@ensv2/reverse-registrar/interfaces/IContractNamer.sol";

/// @notice Guards the dependency setup: the canonical ENSv1 and ENSv2 public resolvers
///         must compile and behave under this repo's remappings and compiler settings.
contract DependenciesTest is Test {
    function test_PublicResolverV2_deploysAndReportsDataProfile() public {
        PublicResolverV2 resolver = new PublicResolverV2(
            INameWrapper(address(0)), IPermissionedRegistry(address(0)), IContractNamer(address(0))
        );
        assertTrue(resolver.supportsInterface(type(IDataResolver).interfaceId));
    }

    function test_PublicResolverV1_compiles() public pure {
        assertGt(type(PublicResolver).creationCode.length, 0);
    }
}
