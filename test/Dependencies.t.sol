// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IDataResolver} from "@ens/contracts/resolvers/profiles/IDataResolver.sol";
import {IExtendedResolver} from "@ens/contracts/resolvers/profiles/IExtendedResolver.sol";
import {INameWrapper} from "@ens/contracts/wrapper/INameWrapper.sol";
import {PublicResolverV2} from "@ensv2/resolver/PublicResolverV2.sol";

import {Grant} from "~src/access-control/interfaces/IEACGrantInitializable.sol";
import {EACBaseRolesLib} from "~src/access-control/libraries/EACBaseRolesLib.sol";
import {IPermissionedRegistry} from "~src/registry/interfaces/IPermissionedRegistry.sol";
import {PermissionedResolver} from "~src/resolver/PermissionedResolver.sol";
import {IDataSetter} from "~src/resolver/interfaces/setters/IDataSetter.sol";
import {IContractNamer} from "~src/reverse-registrar/interfaces/IContractNamer.sol";
import {V2Fixture} from "~test/fixtures/V2Fixture.sol";

/// @notice Guards the dependency setup: the canonical ENSv2 contracts this repo builds on must
///         compile and deploy under this repo's remappings and compiler settings.
contract DependenciesTest is V2Fixture {
    function test_PublicResolverV2_deploys() public {
        PublicResolverV2 resolver = new PublicResolverV2(
            INameWrapper(address(0)), IPermissionedRegistry(address(0)), IContractNamer(address(0))
        );
        assertTrue(resolver.supportsInterface(type(IDataResolver).interfaceId));
    }

    function test_V2Fixture_and_PermissionedResolverProxy_deploy() public {
        deployV2Fixture();
        PermissionedResolver impl = new PermissionedResolver(address(this));
        Grant[] memory grants = new Grant[](1);
        grants[0] = Grant(address(this), EACBaseRolesLib.ALL_ROLES | EACBaseRolesLib.ADMIN_ROLES);
        bytes memory init =
            abi.encodeCall(PermissionedResolver.initialize, (grants, new bytes[](0)));
        PermissionedResolver resolver = PermissionedResolver(
            verifiableFactory.deployProxy(address(impl), uint256(keccak256(init)), init)
        );
        // Since v2-mainnet-deployment-1 it answers reads only through `resolve()`, and its setters
        // take the DNS-encoded name.
        assertTrue(resolver.supportsInterface(type(IExtendedResolver).interfaceId));
        assertTrue(resolver.supportsInterface(type(IDataSetter).interfaceId));
        assertEq(address(universalResolver.ROOT_REGISTRY()), address(rootRegistry));
    }
}
