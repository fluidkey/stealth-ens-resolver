// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {ResolverFeatures} from "@ens/contracts/resolvers/ResolverFeatures.sol";
import {ICompositeResolver} from "@ens/contracts/resolvers/profiles/ICompositeResolver.sol";
import {IExtendedResolver} from "@ens/contracts/resolvers/profiles/IExtendedResolver.sol";
import {IERC7996} from "@ens/contracts/utils/IERC7996.sol";

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {UserRegistry} from "~src/registry/UserRegistry.sol";
import {IRegistry} from "~src/registry/interfaces/IRegistry.sol";
import {RegistryRolesLib} from "~src/registry/libraries/RegistryRolesLib.sol";

import {StealthResolver} from "../src/StealthResolver.sol";
import {IStealthResolver} from "../src/interfaces/IStealthResolver.sol";
import {StealthResolverFixture} from "./utils/StealthResolverFixture.sol";

/// @dev Interfaces and the per-name config: who may set it, what it holds, how it is inherited.
contract StealthResolverConfigTest is StealthResolverFixture {
    function test_supportsInterfaces() public view {
        assertTrue(resolver.supportsInterface(0xba4f4bd5), "ENSIP-30 Section 5");
        assertTrue(resolver.supportsInterface(type(IStealthResolver).interfaceId));
        assertTrue(resolver.supportsInterface(type(IExtendedResolver).interfaceId));
        assertTrue(resolver.supportsInterface(type(ICompositeResolver).interfaceId));
        assertTrue(resolver.supportsInterface(type(IERC7996).interfaceId));
        assertTrue(resolver.supportsInterface(type(IERC165).interfaceId));
        assertFalse(resolver.supportsInterface(0xffffffff));
    }

    function test_supportsResolveMulticall() public view {
        assertTrue(resolver.supportsFeature(ResolverFeatures.RESOLVE_MULTICALL));
        assertFalse(resolver.supportsFeature(ResolverFeatures.SINGULAR));
    }

    /// @dev Read from the verifier once, at deployment: a verifier cannot change the scheme, and
    ///      with it the record key, of a deployed resolver.
    function test_schemeId_fixedAtDeployment() public {
        assertEq(resolver.schemeId(), 1);
        verifier.setSchemeId(42);
        assertEq(resolver.schemeId(), 1);
    }

    function test_setConfig_byOwner() public {
        string[] memory gw = urls("https://alice.gw");
        vm.expectEmit(address(resolver));
        emit StealthResolver.ConfigChanged(
            aliceNode, dns("alice.fkey.eth"), address(aliceRecords), gw
        );
        vm.prank(alice);
        resolver.setConfig(dns("alice.fkey.eth"), address(aliceRecords), gw);
        (address records, string[] memory own) = resolver.config(aliceNode);
        assertEq(records, address(aliceRecords));
        assertEq(own[0], "https://alice.gw");
        assertEq(resolver.gatewayURLs(aliceNode)[0], "https://alice.gw");
    }

    function test_setConfig_byDelegatedSetResolverRole() public {
        address delegate = makeAddr("delegate");
        uint256 tokenId = fkeyRegistry.getTokenId(uint256(keccak256("alice")));
        vm.prank(alice);
        fkeyRegistry.grantRoles(tokenId, RegistryRolesLib.ROLE_SET_RESOLVER, delegate);
        assertTrue(resolver.canSetConfig(dns("alice.fkey.eth"), delegate));
        setConfig(delegate, "alice.fkey.eth", address(aliceRecords), "");
    }

    function test_setConfig_strangerReverts() public {
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(
                StealthResolver.Unauthorized.selector, dns("alice.fkey.eth"), stranger
            )
        );
        resolver.setConfig(dns("alice.fkey.eth"), stranger, new string[](0));
    }

    /// @dev Fluidkey's registry for fkey.eth grants it no registry-wide ROLE_SET_RESOLVER, so it
    ///      cannot change a user's config (decision 2 of the plan).
    function test_setConfig_parentOwnerWithoutRootRoleCannot() public view {
        assertFalse(resolver.canSetConfig(dns("alice.fkey.eth"), fluidkey));
    }

    /// @dev With a registry-wide ROLE_SET_RESOLVER the parent can, exactly as it could set the
    ///      resolver itself. Users who need verified mode must use a registry without it.
    function test_setConfig_registryWideRoleCan() public {
        UserRegistry custodial = deployUserRegistry(
            fluidkey,
            RegistryRolesLib.ROLE_REGISTRAR | RegistryRolesLib.ROLE_SET_RESOLVER,
            uint256(keccak256("custodial"))
        );
        ethRegistry.register(
            "custodial", fluidkey, custodial, address(resolver), _ethTokenRoles(), expiry
        );
        vm.prank(fluidkey);
        custodial.register(
            "dave", makeAddr("dave"), IRegistry(address(0)), address(resolver), 0, expiry
        );
        assertTrue(resolver.canSetConfig(dns("dave.custodial.eth"), fluidkey));
    }

    function test_setConfig_expiredNameReverts() public {
        vm.warp(expiry);
        assertFalse(resolver.canSetConfig(dns("alice.fkey.eth"), alice));
    }

    function test_setConfig_unregisteredNameHasNoAuthority() public view {
        assertFalse(resolver.canSetConfig(dns("bob.fkey.eth"), fluidkey));
        assertFalse(resolver.canSetConfig(dns("bob.fkey.eth"), alice));
        assertFalse(resolver.canSetConfig(dns(""), address(this)));
    }

    function test_getResolver_ownInheritedNone() public {
        (address r,) = resolver.getResolver(dns("bob.fkey.eth"));
        assertEq(r, address(fkeyRecords), "inherited from fkey.eth");
        setConfig(alice, "alice.fkey.eth", address(aliceRecords), "");
        (r,) = resolver.getResolver(dns("alice.fkey.eth"));
        assertEq(r, address(aliceRecords), "own");
        (r,) = resolver.getResolver(dns("other.eth"));
        assertEq(r, address(0), "none");
    }

    /// @dev Fields inherit independently: own records resolver, gateway URLs from fkey.eth.
    function test_gatewayURLs_effectiveThroughResolve() public {
        setConfig(alice, "alice.fkey.eth", address(aliceRecords), "");
        assertEq(resolver.gatewayURLs(aliceNode).length, 0, "direct: own only");
        bytes memory v = resolver.resolve(
            dns("alice.fkey.eth"), abi.encodeCall(IStealthResolver.gatewayURLs, (aliceNode))
        );
        string[] memory effective = abi.decode(v, (string[]));
        assertEq(effective.length, 1);
        assertEq(effective[0], STEALTH_GW);
    }
}
