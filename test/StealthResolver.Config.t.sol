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
        (address records, string[] memory own) = resolver.config(dns("alice.fkey.eth"));
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

    /// @dev A top-level name's config would reach every name below it that has none of its own.
    function test_setConfig_topLevelNameRefused() public {
        assertFalse(resolver.canSetConfig(dns("eth"), address(this)));
        vm.expectRevert(
            abi.encodeWithSelector(StealthResolver.Unauthorized.selector, dns("eth"), address(this))
        );
        resolver.setConfig(dns("eth"), address(fkeyRecords), urls("https://eth.gw"));
    }

    function test_setConfig_selfAsRecordsResolverReverts() public {
        vm.prank(alice);
        vm.expectRevert(StealthResolver.InvalidRecordsResolver.selector);
        resolver.setConfig(dns("alice.fkey.eth"), address(resolver), new string[](0));
    }

    /// @dev Zero records resolver and empty URLs fall back to the nearest ancestor's.
    function test_setConfig_clearFallsBackToInherited() public {
        setConfig(alice, "alice.fkey.eth", address(aliceRecords), "https://alice.gw");
        setConfig(alice, "alice.fkey.eth", address(0), "");
        (address r,) = resolver.getResolver(dns("alice.fkey.eth"));
        assertEq(r, address(fkeyRecords));
        bytes memory v = resolver.resolve(
            dns("alice.fkey.eth"), abi.encodeCall(IStealthResolver.gatewayURLs, (aliceNode))
        );
        assertEq(abi.decode(v, (string[]))[0], STEALTH_GW);
    }

    /// @dev Config belongs to a registration: once the name expires and is registered to someone
    ///      else, the previous holder's config is not read.
    function test_setConfig_droppedOnReregistration() public {
        setConfig(alice, "alice.fkey.eth", address(aliceRecords), "https://alice.gw");
        ethRegistry.grantRootRoles(RegistryRolesLib.ROLE_RENEW, address(this));
        ethRegistry.renew(uint256(keccak256("fkey")), expiry + 1000 days);
        vm.warp(expiry);
        address carol = makeAddr("carol");
        vm.prank(fluidkey);
        fkeyRegistry.register(
            "alice",
            carol,
            IRegistry(address(0)),
            address(resolver),
            RegistryRolesLib.ROLE_SET_RESOLVER,
            expiry + 365 days
        );
        assertFalse(resolver.canSetConfig(dns("alice.fkey.eth"), alice), "old holder");
        (address r,) = resolver.getResolver(dns("alice.fkey.eth"));
        assertEq(r, address(fkeyRecords), "previous holder's config not read");
        (address own,) = resolver.config(dns("alice.fkey.eth"));
        assertEq(own, address(0));
    }

    // Who may write the stealth record.

    function test_setStealthRecord_authority() public {
        assertTrue(resolver.canSetStealthRecord(dns("alice.fkey.eth"), alice), "own name");
        assertFalse(resolver.canSetStealthRecord(dns("alice.fkey.eth"), fluidkey), "parent");
        assertTrue(resolver.canSetStealthRecord(dns("bob.fkey.eth"), fluidkey), "wildcard");
        assertFalse(resolver.canSetStealthRecord(dns("bob.fkey.eth"), alice), "sibling");
        assertTrue(resolver.canSetStealthRecord(dns("x.alice.fkey.eth"), alice), "below own");
        assertFalse(resolver.canSetStealthRecord(dns("eth"), address(this)), "top-level");
        assertFalse(resolver.canSetStealthRecord(dns("x.eth"), address(this)), "unregistered 2LD");
        assertFalse(resolver.canSetStealthRecord(dns(""), address(this)), "root");
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(
                StealthResolver.Unauthorized.selector, dns("bob.fkey.eth"), stranger
            )
        );
        resolver.setStealthRecord(dns("bob.fkey.eth"), 60, hex"0102");
    }

    function test_setStealthRecord_byDelegatedSetResolverRole() public {
        address delegate = makeAddr("delegate");
        uint256 tokenId = fkeyRegistry.getTokenId(uint256(keccak256("alice")));
        vm.prank(alice);
        fkeyRegistry.grantRoles(tokenId, RegistryRolesLib.ROLE_SET_RESOLVER, delegate);
        setRecord(delegate, "alice.fkey.eth", COIN_ETH, META);
    }

    function test_setStealthRecord_emitsAndClears() public {
        vm.expectEmit(address(resolver));
        emit StealthResolver.StealthRecordChanged(aliceNode, dns("alice.fkey.eth"), COIN_ETH, META);
        setRecord(alice, "alice.fkey.eth", COIN_ETH, META);
        setRecord(alice, "alice.fkey.eth", COIN_ETH, "");
        vm.expectRevert(
            abi.encodeWithSelector(StealthResolver.NoStealthRecord.selector, aliceNode, COIN_ETH)
        );
        resolver.verifyStealthResolution(aliceNode, COIN_ETH, address(1), "");
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
