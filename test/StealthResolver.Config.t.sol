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
        (address records,) = resolver.getResolver(dns("alice.fkey.eth"));
        assertEq(records, address(aliceRecords));
        bytes memory v = resolver.resolve(
            dns("alice.fkey.eth"), abi.encodeCall(IStealthResolver.gatewayURLs, (aliceNode))
        );
        assertEq(abi.decode(v, (string[]))[0], "https://alice.gw");
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
        vm.expectRevert(
            abi.encodeWithSelector(
                StealthResolver.InvalidRecordsResolver.selector, address(resolver)
            )
        );
        resolver.setConfig(dns("alice.fkey.eth"), address(resolver), new string[](0));
    }

    /// @dev A mistyped records resolver would fail every forwarded read while the name silently
    ///      resolved unverified.
    function test_setConfig_accountWithoutCodeReverts() public {
        address eoa = makeAddr("eoa");
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(StealthResolver.InvalidRecordsResolver.selector, eoa)
        );
        resolver.setConfig(dns("alice.fkey.eth"), eoa, new string[](0));
    }

    /// @dev A registered name's config is its own: clearing it does not fall back to fkey.eth's.
    function test_setConfig_registeredNameNeverInherits() public {
        setConfig(alice, "alice.fkey.eth", address(aliceRecords), "https://alice.gw");
        setConfig(alice, "alice.fkey.eth", address(0), "");
        (address r,) = resolver.getResolver(dns("alice.fkey.eth"));
        assertEq(r, address(0));
        bytes memory v = resolver.resolve(
            dns("alice.fkey.eth"), abi.encodeCall(IStealthResolver.gatewayURLs, (aliceNode))
        );
        assertEq(abi.decode(v, (string[])).length, 0);
    }

    // Who may write the meta-address.

    function test_setMetaAddress_authority() public {
        assertTrue(resolver.canSetMetaAddress(dns("alice.fkey.eth"), alice), "own name");
        assertFalse(resolver.canSetMetaAddress(dns("alice.fkey.eth"), fluidkey), "parent");
        assertTrue(resolver.canSetMetaAddress(dns("bob.fkey.eth"), fluidkey), "wildcard");
        assertFalse(resolver.canSetMetaAddress(dns("bob.fkey.eth"), alice), "sibling");
        assertTrue(resolver.canSetMetaAddress(dns("x.alice.fkey.eth"), alice), "below own");
        assertFalse(resolver.canSetMetaAddress(dns("eth"), address(this)), "top-level");
        assertFalse(resolver.canSetMetaAddress(dns("x.eth"), address(this)), "unregistered 2LD");
        assertFalse(resolver.canSetMetaAddress(dns(""), address(this)), "root");
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(
                StealthResolver.Unauthorized.selector, dns("bob.fkey.eth"), stranger
            )
        );
        resolver.setMetaAddress(dns("bob.fkey.eth"), hex"0102");
    }

    function test_setMetaAddress_byDelegatedSetResolverRole() public {
        address delegate = makeAddr("delegate");
        uint256 tokenId = fkeyRegistry.getTokenId(uint256(keccak256("alice")));
        vm.prank(alice);
        fkeyRegistry.grantRoles(tokenId, RegistryRolesLib.ROLE_SET_RESOLVER, delegate);
        setMeta(delegate, "alice.fkey.eth", META);
    }

    function test_setMetaAddress_emitsAndClears() public {
        setChain(alice, "alice.fkey.eth", COIN_ETH, true);
        vm.expectEmit(address(resolver));
        emit StealthResolver.MetaAddressChanged(aliceNode, dns("alice.fkey.eth"), META);
        setMeta(alice, "alice.fkey.eth", META);
        setMeta(alice, "alice.fkey.eth", "");
        vm.expectRevert(
            abi.encodeWithSelector(StealthResolver.NoStealthRecord.selector, aliceNode, COIN_ETH)
        );
        resolver.resolve(
            dns("alice.fkey.eth"),
            abi.encodeCall(
                IStealthResolver.verifyStealthResolution, (aliceNode, COIN_ETH, address(1), "")
            )
        );
    }

    // Chain lists.

    /// @dev Only the registered name's own authority writes its chain list; wildcard names and
    ///      registered names below it have none of their own.
    function test_setChains_authority() public {
        uint256[] memory coinTypes = new uint256[](1);
        coinTypes[0] = COIN_ETH;
        vm.prank(fluidkey);
        vm.expectRevert(
            abi.encodeWithSelector(
                StealthResolver.Unauthorized.selector, dns("alice.fkey.eth"), fluidkey
            )
        );
        resolver.setChains(dns("alice.fkey.eth"), coinTypes, true);
        vm.prank(fluidkey);
        vm.expectRevert(
            abi.encodeWithSelector(
                StealthResolver.Unauthorized.selector, dns("bob.fkey.eth"), fluidkey
            )
        );
        resolver.setChains(dns("bob.fkey.eth"), coinTypes, true);
    }

    /// @dev True iff an address query goes to the gateway: listed by the authority and gateway
    ///      URLs set. A wildcard name uses its authority's list; a registered name only its own.
    function test_stealthChain_listAndURLs() public {
        assertTrue(isStealthChain("bob.fkey.eth", COIN_ETH), "fkey.eth's list");
        assertFalse(isStealthChain("bob.fkey.eth", 10), "not listed");
        assertFalse(isStealthChain("alice.fkey.eth", COIN_ETH), "nothing inherited");
        setChain(alice, "alice.fkey.eth", COIN_BASE, true);
        assertFalse(isStealthChain("alice.fkey.eth", COIN_BASE), "no gateway URLs");
        setConfig(alice, "alice.fkey.eth", address(aliceRecords), STEALTH_GW);
        assertTrue(isStealthChain("alice.fkey.eth", COIN_BASE));
        assertTrue(isStealthChain("x.alice.fkey.eth", COIN_BASE), "below alice");
        setConfig(alice, "alice.fkey.eth", address(aliceRecords), "");
        assertFalse(isStealthChain("alice.fkey.eth", COIN_BASE), "URLs cleared");
        setConfig(alice, "alice.fkey.eth", address(aliceRecords), STEALTH_GW);
        setChain(alice, "alice.fkey.eth", COIN_BASE, false);
        assertFalse(isStealthChain("alice.fkey.eth", COIN_BASE), "removed");
    }

    function test_setChains_emits() public {
        vm.expectEmit(address(resolver));
        emit StealthResolver.ChainChanged(aliceNode, dns("alice.fkey.eth"), COIN_BASE, true);
        setChain(alice, "alice.fkey.eth", COIN_BASE, true);
    }

    /// @dev The verifier answers with an EVM address, so only EVM coin types can be listed.
    function test_setChains_nonEVMReverts() public {
        uint256[] memory coinTypes = new uint256[](2);
        coinTypes[0] = COIN_ETH;
        coinTypes[1] = 0; // Bitcoin
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(StealthResolver.InvalidChain.selector, 0));
        resolver.setChains(dns("alice.fkey.eth"), coinTypes, true);
    }

    /// @dev The ENSIP-19 default may be listed; `0x80000001`, Ethereum in ENSIP-11 form, may not:
    ///      chain 1 is 60.
    function test_setChains_defaultListedAliasRejected() public {
        setChain(alice, "alice.fkey.eth", 0x80000000, true);
        uint256[] memory coinTypes = new uint256[](1);
        coinTypes[0] = 0x80000001;
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(StealthResolver.InvalidChain.selector, 0x80000001));
        resolver.setChains(dns("alice.fkey.eth"), coinTypes, true);
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
        assertEq(r, address(fkeyRecords), "wildcard: fkey.eth's");
        (r,) = resolver.getResolver(dns("alice.fkey.eth"));
        assertEq(r, address(0), "registered, no config: nothing inherited");
        setConfig(alice, "alice.fkey.eth", address(aliceRecords), "");
        (r,) = resolver.getResolver(dns("alice.fkey.eth"));
        assertEq(r, address(aliceRecords), "own");
        (r,) = resolver.getResolver(dns("x.alice.fkey.eth"));
        assertEq(r, address(aliceRecords), "wildcard below alice: alice's");
        (r,) = resolver.getResolver(dns("other.eth"));
        assertEq(r, address(0), "none");
    }

    /// @dev The ENSIP-30 Section 5 functions take a node, which cannot be walked to the name's
    ///      authority: called directly they revert; through `resolve()` they are answered by name.
    function test_section5_resolveOnly() public {
        setUpAliceVerified(COIN_ETH);
        vm.expectRevert(
            abi.encodeWithSelector(
                StealthResolver.ResolveOnly.selector, IStealthResolver.gatewayURLs.selector
            )
        );
        resolver.gatewayURLs(aliceNode);
        vm.expectRevert(
            abi.encodeWithSelector(
                StealthResolver.ResolveOnly.selector,
                IStealthResolver.verifyStealthResolution.selector
            )
        );
        resolver.verifyStealthResolution(aliceNode, COIN_ETH, address(1), "");
    }

    /// @dev Through `resolve()` a wildcard name reports its authority's URLs; a registered name
    ///      only its own.
    function test_gatewayURLs_throughResolve() public {
        setConfig(alice, "alice.fkey.eth", address(aliceRecords), "");
        bytes memory v = resolver.resolve(
            dns("alice.fkey.eth"), abi.encodeCall(IStealthResolver.gatewayURLs, (aliceNode))
        );
        assertEq(abi.decode(v, (string[])).length, 0, "registered: not fkey.eth's");
        v = resolver.resolve(
            dns("bob.fkey.eth"), abi.encodeCall(IStealthResolver.gatewayURLs, (bobNode))
        );
        string[] memory effective = abi.decode(v, (string[]));
        assertEq(effective.length, 1);
        assertEq(effective[0], STEALTH_GW, "wildcard: fkey.eth's");
    }

    function test_gatewayURLs_nodeMustMatchName() public {
        vm.expectRevert(
            abi.encodeWithSelector(StealthResolver.NodeMismatch.selector, aliceNode, bobNode)
        );
        resolver.resolve(
            dns("bob.fkey.eth"), abi.encodeCall(IStealthResolver.gatewayURLs, (aliceNode))
        );
    }
}
