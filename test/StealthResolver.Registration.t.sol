// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {EIP3668} from "@ens/contracts/ccipRead/EIP3668.sol";
import {IAddrResolver} from "@ens/contracts/resolvers/profiles/IAddrResolver.sol";
import {IDataResolver} from "@ens/contracts/resolvers/profiles/IDataResolver.sol";
import {UserRegistry} from "~src/registry/UserRegistry.sol";
import {IRegistry} from "~src/registry/interfaces/IRegistry.sol";
import {RegistryRolesLib} from "~src/registry/libraries/RegistryRolesLib.sol";

import {StealthResolver} from "../src/StealthResolver.sol";
import {IStealthResolver} from "../src/interfaces/IStealthResolver.sol";
import {StealthResolverFixture} from "./utils/StealthResolverFixture.sol";

/// @dev State belongs to a registration: ENSv2 renews a name's EAC resource when an expired name is
///      registered again, and StealthResolver keys all state by it.
contract StealthResolverRegistrationTest is StealthResolverFixture {
    bytes internal constant VD = hex"c0ffee";
    address internal carol = makeAddr("carol");
    address internal attacker = makeAddr("attacker");

    function _record(string memory name) internal view returns (bytes memory) {
        bytes memory v = resolver.resolve(
            dns(name), abi.encodeCall(IDataResolver.data, (node(name), stealthKey(COIN_ETH)))
        );
        return abi.decode(v, (bytes));
    }

    /// @dev True if a lying gateway is accepted, i.e. the name resolves unverified.
    function _unverified(string memory name) internal view returns (bool ok) {
        EIP3668.Params memory p = expectLookup(
            address(resolver),
            abi.encodeCall(
                resolver.resolve, (dns(name), abi.encodeCall(IAddrResolver.addr, (node(name))))
            )
        );
        (ok,) = callback(p, abi.encode(attacker, VD));
    }

    /// @dev fkey.eth renewed, alice.fkey.eth expired and registered to `holder`.
    function _reregisterAlice(address holder) internal {
        ethRegistry.grantRootRoles(RegistryRolesLib.ROLE_RENEW, address(this));
        ethRegistry.renew(uint256(keccak256("fkey")), expiry + 1000 days);
        vm.warp(expiry);
        vm.prank(fluidkey);
        fkeyRegistry.register(
            "alice",
            holder,
            IRegistry(address(0)),
            address(resolver),
            RegistryRolesLib.ROLE_SET_RESOLVER,
            expiry + 365 days
        );
    }

    function test_reregistration_dropsRecordAndConfig() public {
        setUpAliceVerified(COIN_ETH);
        _reregisterAlice(carol);
        assertEq(_record("alice.fkey.eth").length, 0, "alice's record not served");
        (address r,) = resolver.getResolver(dns("alice.fkey.eth"));
        assertEq(r, address(0), "alice's config not read");
        bytes memory call = abi.encodeCall(
            IStealthResolver.verifyStealthResolution,
            (aliceNode, COIN_ETH, verifier.derive(metaWithoutFlag(), VD), VD)
        );
        vm.expectRevert(
            abi.encodeWithSelector(StealthResolver.NoStealthRecord.selector, aliceNode, COIN_ETH)
        );
        resolver.resolve(dns("alice.fkey.eth"), call);
        call = abi.encodeCall(IStealthResolver.gatewayURLs, (aliceNode));
        assertEq(abi.decode(resolver.resolve(dns("alice.fkey.eth"), call), (string[])).length, 0);

        setConfig(carol, "alice.fkey.eth", address(0), STEALTH_GW);
        setChain(carol, "alice.fkey.eth", COIN_ETH, true);
        assertTrue(_unverified("alice.fkey.eth"), "alice's record not verified against");
        setMeta(carol, "alice.fkey.eth", META);
        assertEq(_record("alice.fkey.eth"), META);
        assertFalse(_unverified("alice.fkey.eth"), "carol's record verifies");
    }

    /// @dev The same holder registering their expired name again starts from empty state too.
    function test_reregistration_sameHolderStartsEmpty() public {
        setUpAliceVerified(COIN_ETH);
        _reregisterAlice(alice);
        assertEq(_record("alice.fkey.eth").length, 0);
    }

    /// @dev Re-registering the parent drops everything written under its authority: config and
    ///      every wildcard username's record.
    function test_parentReregistration_dropsUsernames() public {
        setMeta(fluidkey, "bob.fkey.eth", META);
        vm.warp(expiry);
        ethRegistry.register(
            "fkey", carol, fkeyRegistry, address(resolver), _ethTokenRoles(), expiry + 365 days
        );
        assertEq(_record("bob.fkey.eth").length, 0, "bob's record not served");
        (address r,) = resolver.getResolver(dns("bob.fkey.eth"));
        assertEq(r, address(0), "fkey.eth's config not read");
        assertTrue(resolver.canSetMetaAddress(dns("bob.fkey.eth"), carol), "new holder writes");
        assertFalse(resolver.canSetMetaAddress(dns("bob.fkey.eth"), fluidkey));
    }

    /// @dev An expired name that is not registered again is a wildcard name of its parent, as
    ///      the UniversalResolver routes it: the parent's config and records apply, not its own.
    function test_expiredName_fallsBackToParent() public {
        setUpAliceVerified(COIN_ETH);
        ethRegistry.grantRootRoles(RegistryRolesLib.ROLE_RENEW, address(this));
        ethRegistry.renew(uint256(keccak256("fkey")), expiry + 1000 days);
        vm.warp(expiry);
        assertEq(_record("alice.fkey.eth").length, 0, "alice's record not served");
        (address r,) = resolver.getResolver(dns("alice.fkey.eth"));
        assertEq(r, address(fkeyRecords));
        assertTrue(resolver.canSetMetaAddress(dns("alice.fkey.eth"), fluidkey));
        assertFalse(resolver.canSetMetaAddress(dns("alice.fkey.eth"), alice));
    }

    /// @dev A reserved name is its own authority, as ENSv2 treats it: written by whoever may set its
    ///      resolver (registry-wide `ROLE_SET_RESOLVER`, as it has no token), never by its parent's
    ///      holder, and it does not inherit the parent's gateway. Registering it keeps the resource,
    ///      so what was written while it was reserved carries over.
    function test_reservedName_isItsOwnAuthority() public {
        address registrar = makeAddr("registrar");
        address clubOwner = makeAddr("club owner");
        UserRegistry clubRegistry = deployUserRegistry(
            registrar,
            RegistryRolesLib.ROLE_REGISTRAR | RegistryRolesLib.ROLE_REGISTER_RESERVED
                | RegistryRolesLib.ROLE_SET_RESOLVER,
            uint256(keccak256("club"))
        );
        ethRegistry.register(
            "club", clubOwner, clubRegistry, address(resolver), _ethTokenRoles(), expiry
        );
        setConfig(clubOwner, "club.eth", address(0), STEALTH_GW);
        setChain(clubOwner, "club.eth", COIN_ETH, true);
        vm.prank(registrar);
        clubRegistry.register(
            "vip", address(0), IRegistry(address(0)), address(resolver), 0, expiry
        );

        assertFalse(resolver.canSetMetaAddress(dns("vip.club.eth"), clubOwner), "not the parent");
        assertTrue(resolver.canSetConfig(dns("vip.club.eth"), registrar), "who sets its resolver");
        assertTrue(resolver.canSetMetaAddress(dns("sub.vip.club.eth"), registrar), "and below");
        assertFalse(isStealthChain("vip.club.eth", COIN_ETH), "no parent gateway");

        setChain(registrar, "vip.club.eth", COIN_ETH, true);
        setMeta(registrar, "vip.club.eth", META);
        vm.prank(registrar);
        clubRegistry.register(
            "vip",
            carol,
            IRegistry(address(0)),
            address(resolver),
            RegistryRolesLib.ROLE_SET_RESOLVER,
            0
        );
        assertTrue(resolver.canSetConfig(dns("vip.club.eth"), carol), "the registrant");
        assertEq(_record("vip.club.eth"), META, "kept on registration");
    }

    /// @dev A transfer keeps the state, as ENS's resolvers keep a name's records: the seller's
    ///      config, chain list and records stay, wildcard names' included, until the buyer clears
    ///      them with `clearRecords`.
    function test_transfer_keepsStateUntilCleared() public {
        address seller = makeAddr("seller");
        address buyer = makeAddr("buyer");
        vm.prank(fluidkey);
        uint256 tokenId = fkeyRegistry.register(
            "shop",
            seller,
            IRegistry(address(0)),
            address(resolver),
            RegistryRolesLib.ROLE_SET_RESOLVER | RegistryRolesLib.ROLE_CAN_TRANSFER_ADMIN,
            expiry
        );
        setConfig(seller, "shop.fkey.eth", address(0), STEALTH_GW);
        setChain(seller, "shop.fkey.eth", COIN_ETH, true);
        setMeta(seller, "shop.fkey.eth", META);
        setMeta(seller, "pay.shop.fkey.eth", META);
        vm.prank(seller);
        fkeyRegistry.safeTransferFrom(seller, buyer, tokenId, 1, "");

        assertEq(_record("pay.shop.fkey.eth"), META, "kept");
        assertFalse(resolver.canSetConfig(dns("shop.fkey.eth"), seller), "seller locked out");
        vm.expectRevert(
            abi.encodeWithSelector(
                StealthResolver.Unauthorized.selector, dns("shop.fkey.eth"), seller
            )
        );
        vm.prank(seller);
        resolver.clearRecords(dns("shop.fkey.eth"));

        vm.expectEmit(address(resolver));
        emit StealthResolver.VersionChanged(node("shop.fkey.eth"), 1);
        vm.prank(buyer);
        resolver.clearRecords(dns("shop.fkey.eth"));
        assertFalse(isStealthChain("shop.fkey.eth", COIN_ETH), "chain list cleared");
        bytes memory call = abi.encodeCall(IStealthResolver.gatewayURLs, (node("shop.fkey.eth")));
        assertEq(
            abi.decode(resolver.resolve(dns("shop.fkey.eth"), call), (string[])).length,
            0,
            "config cleared"
        );
        setChain(buyer, "shop.fkey.eth", COIN_ETH, true);
        assertEq(_record("shop.fkey.eth").length, 0, "record cleared");
        assertEq(_record("pay.shop.fkey.eth").length, 0, "wildcard record cleared");
        setMeta(buyer, "shop.fkey.eth", META);
        assertEq(_record("shop.fkey.eth"), META, "the buyer writes afresh");
    }

    /// @dev Only the authority of a registered name clears, and clearing a parent drops every
    ///      wildcard username's record with its own state.
    function test_clearRecords_authorityOfRegisteredName() public {
        setMeta(fluidkey, "bob.fkey.eth", META);
        vm.expectRevert(
            abi.encodeWithSelector(StealthResolver.Unauthorized.selector, dns("fkey.eth"), stranger)
        );
        vm.prank(stranger);
        resolver.clearRecords(dns("fkey.eth"));
        vm.expectRevert(
            abi.encodeWithSelector(
                StealthResolver.Unauthorized.selector, dns("bob.fkey.eth"), fluidkey
            )
        );
        vm.prank(fluidkey);
        resolver.clearRecords(dns("bob.fkey.eth")); // a wildcard name: clear its record instead

        assertEq(_record("bob.fkey.eth"), META);
        vm.prank(fluidkey);
        resolver.clearRecords(dns("fkey.eth"));
        setChain(fluidkey, "fkey.eth", COIN_ETH, true);
        assertEq(_record("bob.fkey.eth").length, 0, "every username's record");
        (address r,) = resolver.getResolver(dns("bob.fkey.eth"));
        assertEq(r, address(0), "and the config");
    }

    /// @dev Role changes regenerate the token but keep the resource: state is kept.
    function test_roleChange_keepsState() public {
        setUpAliceVerified(COIN_ETH);
        uint256 tokenId = fkeyRegistry.getTokenId(uint256(keccak256("alice")));
        vm.prank(alice);
        fkeyRegistry.grantRoles(tokenId, RegistryRolesLib.ROLE_SET_RESOLVER, makeAddr("delegate"));
        assertTrue(fkeyRegistry.getTokenId(uint256(keccak256("alice"))) != tokenId, "regenerated");
        assertEq(_record("alice.fkey.eth"), META);
        assertFalse(_unverified("alice.fkey.eth"));
    }
}
