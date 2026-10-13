// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {EIP3668} from "@ens/contracts/ccipRead/EIP3668.sol";
import {IAddrResolver} from "@ens/contracts/resolvers/profiles/IAddrResolver.sol";
import {IAddressResolver} from "@ens/contracts/resolvers/profiles/IAddressResolver.sol";
import {IDataResolver} from "@ens/contracts/resolvers/profiles/IDataResolver.sol";
import {IExtendedResolver} from "@ens/contracts/resolvers/profiles/IExtendedResolver.sol";

import {StealthResolver} from "../src/StealthResolver.sol";
import {MockBrokenDataResolver} from "./mocks/MockBrokenDataResolver.sol";
import {MockOffchainRecords} from "./mocks/MockOffchainRecords.sol";
import {MockVerifier} from "./mocks/MockVerifier.sol";
import {StealthResolverFixture} from "./utils/StealthResolverFixture.sol";

/// @dev ENSIP-30 Section 4 through ENSIP-10 resolve(): lookup, callback, verified and unverified.
contract StealthResolverAddrTest is StealthResolverFixture {
    bytes internal constant VD = hex"c0ffee";

    function _lookup(string memory name) internal view returns (EIP3668.Params memory) {
        return expectLookup(
            address(resolver),
            abi.encodeCall(
                resolver.resolve, (dns(name), abi.encodeCall(IAddrResolver.addr, (node(name))))
            )
        );
    }

    function _lookupCoin(string memory name, uint256 coinType)
        internal
        view
        returns (EIP3668.Params memory)
    {
        return expectLookup(
            address(resolver),
            abi.encodeCall(
                resolver.resolve,
                (dns(name), abi.encodeCall(IAddressResolver.addr, (node(name), coinType)))
            )
        );
    }

    function _resolved(bytes memory v) internal pure returns (address) {
        return abi.decode(abi.decode(v, (bytes)), (address));
    }

    function _derived() internal view returns (address) {
        return verifier.derive(metaWithoutFlag(), VD);
    }

    // Lookup shape (step 1).

    function test_lookupShape() public view {
        bytes memory data = abi.encodeCall(IAddrResolver.addr, (bobNode));
        EIP3668.Params memory p = _lookup("bob.fkey.eth");
        assertEq(p.sender, address(resolver));
        assertEq(p.urls.length, 1);
        assertEq(p.urls[0], STEALTH_GW);
        assertEq(p.callData, abi.encodeCall(IExtendedResolver.resolve, (dns("bob.fkey.eth"), data)));
        assertEq(p.callbackFunction, resolver.resolveStealthCallback.selector);
        assertEq(p.extraData, abi.encode(dns("bob.fkey.eth"), COIN_ETH, true));
    }

    function test_lookupShape_coinType() public view {
        EIP3668.Params memory p = _lookupCoin("bob.fkey.eth", COIN_BASE);
        assertEq(p.extraData, abi.encode(dns("bob.fkey.eth"), COIN_BASE, false));
    }

    function test_ownGatewayWinsOverInherited() public {
        setConfig(alice, "alice.fkey.eth", address(aliceRecords), "https://alice.gw");
        assertEq(_lookup("alice.fkey.eth").urls[0], "https://alice.gw");
    }

    function test_nodeMustMatchName() public {
        vm.expectRevert(
            abi.encodeWithSelector(StealthResolver.NodeMismatch.selector, aliceNode, bobNode)
        );
        resolver.resolve(dns("bob.fkey.eth"), abi.encodeCall(IAddrResolver.addr, (aliceNode)));
    }

    // Verified (record in the name's own records resolver).

    function test_verified_honestGateway() public {
        setUpAliceVerified(COIN_ETH);
        (bool ok, bytes memory v) = callback(_lookup("alice.fkey.eth"), abi.encode(_derived(), VD));
        assertTrue(ok);
        assertEq(_resolved(v), _derived());
    }

    function test_verified_coinTypeReturnsBytes() public {
        setUpAliceVerified(COIN_BASE);
        (bool ok, bytes memory v) =
            callback(_lookupCoin("alice.fkey.eth", COIN_BASE), abi.encode(_derived(), VD));
        assertTrue(ok);
        assertEq(abi.decode(abi.decode(v, (bytes)), (bytes)), abi.encodePacked(_derived()));
    }

    function test_verified_lyingGatewayReverts() public {
        setUpAliceVerified(COIN_ETH);
        address attacker = makeAddr("attacker");
        (bool ok, bytes memory v) = callback(_lookup("alice.fkey.eth"), abi.encode(attacker, VD));
        assertFalse(ok);
        assertEq(
            v,
            abi.encodeWithSelector(
                StealthResolver.StealthAddressMismatch.selector, attacker, _derived()
            )
        );
    }

    function test_verified_wrongVerificationDataReverts() public {
        setUpAliceVerified(COIN_ETH);
        (bool ok,) = callback(_lookup("alice.fkey.eth"), abi.encode(_derived(), hex"00"));
        assertFalse(ok);
    }

    function test_verified_resolverEnforcesEquality() public {
        setUpAliceVerified(COIN_ETH);
        verifier.setOverride(address(0xD1FF));
        (bool ok, bytes memory v) = callback(_lookup("alice.fkey.eth"), abi.encode(_derived(), VD));
        assertFalse(ok);
        assertEq(
            v,
            abi.encodeWithSelector(
                StealthResolver.StealthAddressMismatch.selector, _derived(), address(0xD1FF)
            )
        );
    }

    function test_verified_perCoinType() public {
        setUpAliceVerified(COIN_ETH);
        address any = makeAddr("any");
        (bool ok, bytes memory v) =
            callback(_lookupCoin("alice.fkey.eth", COIN_BASE), abi.encode(any, VD));
        assertTrue(ok, "no record for Base: unverified");
        assertEq(abi.decode(abi.decode(v, (bytes)), (bytes)), abi.encodePacked(any));
    }

    function test_verified_recordRemovedBetweenLookupAndCallback() public {
        setUpAliceVerified(COIN_ETH);
        EIP3668.Params memory p = _lookup("alice.fkey.eth");
        string memory key = stealthKey(COIN_ETH);
        vm.prank(alice);
        aliceRecords.setData(aliceNode, key, "");
        (bool ok,) = callback(p, abi.encode(makeAddr("any"), VD));
        assertTrue(ok, "record read at callback time");
    }

    // Unverified.

    function test_unverified_wildcardReturnsGatewayAddress() public {
        address chosen = makeAddr("chosen");
        (bool ok, bytes memory v) =
            callback(_lookup("bob.fkey.eth"), abi.encode(chosen, bytes("ok")));
        assertTrue(ok);
        assertEq(_resolved(v), chosen);
    }

    function test_unverified_verifierChecksApply() public view {
        (bool ok, bytes memory v) =
            callback(_lookup("bob.fkey.eth"), abi.encode(address(1), bytes("reject")));
        assertFalse(ok);
        assertEq(bytes4(v), MockVerifier.Rejected.selector);
    }

    // Inheritance (wildcard names).

    function _setBobRecordInFluidkeyRecords() internal {
        string memory key = stealthKey(COIN_ETH);
        vm.prank(fluidkey);
        fkeyRecords.setData(bobNode, key, META);
    }

    /// @dev A record for bob in Fluidkey's records resolver, inherited from fkey.eth, is the
    ///      record bob is verified against: a lying gateway cannot redirect bob's payments.
    function test_inheritedRecord_verifies() public {
        _setBobRecordInFluidkeyRecords();
        (bool ok, bytes memory v) = callback(_lookup("bob.fkey.eth"), abi.encode(_derived(), VD));
        assertTrue(ok, "honest gateway");
        assertEq(_resolved(v), _derived());

        address attacker = makeAddr("attacker");
        (ok, v) = callback(_lookup("bob.fkey.eth"), abi.encode(attacker, VD));
        assertFalse(ok, "lying gateway");
        assertEq(
            v,
            abi.encodeWithSelector(
                StealthResolver.StealthAddressMismatch.selector, attacker, _derived()
            )
        );
    }

    /// @dev The record served through `resolve(name, data(...))` is the record the callback
    ///      verifies against, for every name: served means verified.
    function test_servedRecordIsVerifiedRecord() public {
        _setBobRecordInFluidkeyRecords();
        bytes memory v = resolver.resolve(
            dns("bob.fkey.eth"), abi.encodeCall(IDataResolver.data, (bobNode, stealthKey(COIN_ETH)))
        );
        assertEq(abi.decode(v, (bytes)), META, "served");
        (bool ok,) = callback(_lookup("bob.fkey.eth"), abi.encode(makeAddr("attacker"), VD));
        assertFalse(ok, "verified against it");
    }

    /// @dev A name's own records resolver replaces the inherited one as a whole: a record left in
    ///      the parent's records resolver no longer applies.
    function test_ownRecordsResolverReplacesInherited() public {
        string memory key = stealthKey(COIN_ETH);
        vm.prank(fluidkey);
        fkeyRecords.setData(aliceNode, key, META);
        setConfig(alice, "alice.fkey.eth", address(aliceRecords), "");
        address any = makeAddr("any");
        (bool ok, bytes memory v) = callback(_lookup("alice.fkey.eth"), abi.encode(any, VD));
        assertTrue(ok);
        assertEq(_resolved(v), any, "unverified: alice's own records resolver has no record");
    }

    /// @dev Two levels: sub.alice.fkey.eth takes alice's records resolver and fkey.eth's URLs.
    function test_inheritedRecord_twoLevels() public {
        setConfig(alice, "alice.fkey.eth", address(aliceRecords), "");
        bytes32 subNode = node("sub.alice.fkey.eth");
        string memory key = stealthKey(COIN_ETH);
        vm.prank(alice);
        aliceRecords.setData(subNode, key, META);
        EIP3668.Params memory p = _lookup("sub.alice.fkey.eth");
        assertEq(p.urls[0], STEALTH_GW);
        (bool ok,) = callback(p, abi.encode(makeAddr("attacker"), VD));
        assertFalse(ok, "verified against alice's records resolver");
    }

    function test_recordsResolverWithoutDataProfile_isUnverified() public {
        MockOffchainRecords offchain = new MockOffchainRecords();
        setConfig(alice, "alice.fkey.eth", address(offchain), "");
        address any = makeAddr("any");
        (bool ok, bytes memory v) = callback(_lookup("alice.fkey.eth"), abi.encode(any, VD));
        assertTrue(ok);
        assertEq(_resolved(v), any);
    }

    function test_recordsResolverClaimingDataButReverting_failsClosed() public {
        MockBrokenDataResolver broken = new MockBrokenDataResolver();
        setConfig(alice, "alice.fkey.eth", address(broken), "");
        (bool ok, bytes memory v) =
            callback(_lookup("alice.fkey.eth"), abi.encode(makeAddr("any"), VD));
        assertFalse(ok);
        assertEq(
            v,
            abi.encodeWithSelector(StealthResolver.RecordUnavailable.selector, aliceNode, COIN_ETH)
        );
    }

    // Malformed records (ENSIP-30 Section 1).

    function _setAliceRecord(bytes memory value) internal {
        string memory key = stealthKey(COIN_ETH);
        vm.prank(alice);
        aliceRecords.setData(aliceNode, key, value);
        setConfig(alice, "alice.fkey.eth", address(aliceRecords), "");
    }

    /// @dev Without this check the verifier would get an empty meta-address, i.e. unverified mode.
    function test_flagOnlyRecordReverts() public {
        _setAliceRecord(hex"01");
        (bool ok, bytes memory v) =
            callback(_lookup("alice.fkey.eth"), abi.encode(makeAddr("any"), VD));
        assertFalse(ok);
        assertEq(v, abi.encodeWithSelector(StealthResolver.MalformedRecord.selector, hex"01"));
    }

    function test_reservedFlagBitsRevert() public {
        bytes memory value = META;
        value[0] = 0x03;
        _setAliceRecord(value);
        (bool ok, bytes memory v) = callback(_lookup("alice.fkey.eth"), abi.encode(_derived(), VD));
        assertFalse(ok);
        assertEq(bytes4(v), StealthResolver.MalformedRecord.selector);
    }

    function test_badLengthRejectedByVerifier() public {
        _setAliceRecord(hex"01aabb");
        (bool ok, bytes memory v) =
            callback(_lookup("alice.fkey.eth"), abi.encode(makeAddr("any"), VD));
        assertFalse(ok);
        assertEq(bytes4(v), MockVerifier.MalformedMetaAddress.selector);
    }

    function test_malformedResponseReverts() public view {
        (bool ok,) = callback(_lookup("bob.fkey.eth"), hex"1234");
        assertFalse(ok);
    }

    // verifyStealthResolution (Section 5).

    function test_verifyStealthResolution() public {
        setUpAliceVerified(COIN_ETH);
        assertEq(resolver.verifyStealthResolution(aliceNode, COIN_ETH, _derived(), VD), _derived());
        vm.expectRevert(
            abi.encodeWithSelector(
                StealthResolver.StealthAddressMismatch.selector, address(0xBAD), _derived()
            )
        );
        resolver.verifyStealthResolution(aliceNode, COIN_ETH, address(0xBAD), VD);
    }

    /// @dev A node cannot be walked to its ancestors: out-of-flow verification covers names with
    ///      their own records resolver only, though the callback verifies inherited records.
    function test_verifyStealthResolution_inheritedRecordNotFound() public {
        _setBobRecordInFluidkeyRecords();
        address derived = _derived(); // external call: before expectRevert
        vm.expectRevert(
            abi.encodeWithSelector(StealthResolver.NoStealthRecord.selector, bobNode, COIN_ETH)
        );
        resolver.verifyStealthResolution(bobNode, COIN_ETH, derived, VD);
    }

    function test_verifyStealthResolution_missingRecordReverts() public {
        vm.expectRevert(
            abi.encodeWithSelector(StealthResolver.NoStealthRecord.selector, bobNode, COIN_ETH)
        );
        resolver.verifyStealthResolution(bobNode, COIN_ETH, address(1), "");
    }
}
