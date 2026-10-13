// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {EIP3668} from "@ens/contracts/ccipRead/EIP3668.sol";
import {IAddrResolver} from "@ens/contracts/resolvers/profiles/IAddrResolver.sol";
import {IAddressResolver} from "@ens/contracts/resolvers/profiles/IAddressResolver.sol";
import {IDataResolver} from "@ens/contracts/resolvers/profiles/IDataResolver.sol";
import {IExtendedResolver} from "@ens/contracts/resolvers/profiles/IExtendedResolver.sol";
import {IRegistry} from "~src/registry/interfaces/IRegistry.sol";
import {RegistryRolesLib} from "~src/registry/libraries/RegistryRolesLib.sol";

import {StealthResolver} from "../src/StealthResolver.sol";
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

    // Verified (the name's own record).

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
        setRecord(alice, "alice.fkey.eth", COIN_ETH, "");
        (bool ok,) = callback(p, abi.encode(makeAddr("any"), VD));
        assertTrue(ok, "record read at callback time");
    }

    function test_verified_recordAddedBetweenLookupAndCallback() public {
        EIP3668.Params memory p = _lookup("alice.fkey.eth");
        setRecord(alice, "alice.fkey.eth", COIN_ETH, META);
        (bool ok,) = callback(p, abi.encode(makeAddr("attacker"), VD));
        assertFalse(ok, "record read at callback time");
    }

    // Unverified.

    /// @dev A gateway answers "no address on this chain" with the zero address: an unset record,
    ///      empty bytes for `addr(coinType)` as for any ENS resolver.
    function test_unverified_zeroAddressIsUnset() public view {
        (bool ok, bytes memory v) =
            callback(_lookupCoin("bob.fkey.eth", COIN_BASE), abi.encode(address(0), bytes("ok")));
        assertTrue(ok);
        assertEq(abi.decode(abi.decode(v, (bytes)), (bytes)).length, 0);
        (ok, v) = callback(_lookup("bob.fkey.eth"), abi.encode(address(0), bytes("ok")));
        assertTrue(ok);
        assertEq(_resolved(v), address(0));
    }

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

    // Non-EVM coin types: forwarded, the verifier answers with an EVM address.

    function test_nonEvmCoinType_forwarded() public {
        bytes memory btc = hex"0014aabbccddeeff00112233445566778899aabbccdd";
        setConfig(alice, "alice.fkey.eth", address(aliceRecords), "");
        vm.prank(alice);
        aliceRecords.setAddr(aliceNode, 0, btc);
        bytes memory v = resolver.resolve(
            dns("alice.fkey.eth"), abi.encodeCall(IAddressResolver.addr, (aliceNode, 0))
        );
        assertEq(abi.decode(v, (bytes)), btc, "static Bitcoin address, no lookup");
    }

    function test_defaultEvmCoinType_goesToGateway() public view {
        EIP3668.Params memory p = _lookupCoin("bob.fkey.eth", 1 << 31);
        assertEq(p.urls[0], STEALTH_GW);
    }

    // Wildcard names: the record is written by the nearest registered ancestor.

    function _setBobRecord() internal {
        setRecord(fluidkey, "bob.fkey.eth", COIN_ETH, META);
    }

    /// @dev Fluidkey writes the record of bob, a username that exists only in its gateway: a
    ///      lying gateway cannot redirect bob's payments.
    function test_wildcardRecord_verifies() public {
        _setBobRecord();
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
        _setBobRecord();
        bytes memory v = resolver.resolve(
            dns("bob.fkey.eth"), abi.encodeCall(IDataResolver.data, (bobNode, stealthKey(COIN_ETH)))
        );
        assertEq(abi.decode(v, (bytes)), META, "served");
        (bool ok,) = callback(_lookup("bob.fkey.eth"), abi.encode(makeAddr("attacker"), VD));
        assertFalse(ok, "verified against it");
    }

    /// @dev Registration takes authority: a record Fluidkey wrote for a username before it was
    ///      registered is not read once it is, and Fluidkey cannot write it afterwards.
    function test_registrationTakesAuthority() public {
        setRecord(fluidkey, "carol.fkey.eth", COIN_ETH, META);
        address carol = makeAddr("carol");
        vm.prank(fluidkey);
        fkeyRegistry.register(
            "carol",
            carol,
            IRegistry(address(0)),
            address(resolver),
            RegistryRolesLib.ROLE_SET_RESOLVER,
            expiry
        );
        address any = makeAddr("any");
        (bool ok, bytes memory v) = callback(_lookup("carol.fkey.eth"), abi.encode(any, VD));
        assertTrue(ok);
        assertEq(_resolved(v), any, "unverified: carol has no record of her own");

        vm.prank(fluidkey);
        vm.expectRevert(
            abi.encodeWithSelector(
                StealthResolver.Unauthorized.selector, dns("carol.fkey.eth"), fluidkey
            )
        );
        resolver.setStealthRecord(dns("carol.fkey.eth"), COIN_ETH, META);
    }

    /// @dev Two levels: sub.alice.fkey.eth is written by alice and takes fkey.eth's URLs.
    function test_wildcardRecord_twoLevels() public {
        setRecord(alice, "sub.alice.fkey.eth", COIN_ETH, META);
        EIP3668.Params memory p = _lookup("sub.alice.fkey.eth");
        assertEq(p.urls[0], STEALTH_GW);
        (bool ok,) = callback(p, abi.encode(makeAddr("attacker"), VD));
        assertFalse(ok, "verified against the record alice wrote");
    }

    /// @dev The record does not depend on the records resolver: an offchain one serves the other
    ///      records while the stealth record verifies.
    function test_offchainRecordsResolver_verifies() public {
        MockOffchainRecords offchain = new MockOffchainRecords();
        vm.prank(fluidkey);
        resolver.setConfig(dns("fkey.eth"), address(offchain), urls(STEALTH_GW));
        _setBobRecord();
        (bool ok,) = callback(_lookup("bob.fkey.eth"), abi.encode(makeAddr("attacker"), VD));
        assertFalse(ok, "verified");
        (ok,) = callback(_lookup("bob.fkey.eth"), abi.encode(_derived(), VD));
        assertTrue(ok);
    }

    // Malformed records (ENSIP-30 Section 1), refused when written.

    function _expectMalformed(bytes memory value) internal {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(StealthResolver.MalformedRecord.selector, value));
        resolver.setStealthRecord(dns("alice.fkey.eth"), COIN_ETH, value);
    }

    /// @dev Without this check the verifier would get an empty meta-address, i.e. unverified mode.
    function test_flagOnlyRecordRefused() public {
        _expectMalformed(hex"01");
    }

    function test_reservedFlagBitsRefused() public {
        bytes memory value = META;
        value[0] = 0x03;
        _expectMalformed(value);
        value[0] = 0x80;
        _expectMalformed(value);
    }

    /// @dev Scheme-specific shape is the verifier's to check, when verifying (fail closed).
    function test_badLengthRejectedByVerifier() public {
        setRecord(alice, "alice.fkey.eth", COIN_ETH, hex"01aabb");
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

    /// @dev Out-of-flow verification covers wildcard names too.
    function test_verifyStealthResolution_wildcardName() public {
        _setBobRecord();
        assertEq(resolver.verifyStealthResolution(bobNode, COIN_ETH, _derived(), VD), _derived());
    }

    function test_verifyStealthResolution_missingRecordReverts() public {
        vm.expectRevert(
            abi.encodeWithSelector(StealthResolver.NoStealthRecord.selector, bobNode, COIN_ETH)
        );
        resolver.verifyStealthResolution(bobNode, COIN_ETH, address(1), "");
    }
}
