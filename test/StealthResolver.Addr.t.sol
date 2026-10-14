// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {EIP3668} from "@ens/contracts/ccipRead/EIP3668.sol";
import {IAddrResolver} from "@ens/contracts/resolvers/profiles/IAddrResolver.sol";
import {IAddressResolver} from "@ens/contracts/resolvers/profiles/IAddressResolver.sol";
import {IDataResolver} from "@ens/contracts/resolvers/profiles/IDataResolver.sol";
import {IExtendedResolver} from "@ens/contracts/resolvers/profiles/IExtendedResolver.sol";
import {IRegistry} from "~src/registry/interfaces/IRegistry.sol";
import {RegistryRolesLib} from "~src/registry/libraries/RegistryRolesLib.sol";

import {IStealthResolver} from "../src/interfaces/IStealthResolver.sol";

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

    function _data(bytes32 n, uint256 coinType) internal view returns (bytes memory) {
        bytes memory v = resolver.resolve(
            dns("alice.fkey.eth"), abi.encodeCall(IDataResolver.data, (n, stealthKey(coinType)))
        );
        return abi.decode(v, (bytes));
    }

    function _resolved(bytes memory v) internal pure returns (address) {
        return abi.decode(abi.decode(v, (bytes)), (address));
    }

    function _derived() internal view returns (address) {
        return verifier.derive(metaWithoutFlag(), VD);
    }

    /// @dev `verifyStealthResolution` calldata for `resolve()`, the only way it is answered.
    function _verifyCall(string memory name, uint256 coinType, address claimed)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodeCall(
            IStealthResolver.verifyStealthResolution, (node(name), coinType, claimed, VD)
        );
    }

    function _verify(string memory name, uint256 coinType, address claimed)
        internal
        view
        returns (address)
    {
        return
            abi.decode(resolver.resolve(dns(name), _verifyCall(name, coinType, claimed)), (address));
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
        setChain(alice, "alice.fkey.eth", COIN_ETH, true);
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

    // Chain lists (static on unlisted chains).

    /// @dev Only listed chains are stealth: Base is not on alice's list, so her static Base
    ///      address is forwarded, while Ethereum goes to the gateway and verifies.
    function test_unlistedChain_staticAddressForwarded() public {
        setUpAliceVerified(COIN_ETH);
        bytes memory baseStatic = abi.encodePacked(makeAddr("aliceBase"));
        vm.prank(alice);
        aliceRecords.setAddr(aliceNode, COIN_BASE, baseStatic);
        bytes memory v = resolver.resolve(
            dns("alice.fkey.eth"), abi.encodeCall(IAddressResolver.addr, (aliceNode, COIN_BASE))
        );
        assertEq(abi.decode(v, (bytes)), baseStatic, "Base: static");
        assertEq(_lookup("alice.fkey.eth").urls[0], STEALTH_GW, "Ethereum: gateway");
    }

    /// @dev A listed chain is stealth even if a static address is set for it.
    function test_listedChain_stealthWinsOverStatic() public {
        setUpAliceVerified(COIN_ETH);
        vm.prank(alice);
        aliceRecords.setAddr(aliceNode, makeAddr("aliceStatic"));
        (bool ok, bytes memory v) = callback(_lookup("alice.fkey.eth"), abi.encode(_derived(), VD));
        assertTrue(ok);
        assertEq(_resolved(v), _derived());
    }

    /// @dev Removing a chain falls back to the static address, never to unverified mode.
    function test_removedChain_fallsBackToStatic() public {
        setUpAliceVerified(COIN_ETH);
        address aliceStatic = makeAddr("aliceStatic");
        vm.prank(alice);
        aliceRecords.setAddr(aliceNode, aliceStatic);
        setChain(alice, "alice.fkey.eth", COIN_ETH, false);
        bytes memory v =
            resolver.resolve(dns("alice.fkey.eth"), abi.encodeCall(IAddrResolver.addr, (aliceNode)));
        assertEq(abi.decode(v, (address)), aliceStatic);
    }

    /// @dev A chain removed between lookup and callback: the gateway's answer is not accepted,
    ///      verified or not.
    function test_chainRemovedBetweenLookupAndCallback() public {
        EIP3668.Params memory p = _lookup("bob.fkey.eth");
        setChain(fluidkey, "fkey.eth", COIN_ETH, false);
        (bool ok, bytes memory v) = callback(p, abi.encode(makeAddr("any"), VD));
        assertFalse(ok);
        assertEq(v, abi.encodeWithSelector(StealthResolver.ChainNotStealth.selector, COIN_ETH));
    }

    /// @dev Gateway URLs cleared between lookup and callback: the same.
    function test_gatewayRemovedBetweenLookupAndCallback() public {
        EIP3668.Params memory p = _lookup("bob.fkey.eth");
        setConfig(fluidkey, "fkey.eth", address(fkeyRecords), "");
        (bool ok, bytes memory v) = callback(p, abi.encode(makeAddr("any"), VD));
        assertFalse(ok);
        assertEq(v, abi.encodeWithSelector(StealthResolver.ChainNotStealth.selector, COIN_ETH));
    }

    /// @dev The record is served only for listed chains.
    function test_recordServedOnlyForListedChains() public {
        setUpAliceVerified(COIN_ETH);
        assertEq(_data(aliceNode, COIN_ETH), META);
        assertEq(_data(aliceNode, COIN_BASE).length, 0);
        address derived = _derived();
        vm.expectRevert(
            abi.encodeWithSelector(StealthResolver.NoStealthRecord.selector, aliceNode, COIN_BASE)
        );
        resolver.resolve(dns("alice.fkey.eth"), _verifyCall("alice.fkey.eth", COIN_BASE, derived));
    }

    function test_verified_recordRemovedBetweenLookupAndCallback() public {
        setUpAliceVerified(COIN_ETH);
        EIP3668.Params memory p = _lookup("alice.fkey.eth");
        setMeta(alice, "alice.fkey.eth", "");
        (bool ok,) = callback(p, abi.encode(makeAddr("any"), VD));
        assertTrue(ok, "record read at callback time");
    }

    function test_verified_recordAddedBetweenLookupAndCallback() public {
        setConfig(alice, "alice.fkey.eth", address(aliceRecords), STEALTH_GW);
        setChain(alice, "alice.fkey.eth", COIN_ETH, true);
        EIP3668.Params memory p = _lookup("alice.fkey.eth");
        setMeta(alice, "alice.fkey.eth", META);
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

    /// @dev A registered name without gateway URLs is never sent to an ancestor's gateway: its
    ///      static address is forwarded, even though fkey.eth has a gateway.
    function test_registeredNameDoesNotInheritGateway() public {
        address aliceStatic = makeAddr("aliceStatic");
        vm.prank(alice);
        aliceRecords.setAddr(aliceNode, aliceStatic);
        setConfig(alice, "alice.fkey.eth", address(aliceRecords), "");
        bytes memory v =
            resolver.resolve(dns("alice.fkey.eth"), abi.encodeCall(IAddrResolver.addr, (aliceNode)));
        assertEq(abi.decode(v, (address)), aliceStatic);
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

    function test_defaultEvmCoinType_goesToGateway() public {
        setChain(fluidkey, "fkey.eth", 1 << 31, true);
        EIP3668.Params memory p = _lookupCoin("bob.fkey.eth", 1 << 31);
        assertEq(p.urls[0], STEALTH_GW);
    }

    // Wildcard names: the record is written by the nearest registered ancestor.

    function _setBobRecord() internal {
        setMeta(fluidkey, "bob.fkey.eth", META);
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
        setMeta(fluidkey, "carol.fkey.eth", META);
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
        setConfig(carol, "carol.fkey.eth", address(0), STEALTH_GW);
        setChain(carol, "carol.fkey.eth", COIN_ETH, true);
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
        resolver.setMetaAddress(dns("carol.fkey.eth"), META);
    }

    /// @dev Two levels: sub.alice.fkey.eth is written by alice and takes fkey.eth's URLs.
    function test_wildcardRecord_twoLevels() public {
        setConfig(alice, "alice.fkey.eth", address(aliceRecords), STEALTH_GW);
        setChain(alice, "alice.fkey.eth", COIN_ETH, true);
        setMeta(alice, "sub.alice.fkey.eth", META);
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
        resolver.setMetaAddress(dns("alice.fkey.eth"), value);
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
        setConfig(alice, "alice.fkey.eth", address(aliceRecords), STEALTH_GW);
        setChain(alice, "alice.fkey.eth", COIN_ETH, true);
        setMeta(alice, "alice.fkey.eth", hex"01aabb");
        (bool ok, bytes memory v) =
            callback(_lookup("alice.fkey.eth"), abi.encode(makeAddr("any"), VD));
        assertFalse(ok);
        assertEq(bytes4(v), MockVerifier.MalformedMetaAddress.selector);
    }

    function test_malformedResponseReverts() public view {
        (bool ok,) = callback(_lookup("bob.fkey.eth"), hex"1234");
        assertFalse(ok);
    }

    // verifyStealthResolution (Section 5), through resolve().

    function test_verifyThroughResolve_registeredName() public {
        setUpAliceVerified(COIN_ETH);
        address derived = _derived();
        assertEq(_verify("alice.fkey.eth", COIN_ETH, derived), derived);
        vm.expectRevert(
            abi.encodeWithSelector(
                StealthResolver.StealthAddressMismatch.selector, address(0xBAD), derived
            )
        );
        resolver.resolve(
            dns("alice.fkey.eth"), _verifyCall("alice.fkey.eth", COIN_ETH, address(0xBAD))
        );
    }

    /// @dev The record is located by name, as for every other query: out-of-flow verification
    ///      covers wildcard names too.
    function test_verifyThroughResolve() public {
        _setBobRecord();
        address derived = _derived();
        bytes memory call = abi.encodeCall(
            IStealthResolver.verifyStealthResolution, (bobNode, COIN_ETH, derived, VD)
        );
        bytes memory v = resolver.resolve(dns("bob.fkey.eth"), call);
        assertEq(abi.decode(v, (address)), derived);

        call = abi.encodeCall(
            IStealthResolver.verifyStealthResolution, (bobNode, COIN_ETH, address(0xBAD), VD)
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                StealthResolver.StealthAddressMismatch.selector, address(0xBAD), derived
            )
        );
        resolver.resolve(dns("bob.fkey.eth"), call);
    }

    function test_verifyThroughResolve_nodeMustMatchName() public {
        bytes memory call = abi.encodeCall(
            IStealthResolver.verifyStealthResolution, (aliceNode, COIN_ETH, address(1), VD)
        );
        vm.expectRevert(
            abi.encodeWithSelector(StealthResolver.NodeMismatch.selector, aliceNode, bobNode)
        );
        resolver.resolve(dns("bob.fkey.eth"), call);
    }

    function test_verifyThroughResolve_missingRecordReverts() public {
        vm.expectRevert(
            abi.encodeWithSelector(StealthResolver.NoStealthRecord.selector, bobNode, COIN_ETH)
        );
        resolver.resolve(dns("bob.fkey.eth"), _verifyCall("bob.fkey.eth", COIN_ETH, address(1)));
    }
}
