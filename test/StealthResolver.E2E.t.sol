// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IMulticallable} from "@ens/contracts/resolvers/IMulticallable.sol";
import {IAddrResolver} from "@ens/contracts/resolvers/profiles/IAddrResolver.sol";
import {IContentHashResolver} from "@ens/contracts/resolvers/profiles/IContentHashResolver.sol";
import {ITextResolver} from "@ens/contracts/resolvers/profiles/ITextResolver.sol";

import {StealthResolver} from "../src/StealthResolver.sol";
import {MockOffchainRecords} from "./mocks/MockOffchainRecords.sol";
import {StealthResolverFixture} from "./utils/StealthResolverFixture.sol";

/// @dev Whole resolutions: `resolve(name, multicall(...))` batches, and resolution through ENS's
///      UniversalResolverV2 the way viem and ethers resolve, with simulated gateways.
contract StealthResolverE2ETest is StealthResolverFixture {
    bytes internal constant VD = hex"c0ffee";

    function _multicall(bytes[] memory calls) internal pure returns (bytes memory) {
        return abi.encodeCall(IMulticallable.multicall, (calls));
    }

    /// @dev UniversalResolverV2.resolve(name, data) followed to the end; returns the record.
    function _ur(string memory name, bytes memory data)
        internal
        view
        returns (bool ok, bytes memory result)
    {
        bytes memory v;
        (ok, v) = ccipCall(
            address(universalResolver), abi.encodeCall(universalResolver.resolve, (dns(name), data))
        );
        if (ok) {
            address resolvedBy;
            (result, resolvedBy) = abi.decode(v, (bytes, address));
            assertEq(resolvedBy, address(resolver), "resolved by StealthResolver");
        }
    }

    // resolve(name, multicall(...)) batches.

    function test_multicall_mixesForwardedAndStealth() public {
        vm.startPrank(fluidkey);
        fkeyRecords.setText(bobNode, "avatar", "ipfs://bob");
        fkeyRecords.setContenthash(bobNode, hex"e301");
        vm.stopPrank();
        gwClaimed = makeAddr("chosen");
        gwVerificationData = "ok";

        bytes[] memory calls = new bytes[](3);
        calls[0] = abi.encodeCall(ITextResolver.text, (bobNode, "avatar"));
        calls[1] = abi.encodeCall(IAddrResolver.addr, (bobNode));
        calls[2] = abi.encodeCall(IContentHashResolver.contenthash, (bobNode));
        (bool ok, bytes memory v) = ccipCall(
            address(resolver),
            abi.encodeCall(resolver.resolve, (dns("bob.fkey.eth"), _multicall(calls)))
        );
        assertTrue(ok);
        bytes[] memory results = abi.decode(abi.decode(v, (bytes)), (bytes[]));
        assertEq(abi.decode(results[0], (string)), "ipfs://bob");
        assertEq(abi.decode(results[1], (address)), gwClaimed);
        assertEq(abi.decode(results[2], (bytes)), hex"e301");
    }

    function test_multicall_failingItemCarriesItsError() public {
        setUpAliceVerified(COIN_ETH);
        vm.prank(alice);
        aliceRecords.setText(aliceNode, "url", "https://alice.example");
        gwClaimed = makeAddr("attacker"); // lying gateway: the address item fails, the rest resolves
        gwVerificationData = VD;

        bytes[] memory calls = new bytes[](2);
        calls[0] = abi.encodeCall(ITextResolver.text, (aliceNode, "url"));
        calls[1] = abi.encodeCall(IAddrResolver.addr, (aliceNode));
        (bool ok, bytes memory v) = ccipCall(
            address(resolver),
            abi.encodeCall(resolver.resolve, (dns("alice.fkey.eth"), _multicall(calls)))
        );
        assertTrue(ok);
        bytes[] memory results = abi.decode(abi.decode(v, (bytes)), (bytes[]));
        assertEq(abi.decode(results[0], (string)), "https://alice.example");
        assertEq(bytes4(results[1]), StealthResolver.StealthAddressMismatch.selector);
    }

    // Through UniversalResolverV2.

    function test_ur_wildcardUsername_unverified() public {
        gwClaimed = makeAddr("chosen");
        gwVerificationData = "ok";
        (bool ok, bytes memory result) =
            _ur("bob.fkey.eth", abi.encodeCall(IAddrResolver.addr, (bobNode)));
        assertTrue(ok);
        assertEq(abi.decode(result, (address)), gwClaimed);
    }

    function test_ur_registeredName_verified() public {
        setUpAliceVerified(COIN_ETH);
        bytes memory data = abi.encodeCall(IAddrResolver.addr, (aliceNode));

        gwClaimed = verifier.derive(metaWithoutFlag(), VD);
        gwVerificationData = VD;
        (bool ok, bytes memory result) = _ur("alice.fkey.eth", data);
        assertTrue(ok, "honest gateway");
        assertEq(abi.decode(result, (address)), gwClaimed);

        gwClaimed = makeAddr("attacker");
        (ok,) = _ur("alice.fkey.eth", data);
        assertFalse(ok, "lying gateway does not resolve");
    }

    function test_ur_offchainRecordsForWildcardName() public {
        MockOffchainRecords offchain = new MockOffchainRecords();
        vm.prank(fluidkey);
        resolver.setConfig(dns("fkey.eth"), address(offchain), urls(STEALTH_GW));
        recordsAnswer = abi.encode("ipfs://from-gateway");
        (bool ok, bytes memory result) =
            _ur("bob.fkey.eth", abi.encodeCall(ITextResolver.text, (bobNode, "avatar")));
        assertTrue(ok);
        assertEq(abi.decode(result, (string)), "ipfs://from-gateway");
    }

    function test_ur_multicall() public {
        vm.prank(fluidkey);
        fkeyRecords.setText(bobNode, "avatar", "ipfs://bob");
        gwClaimed = makeAddr("chosen");
        gwVerificationData = "ok";
        bytes[] memory calls = new bytes[](2);
        calls[0] = abi.encodeCall(ITextResolver.text, (bobNode, "avatar"));
        calls[1] = abi.encodeCall(IAddrResolver.addr, (bobNode));
        (bool ok, bytes memory result) = _ur("bob.fkey.eth", _multicall(calls));
        assertTrue(ok);
        bytes[] memory results = abi.decode(result, (bytes[]));
        assertEq(abi.decode(results[0], (string)), "ipfs://bob");
        assertEq(abi.decode(results[1], (address)), gwClaimed);
    }
}
