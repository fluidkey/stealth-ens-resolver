// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {CCIPBatcher} from "@ens/contracts/ccipRead/CCIPBatcher.sol";
import {EIP3668} from "@ens/contracts/ccipRead/EIP3668.sol";
import {IMulticallable} from "@ens/contracts/resolvers/IMulticallable.sol";
import {IAddrResolver} from "@ens/contracts/resolvers/profiles/IAddrResolver.sol";
import {IContentHashResolver} from "@ens/contracts/resolvers/profiles/IContentHashResolver.sol";
import {IDataResolver} from "@ens/contracts/resolvers/profiles/IDataResolver.sol";
import {ITextResolver} from "@ens/contracts/resolvers/profiles/ITextResolver.sol";

import {StealthResolver} from "../src/StealthResolver.sol";
import {IStealthResolver} from "../src/interfaces/IStealthResolver.sol";
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

    /// @dev Out-of-flow verification of a wildcard name's past resolution, through the
    ///      UniversalResolver: located by name, no CCIP-Read needed.
    function test_ur_verifyStealthResolution() public {
        vm.prank(fluidkey);
        resolver.setMetaAddress(dns("bob.fkey.eth"), META);
        address derived = verifier.derive(metaWithoutFlag(), VD);
        (bool ok, bytes memory result) = _ur(
            "bob.fkey.eth",
            abi.encodeCall(
                IStealthResolver.verifyStealthResolution, (bobNode, COIN_ETH, derived, VD)
            )
        );
        assertTrue(ok);
        assertEq(abi.decode(result, (address)), derived);

        (ok,) = _ur(
            "bob.fkey.eth",
            abi.encodeCall(
                IStealthResolver.verifyStealthResolution, (bobNode, COIN_ETH, address(0xBAD), VD)
            )
        );
        assertFalse(ok, "mismatch reverts");
    }

    // resolve(name, multicall(...)) batches.

    function test_multicall_mixesForwardedAndStealth() public {
        vm.startPrank(fluidkey);
        fkeyRecords.setText(dns("bob.fkey.eth"), "avatar", "ipfs://bob");
        fkeyRecords.setContenthash(dns("bob.fkey.eth"), hex"e301");
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

    /// @dev The node-checked form is split the same way; the node is checked against the name.
    function test_multicallWithNodeCheck_mixesForwardedAndStealth() public {
        vm.prank(fluidkey);
        fkeyRecords.setText(dns("bob.fkey.eth"), "avatar", "ipfs://bob");
        gwClaimed = makeAddr("chosen");
        gwVerificationData = "ok";

        bytes[] memory calls = new bytes[](2);
        calls[0] = abi.encodeCall(ITextResolver.text, (bobNode, "avatar"));
        calls[1] = abi.encodeCall(IAddrResolver.addr, (bobNode));
        (bool ok, bytes memory v) = ccipCall(
            address(resolver),
            abi.encodeCall(
                resolver.resolve,
                (
                    dns("bob.fkey.eth"),
                    abi.encodeCall(IMulticallable.multicallWithNodeCheck, (bobNode, calls))
                )
            )
        );
        assertTrue(ok);
        bytes[] memory results = abi.decode(abi.decode(v, (bytes)), (bytes[]));
        assertEq(abi.decode(results[0], (string)), "ipfs://bob");
        assertEq(abi.decode(results[1], (address)), gwClaimed);
    }

    /// @dev A batch gateway may fail an item, but never choose what it reads as: its bytes are
    ///      wrapped even when they start with a selector ENS's default passes through, so a client
    ///      that skips the error marker reads no address.
    function test_multicall_batchGatewayFailureIsWrapped() public {
        setUpAliceVerified(COIN_ETH);
        bytes[] memory calls = new bytes[](1);
        calls[0] = abi.encodeCall(IAddrResolver.addr, (aliceNode));
        bytes memory call =
            abi.encodeCall(resolver.resolve, (dns("alice.fkey.eth"), _multicall(calls)));
        address attacker = makeAddr("attacker");
        bytes[2] memory payloads = [
            abi.encodePacked(bytes12(0), attacker, bytes4(0)),
            abi.encodePacked(bytes4(0x08c379a0), bytes8(0), attacker) // Error(string)
        ];
        for (uint256 i; i < payloads.length; ++i) {
            EIP3668.Params memory p = expectLookup(address(resolver), call);
            bool[] memory failures = new bool[](1);
            failures[0] = true;
            bytes[] memory responses = new bytes[](1);
            responses[0] = payloads[i];
            (bool ok, bytes memory v) = callback(p, abi.encode(failures, responses));
            assertTrue(ok);
            bytes memory item = abi.decode(abi.decode(v, (bytes)), (bytes[]))[0];
            assertEq(bytes4(item), CCIPBatcher.UnsafeBatchGatewayResponse.selector);
            assertEq(item.length % 32, 4, "marked as an error");
            assertEq(address(uint160(uint256(bytes32(item)))), address(0), "reads as no address");
        }
    }

    function test_multicall_failingItemCarriesItsError() public {
        setUpAliceVerified(COIN_ETH);
        vm.prank(alice);
        aliceRecords.setText(dns("alice.fkey.eth"), "url", "https://alice.example");
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

    /// @dev A username that exists only in Fluidkey's gateway, verified against the record
    ///      Fluidkey published for it onchain; the record reads the same through the UR.
    function test_ur_wildcardUsername_verified() public {
        string memory key = stealthKey(COIN_ETH);
        setMeta(fluidkey, "bob.fkey.eth", META);

        (bool ok, bytes memory result) =
            _ur("bob.fkey.eth", abi.encodeCall(IDataResolver.data, (bobNode, key)));
        assertTrue(ok);
        assertEq(abi.decode(result, (bytes)), META, "record");

        bytes memory data = abi.encodeCall(IAddrResolver.addr, (bobNode));
        gwClaimed = verifier.derive(metaWithoutFlag(), VD);
        gwVerificationData = VD;
        (ok, result) = _ur("bob.fkey.eth", data);
        assertTrue(ok, "honest gateway");
        assertEq(abi.decode(result, (address)), gwClaimed);

        gwClaimed = makeAddr("attacker");
        (ok,) = _ur("bob.fkey.eth", data);
        assertFalse(ok, "lying gateway does not resolve");
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

    /// @dev Fluidkey's setup: profile records from an offchain records resolver, usernames
    ///      verified against records stored in StealthResolver.
    function test_ur_offchainRecords_verifiedUsername() public {
        MockOffchainRecords offchain = new MockOffchainRecords();
        vm.prank(fluidkey);
        resolver.setConfig(dns("fkey.eth"), address(offchain), urls(STEALTH_GW));
        setMeta(fluidkey, "bob.fkey.eth", META);

        recordsAnswer = abi.encode("ipfs://from-gateway");
        (bool ok, bytes memory result) =
            _ur("bob.fkey.eth", abi.encodeCall(ITextResolver.text, (bobNode, "avatar")));
        assertTrue(ok);
        assertEq(abi.decode(result, (string)), "ipfs://from-gateway");

        bytes memory data = abi.encodeCall(IAddrResolver.addr, (bobNode));
        gwClaimed = verifier.derive(metaWithoutFlag(), VD);
        gwVerificationData = VD;
        (ok,) = _ur("bob.fkey.eth", data);
        assertTrue(ok, "honest gateway");
        gwClaimed = makeAddr("attacker");
        (ok,) = _ur("bob.fkey.eth", data);
        assertFalse(ok, "lying gateway does not resolve");
    }

    function test_ur_multicall() public {
        vm.prank(fluidkey);
        fkeyRecords.setText(dns("bob.fkey.eth"), "avatar", "ipfs://bob");
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
