// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {EIP3668} from "@ens/contracts/ccipRead/EIP3668.sol";
import {IBatchGateway} from "@ens/contracts/ccipRead/IBatchGateway.sol";

import {IMulticallable} from "@ens/contracts/resolvers/IMulticallable.sol";
import {IAddrResolver} from "@ens/contracts/resolvers/profiles/IAddrResolver.sol";
import {IAddressResolver} from "@ens/contracts/resolvers/profiles/IAddressResolver.sol";
import {IContentHashResolver} from "@ens/contracts/resolvers/profiles/IContentHashResolver.sol";
import {IDataResolver} from "@ens/contracts/resolvers/profiles/IDataResolver.sol";
import {ITextResolver} from "@ens/contracts/resolvers/profiles/ITextResolver.sol";
import {IUniversalResolver} from "@ens/contracts/universalResolver/IUniversalResolver.sol";
import {NameCoder} from "@ens/contracts/utils/NameCoder.sol";
import {IRegistry} from "~src/registry/interfaces/IRegistry.sol";
import {RegistryRolesLib} from "~src/registry/libraries/RegistryRolesLib.sol";
import {PublicResolverV2} from "~src/resolver/PublicResolverV2.sol";

import {StealthResolver} from "../src/StealthResolver.sol";
import {MockOffchainRecords} from "./mocks/MockOffchainRecords.sol";
import {StealthResolverFixture} from "./utils/StealthResolverFixture.sol";

/// @dev Everything that is not a stealth address or the stealth record is forwarded, unchanged,
///      to the effective records resolver: an unmodified PermissionedResolver, PublicResolverV2 or
///      offchain resolver. The stealth record is answered from StealthResolver's own storage.
contract StealthResolverForwardTest is StealthResolverFixture {
    function _data(string memory name, string memory key) internal view returns (bytes memory) {
        bytes memory v =
            resolver.resolve(dns(name), abi.encodeCall(IDataResolver.data, (node(name), key)));
        return abi.decode(v, (bytes));
    }

    function _text(string memory name, string memory key) internal view returns (string memory) {
        bytes memory v =
            resolver.resolve(dns(name), abi.encodeCall(ITextResolver.text, (node(name), key)));
        return abi.decode(v, (string));
    }

    function test_ownRecordsResolver() public {
        setConfig(alice, "alice.fkey.eth", address(aliceRecords), "");
        vm.startPrank(alice);
        aliceRecords.setText(aliceNode, "url", "https://alice.example");
        aliceRecords.setContenthash(aliceNode, hex"e301");
        vm.stopPrank();
        assertEq(_text("alice.fkey.eth", "url"), "https://alice.example");
        bytes memory v = resolver.resolve(
            dns("alice.fkey.eth"), abi.encodeCall(IContentHashResolver.contenthash, (aliceNode))
        );
        assertEq(abi.decode(v, (bytes)), hex"e301");
    }

    function test_wildcardInheritsParentsRecordsResolver() public {
        vm.prank(fluidkey);
        fkeyRecords.setText(bobNode, "avatar", "ipfs://bob");
        assertEq(_text("bob.fkey.eth", "avatar"), "ipfs://bob");
    }

    function test_stealthRecordServed() public {
        setUpAliceVerified(COIN_ETH);
        assertEq(
            _data("alice.fkey.eth", stealthKey(COIN_ETH)),
            META,
            "ENSIP-30 Section 1 record served through resolve()"
        );
        assertEq(_data("alice.fkey.eth", stealthKey(COIN_BASE)).length, 0, "other coin type");
    }

    /// @dev With a records resolver that answers offchain, the stealth record is still served
    ///      from storage, without a lookup; other data keys go offchain.
    function test_offchainRecordsResolver_stealthRecordFromStorage() public {
        MockOffchainRecords offchain = new MockOffchainRecords();
        vm.prank(fluidkey);
        resolver.setConfig(dns("fkey.eth"), address(offchain), urls(STEALTH_GW));
        setMeta(fluidkey, "bob.fkey.eth", META);
        assertEq(_data("bob.fkey.eth", stealthKey(COIN_ETH)), META);
        expectLookup(
            address(resolver),
            abi.encodeCall(
                resolver.resolve,
                (dns("bob.fkey.eth"), abi.encodeCall(IDataResolver.data, (bobNode, "other")))
            )
        );
    }

    /// @dev Only this scheme's key in canonical form is the record; anything else is forwarded.
    function test_stealthKeyParsing() public {
        setConfig(alice, "alice.fkey.eth", address(aliceRecords), "");
        string[7] memory others = [
            "stealth-meta-address[1][060]",
            "stealth-meta-address[1][0x3c]",
            "stealth-meta-address[1][]",
            "stealth-meta-address[1][60",
            "stealth-meta-address[2][60]",
            "stealth-meta-address[1][-60]",
            // one past type(uint256).max
            "stealth-meta-address[1][115792089237316195423570985008687907853269984665640564039457584007913129639936]"
        ];
        vm.startPrank(alice);
        for (uint256 i; i < others.length; ++i) {
            aliceRecords.setData(aliceNode, others[i], abi.encode(i));
        }
        vm.stopPrank();
        for (uint256 i; i < others.length; ++i) {
            assertEq(_data("alice.fkey.eth", others[i]), abi.encode(i), others[i]);
        }

        // The canonical key of the largest coin type is parsed as the record, not forwarded: not
        // an EVM chain, so never listed, so empty.
        string memory largest = stealthKey(type(uint256).max); // external call: before vm.prank
        vm.prank(alice);
        aliceRecords.setData(aliceNode, largest, META);
        assertEq(
            _data("alice.fkey.eth", stealthKey(type(uint256).max)).length,
            0,
            "largest coin type is the record"
        );
    }

    function test_stealthRecord_nodeMustMatchName() public {
        string memory key = stealthKey(COIN_ETH);
        vm.expectRevert(
            abi.encodeWithSelector(StealthResolver.NodeMismatch.selector, aliceNode, bobNode)
        );
        resolver.resolve(dns("bob.fkey.eth"), abi.encodeCall(IDataResolver.data, (aliceNode, key)));
    }

    /// @dev The stealth key written into the records resolver with standard tooling is not the
    ///      record: StealthResolver serves and verifies its own.
    function test_stealthKeyInRecordsResolverIgnored() public {
        string memory key = stealthKey(COIN_ETH);
        vm.prank(alice);
        aliceRecords.setData(aliceNode, key, META);
        setConfig(alice, "alice.fkey.eth", address(aliceRecords), "");
        assertEq(_data("alice.fkey.eth", key).length, 0);
    }

    /// @dev Only `addr`, `addr(coinType)` and `multicall` take the gateway path; other selectors
    ///      are forwarded, so a static address in the records resolver of a gateway-configured
    ///      name is readable through them. Pinned until per-coin-type coexistence is decided.
    function test_otherSelectorsReachStaticAddress() public {
        vm.prank(fluidkey);
        fkeyRecords.setAddr(bobNode, address(0xBEEF));
        bytes[] memory calls = new bytes[](1);
        calls[0] = abi.encodeCall(IAddrResolver.addr, (bobNode));
        bytes memory v = resolver.resolve(
            dns("bob.fkey.eth"),
            abi.encodeCall(IMulticallable.multicallWithNodeCheck, (bobNode, calls))
        );
        assertEq(abi.decode(abi.decode(v, (bytes[]))[0], (address)), address(0xBEEF));
    }

    function test_addressWithoutGatewayForwarded() public {
        vm.prank(fluidkey);
        resolver.setConfig(dns("fkey.eth"), address(fkeyRecords), new string[](0));
        setConfig(alice, "alice.fkey.eth", address(aliceRecords), "");
        vm.prank(alice);
        aliceRecords.setAddr(aliceNode, address(0xBEEF));
        bytes memory v =
            resolver.resolve(dns("alice.fkey.eth"), abi.encodeCall(IAddrResolver.addr, (aliceNode)));
        assertEq(abi.decode(v, (address)), address(0xBEEF));
    }

    function test_noRecordsResolverAnywhere() public {
        bytes memory name = dns("x.other.eth");
        bytes32 n = NameCoder.namehash(name, 0);
        assertEq(
            abi.decode(resolver.resolve(name, abi.encodeCall(IAddrResolver.addr, (n))), (address)),
            address(0)
        );
        assertEq(
            abi.decode(
                resolver.resolve(name, abi.encodeCall(IAddressResolver.addr, (n, COIN_BASE))),
                (bytes)
            ).length,
            0
        );
        string memory key = stealthKey(COIN_ETH);
        assertEq(
            abi.decode(
                resolver.resolve(name, abi.encodeCall(IDataResolver.data, (n, key))), (bytes)
            ).length,
            0,
            "no stealth record"
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                IUniversalResolver.UnsupportedResolverProfile.selector, ITextResolver.text.selector
            )
        );
        resolver.resolve(name, abi.encodeCall(ITextResolver.text, (n, "url")));
    }

    function test_offchainRecordsResolver_roundTrip() public {
        MockOffchainRecords offchain = new MockOffchainRecords();
        vm.prank(fluidkey);
        resolver.setConfig(dns("fkey.eth"), address(offchain), urls(STEALTH_GW));
        bytes memory call = abi.encodeCall(
            resolver.resolve,
            (dns("bob.fkey.eth"), abi.encodeCall(ITextResolver.text, (bobNode, "avatar")))
        );
        // ENS's ResolverCaller routes resolvers without ERC-7996 through the batch gateway,
        // exactly as the UniversalResolver does; the lookup is owned by StealthResolver.
        EIP3668.Params memory p = expectLookup(address(resolver), call);
        assertEq(p.sender, address(resolver));
        assertEq(bytes4(p.callData), IBatchGateway.query.selector);

        recordsAnswer = abi.encode("ipfs://from-gateway");
        (bool ok, bytes memory v) = ccipCall(address(resolver), call);
        assertTrue(ok);
        assertEq(abi.decode(abi.decode(v, (bytes)), (string)), "ipfs://from-gateway");
    }

    /// @dev A name migrated from ENSv1 keeps its records in PublicResolverV2.
    function test_publicResolverV2AsRecordsResolver() public {
        PublicResolverV2 publicResolver =
            new PublicResolverV2(nameWrapper, rootRegistry, contractNamer);
        bytes memory name = registerWrappedETH2LD("migrated", 0);
        bytes32 n = NameCoder.namehash(name, 0);
        ethRegistry.register(
            "migrated",
            testOwner,
            IRegistry(address(0)),
            address(resolver),
            RegistryRolesLib.ROLE_SET_RESOLVER | RegistryRolesLib.ROLE_SET_RESOLVER_ADMIN,
            expiry
        );
        vm.startPrank(testOwner);
        publicResolver.setText(n, "url", "https://migrated.example");
        resolver.setConfig(name, address(publicResolver), new string[](0));
        vm.stopPrank();
        bytes memory v = resolver.resolve(name, abi.encodeCall(ITextResolver.text, (n, "url")));
        assertEq(abi.decode(v, (string)), "https://migrated.example");
    }
}
