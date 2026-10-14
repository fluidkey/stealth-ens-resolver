// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IGatewayProvider} from "@ens/contracts/ccipRead/IGatewayProvider.sol";
import {IDataResolver} from "@ens/contracts/resolvers/profiles/IDataResolver.sol";
import {IRegistry} from "~src/registry/interfaces/IRegistry.sol";

import {StealthResolver} from "../src/StealthResolver.sol";
import {IStealthVerifier} from "../src/interfaces/IStealthVerifier.sol";
import {StealthResolverFixture} from "./utils/StealthResolverFixture.sol";

/// @dev Exposes the key parser.
contract StealthResolverHarness is StealthResolver {
    constructor(IRegistry r, IStealthVerifier v, IGatewayProvider g) StealthResolver(r, v, g) {}

    function parse(string memory key) external view returns (bool, uint256) {
        return _parseStealthKey(key);
    }

    function key(uint256 coinType) external view returns (string memory) {
        return _stealthKey(coinType);
    }
}

contract StealthResolverFuzzTest is StealthResolverFixture {
    StealthResolverHarness internal harness;

    function setUp() public override {
        super.setUp();
        harness = new StealthResolverHarness(rootRegistry, verifier, batchGatewayProvider);
    }

    /// @dev Every coin type's canonical key is the record through `resolve()`: the meta-address
    ///      for the listed chain, empty for every other.
    function testFuzz_recordServedOnlyForListedChain(uint256 coinType) public {
        setChain(alice, "alice.fkey.eth", COIN_BASE, true);
        setMeta(alice, "alice.fkey.eth", META);
        bytes memory v = resolver.resolve(
            dns("alice.fkey.eth"),
            abi.encodeCall(IDataResolver.data, (aliceNode, stealthKey(coinType)))
        );
        assertEq(abi.decode(v, (bytes)), coinType == COIN_BASE ? META : bytes(""));
    }

    /// @dev Only canonical keys parse: anything after the prefix that parses is the canonical key
    ///      of the coin type it parses to.
    function testFuzz_onlyCanonicalKeysParse(bytes memory suffix) public view {
        string memory k = string.concat("stealth-meta-address[1][", string(suffix));
        (bool ok, uint256 coinType) = harness.parse(k);
        if (ok) assertEq(k, harness.key(coinType));
    }

    /// @dev Leading zeros never parse.
    function testFuzz_leadingZerosRejected(uint256 coinType, uint8 zeros) public view {
        zeros = uint8(bound(zeros, 1, 5));
        string memory digits = vm.toString(coinType);
        for (uint256 i; i < zeros; ++i) {
            digits = string.concat("0", digits);
        }
        (bool ok,) = harness.parse(string.concat("stealth-meta-address[1][", digits, "]"));
        assertFalse(ok);
    }

    /// @dev Written iff empty, or a flag byte with reserved bits zero and a non-empty meta-address.
    function testFuzz_writeValidation(bytes memory value) public {
        bool wellFormed = value.length == 0 || (value.length >= 2 && uint8(value[0]) & 0xfe == 0);
        vm.prank(alice);
        if (!wellFormed) {
            vm.expectRevert(abi.encodeWithSelector(StealthResolver.MalformedRecord.selector, value));
        }
        resolver.setMetaAddress(dns("alice.fkey.eth"), value);
    }
}
