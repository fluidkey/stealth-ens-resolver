// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IExtendedResolver} from "@ens/contracts/resolvers/profiles/IExtendedResolver.sol";
import {IUniversalResolver} from "@ens/contracts/universalResolver/IUniversalResolver.sol";
import {BytesUtils} from "@ens/contracts/utils/BytesUtils.sol";
import {NameCoder} from "@ens/contracts/utils/NameCoder.sol";

import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import {IRegistry} from "~src/registry/interfaces/IRegistry.sol";

import {ERC6538Bridge} from "../src/ERC6538Bridge.sol";
import {MockOffchainRecords} from "./mocks/MockOffchainRecords.sol";
import {StealthResolverFixture} from "./utils/StealthResolverFixture.sol";

/// @dev A resolver that answers every query with bytes chosen by the test.
contract MockRawResolver is IExtendedResolver, ERC165 {
    bytes public answer;

    function setAnswer(bytes memory a) external {
        answer = a;
    }

    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return interfaceId == type(IExtendedResolver).interfaceId
            || super.supportsInterface(interfaceId);
    }

    function resolve(bytes calldata, bytes calldata) external view returns (bytes memory) {
        return answer;
    }
}

/// @dev ERC6538Bridge through namechain's UniversalResolverV2 and StealthResolver.
contract ERC6538BridgeTest is StealthResolverFixture {
    ERC6538Bridge internal bridge;

    function setUp() public override {
        super.setUp();
        bridge = new ERC6538Bridge(universalResolver);
    }

    function _of(string memory name) internal view returns (bytes memory) {
        return bridge.stealthMetaAddressOf(dns(name), 1);
    }

    /// @dev A name of its own registered with `resolver` in the .eth registry.
    function _register(string memory label, address nameResolver) internal {
        ethRegistry.register(
            label, makeAddr(label), IRegistry(address(0)), nameResolver, _ethTokenRoles(), expiry
        );
    }

    function test_constructor_rejectsNonContract() public {
        address eoa = makeAddr("eoa");
        vm.expectRevert(
            abi.encodeWithSelector(ERC6538Bridge.InvalidUniversalResolver.selector, eoa)
        );
        new ERC6538Bridge(IUniversalResolver(eoa));
    }

    /// @dev A registered name: the record without its flag byte, two compressed keys.
    function test_registeredName() public {
        setUpAliceVerified(COIN_ETH);
        assertEq(_of("alice.fkey.eth"), metaWithoutFlag());
        assertEq(_of("alice.fkey.eth").length, 66);
    }

    /// @dev A wildcard username, whose record the parent wrote, through ENSIP-10.
    function test_wildcardName() public {
        setMeta(fluidkey, "bob.fkey.eth", META);
        assertEq(_of("bob.fkey.eth"), metaWithoutFlag());
    }

    /// @dev Flag bit 0 clear: the recipient does not detect client-side derivations.
    function test_flagClear_empty() public {
        setUpAliceVerified(COIN_ETH);
        setMeta(alice, "alice.fkey.eth", bytes.concat(hex"00", metaWithoutFlag()));
        assertEq(_of("alice.fkey.eth"), "");
    }

    /// @dev Coin type 60 not enabled: the name has no record for Ethereum.
    function test_ethereumNotListed_empty() public {
        setUpAliceVerified(COIN_BASE);
        assertEq(_of("alice.fkey.eth"), "");
    }

    function test_noRecord_empty() public {
        setConfig(alice, "alice.fkey.eth", address(aliceRecords), STEALTH_GW);
        setChain(alice, "alice.fkey.eth", COIN_ETH, true);
        assertEq(_of("alice.fkey.eth"), "");
    }

    /// @dev Scheme 1 needs 66 bytes after the flag; other schemes' encodings are the caller's.
    function test_schemeOneLength() public {
        setUpAliceVerified(COIN_ETH);
        setMeta(alice, "alice.fkey.eth", hex"01aabbcc");
        assertEq(_of("alice.fkey.eth"), "");
    }

    /// @dev Another scheme's record is whatever the name's resolver serves under its key: here
    ///      StealthResolver forwards it to the records resolver.
    function test_otherScheme_servedByTheNamesResolver() public {
        setUpAliceVerified(COIN_ETH);
        assertEq(bridge.stealthMetaAddressOf(dns("alice.fkey.eth"), 2), "", "unset");
        vm.prank(alice);
        aliceRecords.setData(dns("alice.fkey.eth"), "stealth-meta-address[2][60]", hex"01aabbcc");
        assertEq(bridge.stealthMetaAddressOf(dns("alice.fkey.eth"), 2), hex"aabbcc");
    }

    /// @dev No resolver anywhere up the name: empty, not a revert.
    function test_unknownName_empty() public view {
        assertEq(_of("nobody.eth"), "");
    }

    /// @dev A malformed name is the caller's fault, not a failed lookup: it reverts before
    ///      anything is read. Empty, a label longer than the name, no terminator.
    function test_malformedName_reverts() public {
        bytes[3] memory names = [bytes(hex""), bytes(hex"05abcd"), bytes(hex"03abcdef")];
        for (uint256 i; i < names.length; ++i) {
            vm.expectRevert(abi.encodeWithSelector(NameCoder.DNSDecodingFailed.selector, names[i]));
            bridge.stealthMetaAddressOf(names[i], 1);
        }
    }

    /// @dev A resolver that answers offchain: an onchain caller cannot follow it.
    function test_offchainResolver_empty() public {
        _register("offchain", address(new MockOffchainRecords()));
        assertEq(_of("offchain.eth"), "");
    }

    /// @dev Whatever a resolver answers, malformed or not, the bridge returns empty or a record.
    function test_malformedAnswers_empty() public {
        MockRawResolver raw = new MockRawResolver();
        _register("raw", address(raw));
        bytes[5] memory answers = [
            bytes(hex"01"),
            abi.encodePacked(uint256(64), uint256(67)),
            abi.encodePacked(uint256(32), uint256(1000), bytes32(0)),
            abi.encode(bytes.concat(hex"02", metaWithoutFlag())),
            abi.encode(bytes(hex"01"))
        ];
        for (uint256 i; i < answers.length; ++i) {
            raw.setAnswer(answers[i]);
            assertEq(_of("raw.eth"), "", vm.toString(i));
        }
        raw.setAnswer(abi.encode(META));
        assertEq(_of("raw.eth"), metaWithoutFlag(), "well formed");
    }

    /// @dev The returned bytes are the record's own, not a copy that could drift.
    function test_matchesTheRecord() public {
        setUpAliceVerified(COIN_ETH);
        bytes memory record = abi.decode(
            resolver.resolve(
                dns("alice.fkey.eth"),
                abi.encodeWithSignature(
                    "data(bytes32,string)", aliceNode, "stealth-meta-address[1][60]"
                )
            ),
            (bytes)
        );
        assertEq(_of("alice.fkey.eth"), BytesUtils.substring(record, 1, record.length - 1));
    }
}
