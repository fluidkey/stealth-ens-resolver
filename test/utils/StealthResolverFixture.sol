// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {BytesUtils} from "@ens/contracts/utils/BytesUtils.sol";
import {NameCoder} from "@ens/contracts/utils/NameCoder.sol";
import {EACBaseRolesLib} from "~src/access-control/libraries/EACBaseRolesLib.sol";
import {UserRegistry} from "~src/registry/UserRegistry.sol";
import {IRegistry} from "~src/registry/interfaces/IRegistry.sol";
import {RegistryRolesLib} from "~src/registry/libraries/RegistryRolesLib.sol";
import {PermissionedResolver} from "~src/resolver/PermissionedResolver.sol";
import {V1Fixture} from "~test/fixtures/V1Fixture.sol";
import {V2Fixture} from "~test/fixtures/V2Fixture.sol";

import {StealthResolver} from "../../src/StealthResolver.sol";
import {MockVerifier} from "../mocks/MockVerifier.sol";
import {CCIPClient} from "./CCIPClient.sol";
import {TEST_META} from "./Constants.sol";

/// @dev namechain's own ENSv1 + ENSv2 fixtures plus:
///      - `fkey.eth`: owner `fluidkey`, its own UserRegistry (Fluidkey has no registry-wide
///        ROLE_SET_RESOLVER there), resolver = StealthResolver, config = Fluidkey's
///        PermissionedResolver + stealth gateway.
///      - `alice.fkey.eth`: registered to `alice` (ROLE_SET_RESOLVER + admin), resolver =
///        StealthResolver, no config yet; `aliceRecords` = her own PermissionedResolver.
///      - `bob.fkey.eth`: not registered (wildcard username).
abstract contract StealthResolverFixture is V1Fixture, V2Fixture, CCIPClient {
    uint256 internal constant COIN_ETH = 60;
    uint256 internal constant COIN_BASE = 0x80000000 | 8453;
    bytes internal constant META = TEST_META;

    StealthResolver internal resolver;
    MockVerifier internal verifier;
    PermissionedResolver internal resolverImpl;
    UserRegistry internal fkeyRegistry;
    PermissionedResolver internal fkeyRecords;
    PermissionedResolver internal aliceRecords;

    address internal fluidkey = makeAddr("fluidkey");
    address internal alice = makeAddr("alice");
    address internal stranger = makeAddr("stranger");

    bytes32 internal fkeyNode;
    bytes32 internal aliceNode;
    bytes32 internal bobNode;
    uint64 internal expiry;

    function setUp() public virtual {
        deployV1Fixture();
        deployV2Fixture();
        verifier = new MockVerifier();
        resolver = new StealthResolver(rootRegistry, verifier, batchGatewayProvider);
        resolverImpl = new PermissionedResolver(address(this));
        expiry = uint64(block.timestamp + 365 days);

        fkeyRegistry = deployUserRegistry(
            fluidkey,
            RegistryRolesLib.ROLE_REGISTRAR | RegistryRolesLib.ROLE_REGISTRAR_ADMIN
                | RegistryRolesLib.ROLE_RENEW | RegistryRolesLib.ROLE_RENEW_ADMIN,
            uint256(keccak256("fkey"))
        );
        ethRegistry.register(
            "fkey", fluidkey, fkeyRegistry, address(resolver), _ethTokenRoles(), expiry
        );
        vm.prank(fluidkey);
        fkeyRegistry.register(
            "alice",
            alice,
            IRegistry(address(0)),
            address(resolver),
            RegistryRolesLib.ROLE_SET_RESOLVER | RegistryRolesLib.ROLE_SET_RESOLVER_ADMIN,
            expiry
        );

        fkeyNode = node("fkey.eth");
        aliceNode = node("alice.fkey.eth");
        bobNode = node("bob.fkey.eth");

        fkeyRecords = deployRecords(fluidkey);
        aliceRecords = deployRecords(alice);
        setConfig(fluidkey, "fkey.eth", address(fkeyRecords), STEALTH_GW);
    }

    // Names and config.

    function dns(string memory name) internal pure returns (bytes memory) {
        return NameCoder.encode(name);
    }

    function node(string memory name) internal pure returns (bytes32) {
        return NameCoder.namehash(NameCoder.encode(name), 0);
    }

    function urls(string memory url) internal pure returns (string[] memory list) {
        if (bytes(url).length == 0) return new string[](0);
        list = new string[](1);
        list[0] = url;
    }

    function setConfig(address caller, string memory name, address records, string memory url)
        internal
    {
        vm.prank(caller);
        resolver.setConfig(dns(name), records, urls(url));
    }

    /// @dev An unmodified ENSv2 PermissionedResolver proxy with `admin` holding every role.
    function deployRecords(address admin) internal returns (PermissionedResolver) {
        bytes memory init = abi.encodeCall(
            PermissionedResolver.initialize,
            (admin, EACBaseRolesLib.ALL_ROLES | EACBaseRolesLib.ADMIN_ROLES, new bytes[](0))
        );
        return PermissionedResolver(
            verifiableFactory.deployProxy(
                address(resolverImpl), uint256(keccak256(abi.encode(admin))), init
            )
        );
    }

    function stealthKey(uint256 coinType) internal view returns (string memory) {
        return string.concat(
            "stealth-meta-address[",
            vm.toString(resolver.schemeId()),
            "][",
            vm.toString(coinType),
            "]"
        );
    }

    /// @dev Alice's record, written to her own records resolver, and her config pointing at it.
    function setUpAliceVerified(uint256 coinType) internal {
        string memory key = stealthKey(coinType); // external call: build before vm.prank
        vm.prank(alice);
        aliceRecords.setData(aliceNode, key, META);
        setConfig(alice, "alice.fkey.eth", address(aliceRecords), "");
    }

    function metaWithoutFlag() internal pure returns (bytes memory) {
        return BytesUtils.substring(META, 1, META.length - 1);
    }
}
