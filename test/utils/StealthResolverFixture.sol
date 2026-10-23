// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {OffchainLookup} from "@ens/contracts/ccipRead/EIP3668.sol";
import {IAddressResolver} from "@ens/contracts/resolvers/profiles/IAddressResolver.sol";
import {BytesUtils} from "@ens/contracts/utils/BytesUtils.sol";
import {NameCoder} from "@ens/contracts/utils/NameCoder.sol";
import {
    Grant,
    IEACGrantInitializable
} from "~src/access-control/interfaces/IEACGrantInitializable.sol";
import {EACBaseRolesLib} from "~src/access-control/libraries/EACBaseRolesLib.sol";
import {UserRegistry} from "~src/registry/UserRegistry.sol";
import {IRegistry} from "~src/registry/interfaces/IRegistry.sol";
import {IRegistryURIRenderer} from "~src/registry/interfaces/IRegistryURIRenderer.sol";
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
    UserRegistry internal userRegistryImpl;
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
        userRegistryImpl =
            new UserRegistry(labelStore, IRegistryURIRenderer(address(0)), address(this));
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
        setChain(fluidkey, "fkey.eth", COIN_ETH, true);
        setChain(fluidkey, "fkey.eth", COIN_BASE, true);
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
        Grant[] memory grants = new Grant[](1);
        grants[0] = Grant(admin, EACBaseRolesLib.ALL_ROLES | EACBaseRolesLib.ADMIN_ROLES);
        bytes memory init =
            abi.encodeCall(PermissionedResolver.initialize, (grants, new bytes[](0)));
        return PermissionedResolver(
            verifiableFactory.deployProxy(
                address(resolverImpl), uint256(keccak256(abi.encode(admin))), init
            )
        );
    }

    /// @dev An unmodified ENSv2 UserRegistry proxy with `owner` holding `roleBitmap` on its root.
    ///      namechain's V2Fixture provided this until v2-mainnet-deployment-1.
    function deployUserRegistry(address owner, uint256 roleBitmap, uint256 salt)
        internal
        returns (UserRegistry)
    {
        Grant[] memory grants = new Grant[](1);
        grants[0] = Grant(owner, roleBitmap);
        return UserRegistry(
            verifiableFactory.deployProxy(
                address(userRegistryImpl),
                salt,
                abi.encodeCall(IEACGrantInitializable.initialize, (grants))
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

    function setMeta(address caller, string memory name, bytes memory value) internal {
        vm.prank(caller);
        resolver.setMetaAddress(dns(name), value);
    }

    function setChain(address caller, string memory name, uint256 coinType, bool enabled) internal {
        uint256[] memory coinTypes = new uint256[](1);
        coinTypes[0] = coinType;
        vm.prank(caller);
        resolver.setChains(dns(name), coinTypes, enabled);
    }

    /// @dev Alice's config pointing at her own records resolver and Fluidkey's gateway (a
    ///      registered name inherits nothing), `coinType` on her chain list, and her meta-address.
    function setUpAliceVerified(uint256 coinType) internal {
        setConfig(alice, "alice.fkey.eth", address(aliceRecords), STEALTH_GW);
        setChain(alice, "alice.fkey.eth", coinType, true);
        setMeta(alice, "alice.fkey.eth", META);
    }

    /// @dev Whether an address query for `name` on `coinType` goes to the stealth gateway, probed
    ///      as ENSIP-30 Section 2 has clients probe it: the query reverts `OffchainLookup` with
    ///      this resolver's stealth callback.
    function isStealthChain(string memory name, uint256 coinType) internal view returns (bool) {
        (bool ok, bytes memory v) = address(resolver)
            .staticcall(
                abi.encodeCall(
                    resolver.resolve,
                    (dns(name), abi.encodeCall(IAddressResolver.addr, (node(name), coinType)))
                )
            );
        if (ok || bytes4(v) != OffchainLookup.selector) return false;
        (,,, bytes4 callback,) = abi.decode(
            BytesUtils.substring(v, 4, v.length - 4), (address, string[], bytes, bytes4, bytes)
        );
        return callback == resolver.resolveStealthCallback.selector;
    }

    function metaWithoutFlag() internal pure returns (bytes memory) {
        return BytesUtils.substring(META, 1, META.length - 1);
    }
}
