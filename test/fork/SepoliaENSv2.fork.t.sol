// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IGatewayProvider} from "@ens/contracts/ccipRead/IGatewayProvider.sol";
import {IAddrResolver} from "@ens/contracts/resolvers/profiles/IAddrResolver.sol";
import {ITextResolver} from "@ens/contracts/resolvers/profiles/ITextResolver.sol";

import {IUniversalResolver} from "@ens/contracts/universalResolver/IUniversalResolver.sol";
import {BytesUtils} from "@ens/contracts/utils/BytesUtils.sol";
import {NameCoder} from "@ens/contracts/utils/NameCoder.sol";
import {VerifiableFactory} from "@ensdomains/verifiable-factory/VerifiableFactory.sol";
import {EACBaseRolesLib} from "~src/access-control/libraries/EACBaseRolesLib.sol";
import {IPermissionedRegistry} from "~src/registry/interfaces/IPermissionedRegistry.sol";
import {IRegistry} from "~src/registry/interfaces/IRegistry.sol";
import {RegistryRolesLib} from "~src/registry/libraries/RegistryRolesLib.sol";
import {PermissionedResolver} from "~src/resolver/PermissionedResolver.sol";

import {Deploy} from "../../script/Deploy.s.sol";
import {StealthResolver} from "../../src/StealthResolver.sol";
import {MockVerifier} from "../mocks/MockVerifier.sol";
import {CCIPClient} from "../utils/CCIPClient.sol";
import {TEST_META} from "../utils/Constants.sol";

/// @dev Against ENS's ENSv2 deployment on Sepolia (namechain docs/addresses/sepolia.md):
///      StealthResolver deployed through the deploy script, a fresh name registered in the live
///      ETHRegistry, other records in a PermissionedResolver deployed from ENS's implementation,
///      and resolution through the live UniversalResolverV2. Runs when SEPOLIA_RPC_URL is set.
///      Pinned to a block where LABEL is available, so the test cannot break when the label is
///      registered later; the RPC must serve historical state (archive).
contract SepoliaENSv2ForkTest is CCIPClient {
    uint256 internal constant FORK_BLOCK = 11_906_000; // 2026-10-13, LABEL available

    IRegistry internal constant ROOT_REGISTRY =
        IRegistry(0x11b5BfbE9078D826b1eDBDd1cFC12f5828D9F50C);
    IPermissionedRegistry internal constant ETH_REGISTRY =
        IPermissionedRegistry(0x67b728a792e789a8978b30cF1b3b641f19354b43);
    address internal constant ETH_REGISTRAR = 0xa4449a0dD2b83007553D9b1d28b583A46A805a30;
    IGatewayProvider internal constant BATCH_GATEWAYS =
        IGatewayProvider(0xE4e7245716d12D0F6AeA01DFe0E635C43D7D083c);
    VerifiableFactory internal constant FACTORY =
        VerifiableFactory(0x118Bc31A50d559F7015a8Da26d54B3b030CdB70F);
    address internal constant PERMISSIONED_RESOLVER_IMPL =
        0x7E4B2d59938930168024201752EE5503df402303;
    IUniversalResolver internal constant UR =
        IUniversalResolver(0x85eDf8B6b7D4211e2b07AA687506B746357B92cf);

    string internal constant LABEL = "ensip30-stealth-resolver-fork-test";
    bytes internal constant VD = hex"c0ffee";

    StealthResolver internal resolver;
    MockVerifier internal verifier;
    PermissionedResolver internal records;
    address internal alice = makeAddr("ensip30-stealth-resolver-fork-owner"); // no code on Sepolia
    bytes internal name;
    bytes32 internal nameNode;

    function setUp() public {
        string memory rpc = vm.envOr("SEPOLIA_RPC_URL", string(""));
        if (bytes(rpc).length == 0) {
            vm.skip(true);
            return;
        }
        vm.createSelectFork(rpc, FORK_BLOCK);

        verifier = new MockVerifier();
        vm.setEnv("ROOT_REGISTRY", vm.toString(address(ROOT_REGISTRY)));
        vm.setEnv("VERIFIER", vm.toString(address(verifier)));
        vm.setEnv("BATCH_GATEWAY_PROVIDER", vm.toString(address(BATCH_GATEWAYS)));
        resolver = new Deploy().run();

        vm.prank(ETH_REGISTRAR);
        ETH_REGISTRY.register(
            LABEL,
            alice,
            IRegistry(address(0)),
            address(resolver),
            RegistryRolesLib.ROLE_SET_RESOLVER | RegistryRolesLib.ROLE_SET_RESOLVER_ADMIN,
            uint64(block.timestamp + 365 days)
        );
        name = NameCoder.encode(string.concat(LABEL, ".eth"));
        nameNode = NameCoder.namehash(name, 0);

        bytes memory init = abi.encodeCall(
            PermissionedResolver.initialize,
            (alice, EACBaseRolesLib.ALL_ROLES | EACBaseRolesLib.ADMIN_ROLES, new bytes[](0))
        );
        vm.prank(alice);
        records = PermissionedResolver(
            FACTORY.deployProxy(PERMISSIONED_RESOLVER_IMPL, uint256(keccak256(init)), init)
        );

        vm.startPrank(alice);
        records.setText(nameNode, "url", "https://alice.example");
        resolver.setConfig(name, address(records), _urls());
        resolver.setStealthRecord(name, 60, TEST_META);
        vm.stopPrank();
    }

    function _urls() internal pure returns (string[] memory u) {
        u = new string[](1);
        u[0] = STEALTH_GW;
    }

    function _ur(bytes memory dnsName, bytes memory data)
        internal
        view
        returns (bool ok, bytes memory result)
    {
        bytes memory v;
        (ok, v) = ccipCall(address(UR), abi.encodeCall(UR.resolve, (dnsName, data)));
        if (ok) {
            address resolvedBy;
            (result, resolvedBy) = abi.decode(v, (bytes, address));
            assertEq(resolvedBy, address(resolver));
        }
    }

    function test_sepolia_textForwardedToPermissionedResolver() public view {
        (bool ok, bytes memory result) =
            _ur(name, abi.encodeCall(ITextResolver.text, (nameNode, "url")));
        assertTrue(ok);
        assertEq(abi.decode(result, (string)), "https://alice.example");
    }

    function test_sepolia_verified() public {
        bytes memory data = abi.encodeCall(IAddrResolver.addr, (nameNode));
        gwClaimed = verifier.derive(BytesUtils.substring(TEST_META, 1, TEST_META.length - 1), VD);
        gwVerificationData = VD;
        (bool ok, bytes memory result) = _ur(name, data);
        assertTrue(ok, "honest gateway");
        assertEq(abi.decode(result, (address)), gwClaimed);

        gwClaimed = makeAddr("attacker");
        (ok,) = _ur(name, data);
        assertFalse(ok, "lying gateway does not resolve");
    }

    function test_sepolia_wildcardSubname_unverified() public {
        bytes memory sub = NameCoder.encode(string.concat("bob.", LABEL, ".eth"));
        gwClaimed = makeAddr("chosen");
        gwVerificationData = "ok";
        (bool ok, bytes memory result) =
            _ur(sub, abi.encodeCall(IAddrResolver.addr, (NameCoder.namehash(sub, 0))));
        assertTrue(ok);
        assertEq(abi.decode(result, (address)), gwClaimed);
    }
}
