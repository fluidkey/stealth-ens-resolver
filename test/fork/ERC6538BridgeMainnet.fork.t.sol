// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IDataResolver} from "@ens/contracts/resolvers/profiles/IDataResolver.sol";
import {IUniversalResolver} from "@ens/contracts/universalResolver/IUniversalResolver.sol";
import {NameCoder} from "@ens/contracts/utils/NameCoder.sol";
import {Test} from "forge-std/Test.sol";

import {ERC6538Bridge} from "../../src/ERC6538Bridge.sol";
import {TEST_META} from "../utils/Constants.sol";

interface IENSRegistryV1 {
    function owner(bytes32 node) external view returns (address);
    function setSubnodeRecord(
        bytes32 node,
        bytes32 label,
        address owner,
        address resolver,
        uint64 ttl
    ) external;
}

/// @dev An ENSv1-style resolver holding one ENSIP-24 data record.
contract MockDataResolver {
    bytes internal _value;

    constructor(bytes memory value) {
        _value = value;
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == 0x01ffc9a7 || interfaceId == type(IDataResolver).interfaceId;
    }

    function data(bytes32, string calldata key) external view returns (bytes memory) {
        return
            keccak256(bytes(key)) == keccak256("stealth-meta-address[1][60]") ? _value : bytes("");
    }
}

/// @dev ERC6538Bridge against ENS on Ethereum mainnet, through its live UniversalResolver: real
///      names without a record read as empty, and an ENSv1 subname given a record in the fork is
///      read through the same path. Runs when MAINNET_RPC_URL is set; pinned to a block, so the
///      RPC must serve historical state.
contract ERC6538BridgeMainnetForkTest is Test {
    uint256 internal constant FORK_BLOCK = 26_190_000; // 2026-10-14

    IUniversalResolver internal constant UNIVERSAL_RESOLVER =
        IUniversalResolver(0xeEeEEEeE14D718C2B47D9923Deab1335E144EeEe);
    IENSRegistryV1 internal constant ENS_V1 =
        IENSRegistryV1(0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e);

    ERC6538Bridge internal bridge;

    function setUp() public {
        string memory rpc = vm.envOr("MAINNET_RPC_URL", string(""));
        if (bytes(rpc).length == 0) {
            vm.skip(true);
            return;
        }
        vm.createSelectFork(rpc, FORK_BLOCK);
        bridge = new ERC6538Bridge(UNIVERSAL_RESOLVER);
    }

    function test_mainnet_namesWithoutRecord_empty() public view {
        assertEq(bridge.stealthMetaAddressOf(NameCoder.encode("ens.eth"), 1), "");
        assertEq(bridge.stealthMetaAddressOf(NameCoder.encode("eth"), 1), "");
        assertEq(
            bridge.stealthMetaAddressOf(NameCoder.encode("no-such-name-erc6538-bridge.eth"), 1), ""
        );
    }

    function test_mainnet_recordReadThroughUniversalResolver() public {
        bytes memory parent = NameCoder.encode("ens.eth");
        bytes32 parentNode = NameCoder.namehash(parent, 0);
        address owner = ENS_V1.owner(parentNode);
        MockDataResolver records = new MockDataResolver(TEST_META);
        vm.prank(owner);
        ENS_V1.setSubnodeRecord(
            parentNode, keccak256("erc6538-bridge-test"), owner, address(records), 0
        );
        assertEq(
            bridge.stealthMetaAddressOf(NameCoder.encode("erc6538-bridge-test.ens.eth"), 1),
            _withoutFlag(TEST_META)
        );
    }

    function _withoutFlag(bytes memory record) internal pure returns (bytes memory out) {
        out = new bytes(record.length - 1);
        for (uint256 i; i < out.length; ++i) {
            out[i] = record[i + 1];
        }
    }
}
