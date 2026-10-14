// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test} from "forge-std/Test.sol";

import {FluidkeySigners} from "../../src/verifiers/FluidkeySigners.sol";
import {FluidkeyVerifier} from "../../src/verifiers/FluidkeyVerifier.sol";

interface ISafeProxyFactory {
    function proxyCreationCode() external pure returns (bytes memory);
}

/// @dev FluidkeyVerifier's Safe constants against Ethereum mainnet: the proxy factory's creation
///      code hashes to the constant, and every address in the setup has code. Runs when
///      MAINNET_RPC_URL is set; pinned to a block, so the RPC must serve historical state.
contract FluidkeySafeMainnetForkTest is Test {
    uint256 internal constant FORK_BLOCK = 26_190_000; // 2026-10-14

    address internal constant FACTORY = 0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2;
    address internal constant SINGLETON = 0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552;

    function setUp() public {
        string memory rpc = vm.envOr("MAINNET_RPC_URL", string(""));
        if (bytes(rpc).length == 0) {
            vm.skip(true);
            return;
        }
        vm.createSelectFork(rpc, FORK_BLOCK);
    }

    function test_safeConstants() public {
        assertEq(
            keccak256(
                abi.encodePacked(
                    ISafeProxyFactory(FACTORY).proxyCreationCode(), uint256(uint160(SINGLETON))
                )
            ),
            0x56e3081a3d1bb38ed4eed1a39f7729c3cc77c7825794c15bbf326f3047fd779c,
            "proxy init code hash"
        );
        address[6] memory deployed = [
            FACTORY,
            SINGLETON,
            0xf48f2B2d2a534e402487b3ee7C18c33Aec0Fe5e4, // fallback handler
            0xA238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761, // MultiSend
            0x2dd68b007B46fBe91B9A7c3EDa5A7a1063cB5b47, // SafeModuleSetup
            0x3BDb857AFe9b51d8916D80240d2ADe40D4d3f2f9 // Fluidkey Earn module
        ];
        for (uint256 i; i < deployed.length; ++i) {
            assertGt(deployed[i].code.length, 0, vm.toString(deployed[i]));
        }

        // The constant is the one the verifier uses: a Safe it predicts is what the factory deploys.
        FluidkeyVerifier verifier =
            new FluidkeyVerifier(0x464B31, new FluidkeySigners(address(this)));
        address owner = makeAddr("owner");
        address predicted = verifier.safeAddress(owner, 0);
        address[] memory owners = new address[](1);
        owners[0] = owner;
        bytes memory initializer = abi.encodeWithSelector(
            0xb63e800d,
            owners,
            uint256(1),
            address(0),
            bytes(""),
            0xf48f2B2d2a534e402487b3ee7C18c33Aec0Fe5e4,
            address(0),
            uint256(0),
            address(0)
        );
        (bool ok, bytes memory ret) = FACTORY.call(
            abi.encodeWithSignature(
                "createProxyWithNonce(address,bytes,uint256)", SINGLETON, initializer, 0
            )
        );
        assertTrue(ok, "factory deploys");
        assertEq(abi.decode(ret, (address)), predicted);
    }
}
