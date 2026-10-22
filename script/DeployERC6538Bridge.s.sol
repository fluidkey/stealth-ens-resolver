// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IUniversalResolver} from "@ens/contracts/universalResolver/IUniversalResolver.sol";
import {Script, console} from "forge-std/Script.sol";

import {ERC6538Bridge} from "../src/ERC6538Bridge.sol";

/// @notice Deploys ERC6538Bridge through the canonical CREATE2 deployer
///         (0x4e59b44847b379578588920cA78FbF26c0B4956C). Its address depends only on the salt and
///         the UniversalResolver it reads through. Does nothing if it is already deployed.
///
///   UNIVERSAL_RESOLVER=<a> forge script script/DeployERC6538Bridge.s.sol --fork-url $RPC_URL
///
/// UNIVERSAL_RESOLVER is ENS's UniversalResolver proxy on Ethereum mainnet
/// (0xeEeEEEeE14D718C2B47D9923Deab1335E144EeEe), the entry point ENS keeps and upgrades in place,
/// not one of its implementations: the bridge stores it immutably, and its address depends on it.
contract DeployERC6538Bridge is Script {
    /// @notice Salt for the ERC6538Bridge deployment.
    bytes32 public constant SALT = keccak256("ENSIP-30 ERC6538Bridge");

    function run() external returns (ERC6538Bridge bridge) {
        IUniversalResolver universalResolver =
            IUniversalResolver(vm.envAddress("UNIVERSAL_RESOLVER"));
        address predicted = predict(universalResolver);
        console.log("ERC6538Bridge at", predicted);
        if (predicted.code.length == 0) {
            vm.broadcast();
            require(
                address(new ERC6538Bridge{salt: SALT}(universalResolver)) == predicted,
                "CREATE2 address mismatch"
            );
        }
        bridge = ERC6538Bridge(predicted);
    }

    /// @notice The CREATE2 address of ERC6538Bridge reading through `universalResolver`.
    function predict(IUniversalResolver universalResolver) public pure returns (address) {
        return vm.computeCreate2Address(
            SALT,
            keccak256(
                abi.encodePacked(type(ERC6538Bridge).creationCode, abi.encode(universalResolver))
            ),
            CREATE2_FACTORY
        );
    }
}
