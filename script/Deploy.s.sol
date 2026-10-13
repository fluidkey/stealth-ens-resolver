// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console} from "forge-std/Script.sol";

import {IGatewayProvider} from "@ens/contracts/ccipRead/IGatewayProvider.sol";
import {IRegistry} from "@ensv2/registry/interfaces/IRegistry.sol";

import {StealthResolver} from "../src/StealthResolver.sol";
import {IStealthVerifier} from "../src/interfaces/IStealthVerifier.sol";

/// @notice Deploys StealthResolver through the canonical CREATE2 deployer
///         (0x4e59b44847b379578588920cA78FbF26c0B4956C). The address depends only on the salt,
///         the bytecode and the constructor arguments, so there is one resolver per verifier
///         (scheme) and the same address on every chain where those match.
///
///   ROOT_REGISTRY=<a> VERIFIER=<a> BATCH_GATEWAY_PROVIDER=<a> \
///     forge script script/Deploy.s.sol --fork-url $RPC_URL           # simulation only
///
/// ROOT_REGISTRY and BATCH_GATEWAY_PROVIDER are ENSv2's on the target chain (ENS's own mirror
/// resolver `ENSV2Resolver` exposes the batch gateway provider it uses).
contract Deploy is Script {
    /// @notice Salt for every StealthResolver deployment.
    bytes32 public constant SALT = keccak256("ENSIP-30 StealthResolver");

    function run() external returns (StealthResolver resolver) {
        IRegistry rootRegistry = IRegistry(vm.envAddress("ROOT_REGISTRY"));
        IStealthVerifier verifier = IStealthVerifier(vm.envAddress("VERIFIER"));
        IGatewayProvider batchGateways = IGatewayProvider(vm.envAddress("BATCH_GATEWAY_PROVIDER"));

        address predicted = predict(rootRegistry, verifier, batchGateways);
        console.log("StealthResolver at", predicted);

        vm.broadcast();
        resolver = new StealthResolver{salt: SALT}(rootRegistry, verifier, batchGateways);
        require(address(resolver) == predicted, "CREATE2 address mismatch");
    }

    /// @notice The CREATE2 address for the given constructor arguments.
    function predict(
        IRegistry rootRegistry,
        IStealthVerifier verifier,
        IGatewayProvider batchGateways
    ) public pure returns (address) {
        bytes memory initCode = abi.encodePacked(
            type(StealthResolver).creationCode, abi.encode(rootRegistry, verifier, batchGateways)
        );
        return vm.computeCreate2Address(SALT, keccak256(initCode), CREATE2_FACTORY);
    }
}
