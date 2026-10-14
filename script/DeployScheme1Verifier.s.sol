// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console} from "forge-std/Script.sol";

import {Scheme1Verifier} from "../src/verifiers/Scheme1Verifier.sol";

/// @notice Deploys Scheme1Verifier through the canonical CREATE2 deployer
///         (0x4e59b44847b379578588920cA78FbF26c0B4956C): no constructor arguments, so one address
///         on every chain. Does nothing if it is already deployed. Pass the printed address as
///         VERIFIER to `script/Deploy.s.sol`.
///
///   forge script script/DeployScheme1Verifier.s.sol --fork-url $RPC_URL   # simulation only
contract DeployScheme1Verifier is Script {
    /// @notice Salt for the Scheme1Verifier deployment.
    bytes32 public constant SALT = keccak256("ENSIP-30 Scheme1Verifier");

    function run() external returns (Scheme1Verifier verifier) {
        address predicted = predict();
        console.log("Scheme1Verifier at", predicted);
        if (predicted.code.length == 0) {
            vm.broadcast();
            require(
                address(new Scheme1Verifier{salt: SALT}()) == predicted, "CREATE2 address mismatch"
            );
        }
        verifier = Scheme1Verifier(predicted);
    }

    /// @notice The CREATE2 address of Scheme1Verifier.
    function predict() public pure returns (address) {
        return vm.computeCreate2Address(
            SALT, keccak256(type(Scheme1Verifier).creationCode), CREATE2_FACTORY
        );
    }
}
