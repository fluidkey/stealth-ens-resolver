// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console} from "forge-std/Script.sol";

import {FluidkeySigners, IFluidkeySigners} from "../src/verifiers/FluidkeySigners.sol";
import {FluidkeyVerifier} from "../src/verifiers/FluidkeyVerifier.sol";

/// @notice Deploys FluidkeySigners and FluidkeyVerifier through the canonical CREATE2 deployer
///         (0x4e59b44847b379578588920cA78FbF26c0B4956C). Either is skipped if already deployed.
///         Pass the printed verifier address as VERIFIER to `script/Deploy.s.sol`.
///
///   SIGNERS_OWNER=<a> SCHEME_ID=4606769 \
///     forge script script/DeployFluidkeyVerifier.s.sol --fork-url $RPC_URL   # simulation only
///
/// SIGNERS_OWNER is the Fluidkey account that adds and removes gateway signers. SCHEME_ID is FK1's
/// ERC-5564 scheme ID; deploy only once the scheme's ERC declares it.
contract DeployFluidkeyVerifier is Script {
    bytes32 public constant SIGNERS_SALT = keccak256("ENSIP-30 FluidkeySigners");
    bytes32 public constant VERIFIER_SALT = keccak256("ENSIP-30 FluidkeyVerifier");

    function run() external returns (FluidkeySigners signers, FluidkeyVerifier verifier) {
        address owner = vm.envAddress("SIGNERS_OWNER");
        uint256 schemeId = vm.envUint("SCHEME_ID");

        address predictedSigners = predictSigners(owner);
        if (predictedSigners.code.length == 0) {
            vm.broadcast();
            require(
                address(new FluidkeySigners{salt: SIGNERS_SALT}(owner)) == predictedSigners,
                "CREATE2 address mismatch"
            );
        }
        signers = FluidkeySigners(predictedSigners);
        console.log("FluidkeySigners at", predictedSigners);

        address predictedVerifier = predictVerifier(schemeId, signers);
        if (predictedVerifier.code.length == 0) {
            vm.broadcast();
            require(
                address(new FluidkeyVerifier{salt: VERIFIER_SALT}(schemeId, signers))
                    == predictedVerifier,
                "CREATE2 address mismatch"
            );
        }
        verifier = FluidkeyVerifier(predictedVerifier);
        console.log("FluidkeyVerifier at", predictedVerifier);
    }

    function predictSigners(address owner) public pure returns (address) {
        return vm.computeCreate2Address(
            SIGNERS_SALT,
            keccak256(abi.encodePacked(type(FluidkeySigners).creationCode, abi.encode(owner))),
            CREATE2_FACTORY
        );
    }

    function predictVerifier(uint256 schemeId, IFluidkeySigners signers)
        public
        pure
        returns (address)
    {
        return vm.computeCreate2Address(
            VERIFIER_SALT,
            keccak256(
                abi.encodePacked(type(FluidkeyVerifier).creationCode, abi.encode(schemeId, signers))
            ),
            CREATE2_FACTORY
        );
    }
}
