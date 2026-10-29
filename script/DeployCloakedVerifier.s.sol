// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console} from "forge-std/Script.sol";

import {CloakedSigners, ICloakedSigners} from "../src/verifiers/CloakedSigners.sol";
import {CloakedVerifier} from "../src/verifiers/CloakedVerifier.sol";

/// @notice Deploys CloakedSigners and CloakedVerifier through the canonical CREATE2 deployer
///         (0x4e59b44847b379578588920cA78FbF26c0B4956C). Either is skipped if already deployed.
///         Pass the printed verifier address as VERIFIER to `script/Deploy.s.sol`.
///
///   SIGNERS_OWNER=<a> SCHEME_ID=<id> \
///     forge script script/DeployCloakedVerifier.s.sol --fork-url $RPC_URL   # simulation only
///
/// SIGNERS_OWNER is the Cloaked account that adds and removes gateway signers. SCHEME_ID is the
/// Cloaked scheme's ERC-5564 scheme ID; deploy only once a specification declares it.
contract DeployCloakedVerifier is Script {
    bytes32 public constant SIGNERS_SALT = keccak256("ENSIP-30 CloakedSigners");
    bytes32 public constant VERIFIER_SALT = keccak256("ENSIP-30 CloakedVerifier");

    function run() external returns (CloakedSigners signers, CloakedVerifier verifier) {
        address owner = vm.envAddress("SIGNERS_OWNER");
        uint256 schemeId = vm.envUint("SCHEME_ID");

        address predictedSigners = predictSigners(owner);
        if (predictedSigners.code.length == 0) {
            vm.broadcast();
            require(
                address(new CloakedSigners{salt: SIGNERS_SALT}(owner)) == predictedSigners,
                "CREATE2 address mismatch"
            );
        }
        signers = CloakedSigners(predictedSigners);
        console.log("CloakedSigners at", predictedSigners);

        address predictedVerifier = predictVerifier(schemeId, signers);
        if (predictedVerifier.code.length == 0) {
            vm.broadcast();
            require(
                address(new CloakedVerifier{salt: VERIFIER_SALT}(schemeId, signers))
                    == predictedVerifier,
                "CREATE2 address mismatch"
            );
        }
        verifier = CloakedVerifier(predictedVerifier);
        console.log("CloakedVerifier at", predictedVerifier);
    }

    function predictSigners(address owner) public pure returns (address) {
        return vm.computeCreate2Address(
            SIGNERS_SALT,
            keccak256(abi.encodePacked(type(CloakedSigners).creationCode, abi.encode(owner))),
            CREATE2_FACTORY
        );
    }

    function predictVerifier(uint256 schemeId, ICloakedSigners signers)
        public
        pure
        returns (address)
    {
        return vm.computeCreate2Address(
            VERIFIER_SALT,
            keccak256(
                abi.encodePacked(type(CloakedVerifier).creationCode, abi.encode(schemeId, signers))
            ),
            CREATE2_FACTORY
        );
    }
}
