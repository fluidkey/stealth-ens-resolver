// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Deploy} from "../script/Deploy.s.sol";
import {DeployERC6538Bridge} from "../script/DeployERC6538Bridge.s.sol";
import {DeployFluidkeyVerifier} from "../script/DeployFluidkeyVerifier.s.sol";
import {DeployScheme1Verifier} from "../script/DeployScheme1Verifier.s.sol";

import {ERC6538Bridge} from "../src/ERC6538Bridge.sol";
import {StealthResolver} from "../src/StealthResolver.sol";
import {FluidkeySigners} from "../src/verifiers/FluidkeySigners.sol";
import {FluidkeyVerifier} from "../src/verifiers/FluidkeyVerifier.sol";
import {Scheme1Verifier} from "../src/verifiers/Scheme1Verifier.sol";
import {StealthResolverFixture} from "./utils/StealthResolverFixture.sol";

contract DeployTest is StealthResolverFixture {
    /// @dev Registry and verifier at their predicted addresses; a second run deploys nothing.
    function test_deployFluidkeyVerifier_atPredictedAddresses() public {
        address owner = makeAddr("fluidkey");
        vm.setEnv("SIGNERS_OWNER", vm.toString(owner));
        vm.setEnv("SCHEME_ID", "4606769");
        DeployFluidkeyVerifier script = new DeployFluidkeyVerifier();
        (FluidkeySigners signers, FluidkeyVerifier deployed) = script.run();
        assertEq(address(signers), script.predictSigners(owner));
        assertEq(address(deployed), script.predictVerifier(4606769, signers));
        assertEq(signers.owner(), owner);
        assertEq(address(deployed.SIGNERS()), address(signers));
        assertEq(deployed.schemeId(), 4606769);
        (FluidkeySigners again, FluidkeyVerifier againVerifier) = script.run();
        assertEq(address(again), address(signers));
        assertEq(address(againVerifier), address(deployed));
    }

    /// @dev At the predicted address; a second run finds it and deploys nothing.
    function test_deployScheme1Verifier_atPredictedAddress() public {
        DeployScheme1Verifier script = new DeployScheme1Verifier();
        Scheme1Verifier deployed = script.run();
        assertEq(address(deployed), script.predict());
        assertEq(deployed.schemeId(), 1);
        assertEq(address(script.run()), address(deployed));
    }

    function test_deploy_atPredictedAddress() public {
        vm.setEnv("ROOT_REGISTRY", vm.toString(address(rootRegistry)));
        vm.setEnv("VERIFIER", vm.toString(address(verifier)));
        vm.setEnv("BATCH_GATEWAY_PROVIDER", vm.toString(address(batchGatewayProvider)));
        Deploy script = new Deploy();
        StealthResolver deployed = script.run();
        assertEq(address(deployed), script.predict(rootRegistry, verifier, batchGatewayProvider));
        assertEq(address(deployed.ROOT_REGISTRY()), address(rootRegistry));
        assertEq(address(deployed.VERIFIER()), address(verifier));
        assertEq(deployed.schemeId(), 1);
    }

    /// @dev At the predicted address for the UniversalResolver; a second run deploys nothing.
    function test_deployERC6538Bridge_atPredictedAddress() public {
        vm.setEnv("UNIVERSAL_RESOLVER", vm.toString(address(universalResolver)));
        DeployERC6538Bridge script = new DeployERC6538Bridge();
        ERC6538Bridge deployed = script.run();
        assertEq(address(deployed), script.predict(universalResolver));
        assertEq(address(deployed.UNIVERSAL_RESOLVER()), address(universalResolver));
        assertEq(address(script.run()), address(deployed));
    }
}
