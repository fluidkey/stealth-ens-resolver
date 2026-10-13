// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Deploy} from "../script/Deploy.s.sol";
import {StealthResolver} from "../src/StealthResolver.sol";
import {StealthResolverFixture} from "./utils/StealthResolverFixture.sol";

contract DeployTest is StealthResolverFixture {
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
}
