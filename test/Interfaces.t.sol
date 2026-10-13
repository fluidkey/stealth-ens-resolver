// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test} from "forge-std/Test.sol";

import {IStealthResolver} from "../src/interfaces/IStealthResolver.sol";
import {IStealthVerifier} from "../src/interfaces/IStealthVerifier.sol";

contract InterfacesTest is Test {
    /// @dev ENSIP-30 Section 5 states the interface ID.
    function test_IStealthResolver_interfaceIdMatchesENSIP() public pure {
        assertEq(type(IStealthResolver).interfaceId, bytes4(0xba4f4bd5));
    }

    /// @dev Recomputed from the signature strings, so a changed parameter type in either the
    ///      interface or the ENSIP fails here rather than silently changing the ID.
    function test_IStealthResolver_interfaceIdFromSignatures() public pure {
        bytes4 id = bytes4(keccak256("schemeId()")) ^ bytes4(keccak256("gatewayURLs(bytes32)"))
            ^ bytes4(keccak256("verifyStealthResolution(bytes32,uint256,address,bytes)"));
        assertEq(type(IStealthResolver).interfaceId, id);
    }

    function test_IStealthVerifier_interfaceIdFromSignatures() public pure {
        bytes4 id = bytes4(keccak256("schemeId()"))
            ^ bytes4(keccak256("verify(bytes32,uint256,bytes,bytes,address)"));
        assertEq(type(IStealthVerifier).interfaceId, id);
    }
}
