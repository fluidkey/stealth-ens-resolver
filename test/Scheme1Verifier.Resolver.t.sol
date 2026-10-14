// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IAddrResolver} from "@ens/contracts/resolvers/profiles/IAddrResolver.sol";

import {StealthResolver} from "../src/StealthResolver.sol";
import {IStealthResolver} from "../src/interfaces/IStealthResolver.sol";
import {Scheme1Verifier} from "../src/verifiers/Scheme1Verifier.sol";
import {Scheme1Vectors} from "./utils/Scheme1Vectors.sol";
import {StealthResolverFixture} from "./utils/StealthResolverFixture.sol";

/// @dev StealthResolver with Scheme1Verifier: ENSIP-30 Section 4 end to end with real scheme 1
///      derivations. The fixture's mock verifier is replaced in place, so every name keeps its
///      setup.
contract Scheme1VerifierResolverTest is StealthResolverFixture {
    Scheme1Vectors.Vector internal v;

    function setUp() public override {
        super.setUp();
        vm.etch(address(verifier), address(new Scheme1Verifier()).code);
        v = Scheme1Vectors.all()[5];
        setConfig(alice, "alice.fkey.eth", address(aliceRecords), STEALTH_GW);
        setChain(alice, "alice.fkey.eth", COIN_ETH, true);
        setMeta(alice, "alice.fkey.eth", abi.encodePacked(hex"00", v.metaAddress));
    }

    function _addr(string memory name) internal view returns (bool ok, bytes memory result) {
        (ok, result) = ccipCall(
            address(resolver),
            abi.encodeCall(
                resolver.resolve, (dns(name), abi.encodeCall(IAddrResolver.addr, (node(name))))
            )
        );
    }

    function test_verified() public {
        gwClaimed = v.stealthAddress;
        gwVerificationData = v.verificationData;
        (bool ok, bytes memory result) = _addr("alice.fkey.eth");
        assertTrue(ok);
        assertEq(abi.decode(abi.decode(result, (bytes)), (address)), v.stealthAddress);
    }

    function test_verified_lyingGatewayRejected() public {
        address attacker = makeAddr("attacker");
        gwClaimed = attacker;
        gwVerificationData = v.verificationData;
        (bool ok, bytes memory result) = _addr("alice.fkey.eth");
        assertFalse(ok);
        assertEq(
            result,
            abi.encodeWithSelector(
                StealthResolver.StealthAddressMismatch.selector, attacker, v.stealthAddress
            )
        );
    }

    /// @dev A gateway that derived for another recipient cannot pass it off as this one's.
    function test_verified_otherRecipientsDerivationRejected() public {
        Scheme1Vectors.Vector memory other = Scheme1Vectors.all()[2];
        gwClaimed = other.stealthAddress;
        gwVerificationData = other.verificationData;
        (bool ok, bytes memory result) = _addr("alice.fkey.eth");
        assertFalse(ok);
        assertEq(bytes4(result), Scheme1Verifier.InvalidSharedSecret.selector);
    }

    /// @dev No record: unverified, the gateway's address is returned.
    function test_unverified() public {
        gwClaimed = makeAddr("chosen");
        gwVerificationData = "";
        (bool ok, bytes memory result) = _addr("bob.fkey.eth");
        assertTrue(ok);
        assertEq(abi.decode(abi.decode(result, (bytes)), (address)), gwClaimed);
    }

    /// @dev Out-of-flow verification of a past resolution: no CCIP-Read.
    function test_verifyStealthResolution() public view {
        bytes memory r = resolver.resolve(
            dns("alice.fkey.eth"),
            abi.encodeCall(
                IStealthResolver.verifyStealthResolution,
                (aliceNode, COIN_ETH, v.stealthAddress, v.verificationData)
            )
        );
        assertEq(abi.decode(r, (address)), v.stealthAddress);
    }

    /// @dev The verifier's own cost, the "+ verifier" term of the README's gas table, written to
    ///      `snapshots/Gas.json`.
    function test_gas() public {
        bytes memory call = abi.encodeCall(
            Scheme1Verifier.verify,
            (aliceNode, COIN_ETH, v.metaAddress, v.verificationData, v.stealthAddress)
        );
        uint256 before = gasleft();
        (bool ok,) = address(verifier).staticcall(call);
        vm.snapshotValue("Gas", "Scheme1Verifier_verify", before - gasleft());
        assertTrue(ok);
    }
}
