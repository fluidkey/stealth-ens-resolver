// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IAddrResolver} from "@ens/contracts/resolvers/profiles/IAddrResolver.sol";

import {StealthResolver} from "../src/StealthResolver.sol";
import {FluidkeySigners} from "../src/verifiers/FluidkeySigners.sol";
import {FluidkeyVerifier} from "../src/verifiers/FluidkeyVerifier.sol";
import {FluidkeyVectors} from "./utils/FluidkeyVectors.sol";
import {StealthResolverFixture} from "./utils/StealthResolverFixture.sol";

/// @dev StealthResolver with FluidkeyVerifier: both ENSIP-30 Section 4 modes end to end. The
///      fixture's mock verifier is replaced in place, so every name keeps its setup.
contract FluidkeyVerifierResolverTest is StealthResolverFixture {
    uint256 internal constant SIGNER_KEY = 0xF1;

    FluidkeySigners internal signers;
    FluidkeyVectors.Vector internal v;

    function setUp() public override {
        super.setUp();
        signers = new FluidkeySigners(address(this));
        signers.setSigner(vm.addr(SIGNER_KEY), true);
        vm.etch(address(verifier), address(new FluidkeyVerifier(0x464B31, signers)).code);
        v = FluidkeyVectors.all()[6]; // production auto-earn v1.1 setup
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

    /// @dev The Fluidkey gateway's signature over a response, as `_sign` in the unit tests.
    function _signed(bytes32 forNode, address claimed, uint64 expires)
        internal
        view
        returns (bytes memory)
    {
        bytes32 domain = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256("FluidkeyVerifier"),
                keccak256("1"),
                block.chainid,
                address(verifier)
            )
        );
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "StealthResolution(address resolver,bytes32 node,uint256 coinType,address stealthAddress,uint64 expires)"
                ),
                address(resolver),
                forNode,
                COIN_ETH,
                claimed,
                expires
            )
        );
        (uint8 sv, bytes32 r, bytes32 s) =
            vm.sign(SIGNER_KEY, keccak256(abi.encodePacked(hex"1901", domain, structHash)));
        return abi.encode(expires, abi.encodePacked(r, s, sv));
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

    /// @dev bob.fkey.eth has no record: the signed response is accepted.
    function test_unverified_signed() public {
        gwClaimed = makeAddr("bob's safe");
        gwVerificationData = _signed(bobNode, gwClaimed, uint64(block.timestamp + 300));
        (bool ok, bytes memory result) = _addr("bob.fkey.eth");
        assertTrue(ok);
        assertEq(abi.decode(abi.decode(result, (bytes)), (address)), gwClaimed);
    }

    /// @dev A response signed for another name, or not signed, is refused.
    function test_unverified_unsignedOrOtherNameRejected() public {
        gwClaimed = makeAddr("bob's safe");
        gwVerificationData = _signed(aliceNode, gwClaimed, uint64(block.timestamp + 300));
        (bool ok, bytes memory result) = _addr("bob.fkey.eth");
        assertFalse(ok);
        assertEq(bytes4(result), FluidkeyVerifier.UnknownSigner.selector);

        gwVerificationData = "";
        (ok,) = _addr("bob.fkey.eth");
        assertFalse(ok);
    }

    /// @dev The verifier's own cost in both modes, written to `snapshots/Gas.json`.
    function test_gas() public {
        bytes memory call = abi.encodeCall(
            FluidkeyVerifier.verify,
            (aliceNode, COIN_ETH, v.metaAddress, v.verificationData, v.stealthAddress)
        );
        uint256 before = gasleft();
        (bool ok,) = address(verifier).staticcall(call);
        vm.snapshotValue("Gas", "FluidkeyVerifier_verify_verified", before - gasleft());
        assertTrue(ok);

        address claimed = makeAddr("bob's safe");
        call = abi.encodeCall(
            FluidkeyVerifier.verify,
            (bobNode, COIN_ETH, "", _signed(bobNode, claimed, uint64(block.timestamp)), claimed)
        );
        vm.prank(address(resolver));
        before = gasleft();
        (ok,) = address(verifier).staticcall(call);
        vm.snapshotValue("Gas", "FluidkeyVerifier_verify_signed", before - gasleft());
        assertTrue(ok);
    }
}
