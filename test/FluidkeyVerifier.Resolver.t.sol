// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IMulticallable} from "@ens/contracts/resolvers/IMulticallable.sol";
import {IAddrResolver} from "@ens/contracts/resolvers/profiles/IAddrResolver.sol";
import {IAddressResolver} from "@ens/contracts/resolvers/profiles/IAddressResolver.sol";

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
        v = FluidkeyVectors.all()[6]; // the kit's auto-earn v1.1 setup
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

    /// @dev A Fluidkey signer's EIP-712 signature, as the unit tests build it.
    function _sig(bytes32 structHash) internal view returns (bytes memory) {
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
        (uint8 sv, bytes32 r, bytes32 s) =
            vm.sign(SIGNER_KEY, keccak256(abi.encodePacked(hex"1901", domain, structHash)));
        return abi.encodePacked(r, s, sv);
    }

    /// @dev The Fluidkey gateway's verified response for `forNode` on Ethereum: the vector's
    ///      derivation and a signature over its Safe.
    function _signedDerivation(bytes32 forNode) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "VerifiedStealthResolution(address resolver,bytes32 node,uint256 coinType,address stealthAddress)"
                ),
                address(resolver),
                forNode,
                COIN_ETH,
                v.stealthAddress
            )
        );
        return bytes.concat(v.verificationData, _sig(structHash));
    }

    /// @dev The Fluidkey gateway's unverified response for `forNode` on Ethereum.
    function _signed(bytes32 forNode, address claimed, uint64 expires)
        internal
        view
        returns (bytes memory)
    {
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
        return abi.encode(expires, _sig(structHash));
    }

    function test_verified() public {
        gwClaimed = v.stealthAddress;
        gwVerificationData = _signedDerivation(aliceNode);
        (bool ok, bytes memory result) = _addr("alice.fkey.eth");
        assertTrue(ok);
        assertEq(abi.decode(abi.decode(result, (bytes)), (address)), v.stealthAddress);
    }

    function test_verified_lyingGatewayRejected() public {
        address attacker = makeAddr("attacker");
        gwClaimed = attacker;
        gwVerificationData = _signedDerivation(aliceNode);
        (bool ok, bytes memory result) = _addr("alice.fkey.eth");
        assertFalse(ok);
        assertEq(result, abi.encodeWithSelector(StealthResolver.StealthAddressMismatch.selector));
    }

    /// @dev A derivation without the signature, as a batch gateway answering from its own
    ///      ephemeral key would send, or signed for another name, is refused.
    function test_verified_unsignedOrOtherNameRejected() public {
        gwClaimed = v.stealthAddress;
        gwVerificationData = v.verificationData;
        (bool ok, bytes memory result) = _addr("alice.fkey.eth");
        assertFalse(ok);
        assertEq(bytes4(result), FluidkeyVerifier.InvalidVerificationData.selector);

        gwVerificationData = _signedDerivation(bobNode);
        (ok, result) = _addr("alice.fkey.eth");
        assertFalse(ok);
        assertEq(bytes4(result), FluidkeyVerifier.UnknownSigner.selector);
    }

    /// @dev In a multicall a failed item is returned as data. A valid derivation with a crafted
    ///      signature fails as `UnknownSigner(0)`, so a client that decodes the item as an address
    ///      without checking the error marker reads no address, not one the gateway chose.
    function test_verified_multicallFailureCarriesNoGatewayWord() public {
        bytes32 s = bytes32(abi.encodePacked(bytes8(0xffffffffffffffff), makeAddr("x"), bytes4(0)));
        gwClaimed = v.stealthAddress;
        gwVerificationData = abi.encodePacked(v.verificationData, bytes32(uint256(1)), s, uint8(27));
        bytes[] memory calls = new bytes[](1);
        calls[0] = abi.encodeCall(IAddrResolver.addr, (aliceNode));
        (bool ok, bytes memory r) = ccipCall(
            address(resolver),
            abi.encodeCall(
                resolver.resolve,
                (dns("alice.fkey.eth"), abi.encodeCall(IMulticallable.multicall, (calls)))
            )
        );
        assertTrue(ok);
        bytes memory item = abi.decode(abi.decode(r, (bytes)), (bytes[]))[0];
        assertEq(item, abi.encodeWithSelector(FluidkeyVerifier.UnknownSigner.selector, address(0)));
    }

    /// @dev A chain FK1 does not support fails the lookup even when the name lists it.
    function test_unsupportedChainRejected() public {
        uint256 zkSyncEra = 0x80000000 | 324;
        setChain(alice, "alice.fkey.eth", zkSyncEra, true);
        gwClaimed = v.stealthAddress;
        gwVerificationData = _signedDerivation(aliceNode);
        (bool ok, bytes memory result) = ccipCall(
            address(resolver),
            abi.encodeCall(
                resolver.resolve,
                (
                    dns("alice.fkey.eth"),
                    abi.encodeCall(IAddressResolver.addr, (aliceNode, zkSyncEra))
                )
            )
        );
        assertFalse(ok);
        assertEq(
            result, abi.encodeWithSelector(FluidkeyVerifier.UnsupportedChain.selector, zkSyncEra)
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

    /// @dev The verifier's own cost in verified mode, written to `snapshots/Gas.json`. Each mode
    ///      is its own test, so each starts cold, as the first call in a transaction does.
    function test_gas_verified() public {
        bytes memory call = abi.encodeCall(
            FluidkeyVerifier.verify,
            (aliceNode, COIN_ETH, v.metaAddress, _signedDerivation(aliceNode), v.stealthAddress)
        );
        vm.prank(address(resolver));
        uint256 before = gasleft();
        (bool ok,) = address(verifier).staticcall(call);
        vm.snapshotValue("Gas", "FluidkeyVerifier_verify_verified", before - gasleft());
        assertTrue(ok);
    }

    /// @dev The verifier's own cost for a signed unverified response.
    function test_gas_signed() public {
        address claimed = makeAddr("bob's safe");
        bytes memory call = abi.encodeCall(
            FluidkeyVerifier.verify,
            (bobNode, COIN_ETH, "", _signed(bobNode, claimed, uint64(block.timestamp)), claimed)
        );
        vm.prank(address(resolver));
        uint256 before = gasleft();
        (bool ok,) = address(verifier).staticcall(call);
        vm.snapshotValue("Gas", "FluidkeyVerifier_verify_signed", before - gasleft());
        assertTrue(ok);
    }
}
