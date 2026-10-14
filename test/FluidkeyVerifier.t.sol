// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test} from "forge-std/Test.sol";

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {FluidkeySigners, IFluidkeySigners} from "../src/verifiers/FluidkeySigners.sol";
import {FluidkeyVerifier} from "../src/verifiers/FluidkeyVerifier.sol";
import {FluidkeyVectors} from "./utils/FluidkeyVectors.sol";

/// @dev FluidkeyVerifier against derivations by Fluidkey's stealth-account-kit, every rejection,
///      and the signed unverified mode.
contract FluidkeyVerifierTest is Test {
    uint256 internal constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 internal constant P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 internal constant FK1 = 0x464B31;
    uint256 internal constant SIGNER_KEY = 0xF1;

    FluidkeySigners internal signers;
    FluidkeyVerifier internal verifier;
    FluidkeyVectors.Vector[] internal vectors;

    address internal resolver = makeAddr("resolver");
    bytes32 internal node = keccak256("bob.fkey.eth");

    function setUp() public {
        signers = new FluidkeySigners(address(this));
        signers.setSigner(vm.addr(SIGNER_KEY), true);
        verifier = new FluidkeyVerifier(FK1, signers);
        FluidkeyVectors.Vector[] memory all = FluidkeyVectors.all();
        for (uint256 i; i < all.length; ++i) {
            vectors.push(all[i]);
        }
    }

    function _configHash(bytes memory meta) internal pure returns (uint256 h) {
        assembly {
            h := mload(add(meta, 65)) // bytes 33..64
        }
    }

    function _verify(bytes memory meta, bytes memory vd) internal view returns (address) {
        return verifier.verify(node, 60, meta, vd, address(0xdead));
    }

    function _expectVerifyRevert(bytes4 error, bytes memory meta, bytes memory vd) internal {
        vm.expectRevert(error);
        _verify(meta, vd);
    }

    // Deployment.

    function test_schemeId() public view {
        assertEq(verifier.schemeId(), 4606769);
    }

    function test_constructor_rejects() public {
        vm.expectRevert(abi.encodeWithSelector(FluidkeyVerifier.InvalidSchemeId.selector, 0));
        new FluidkeyVerifier(0, signers);
        vm.expectRevert(abi.encodeWithSelector(FluidkeyVerifier.InvalidSchemeId.selector, 1));
        new FluidkeyVerifier(1, signers);
        address eoa = makeAddr("eoa");
        vm.expectRevert(abi.encodeWithSelector(FluidkeyVerifier.InvalidSigners.selector, eoa));
        new FluidkeyVerifier(FK1, IFluidkeySigners(eoa));
    }

    // Verified mode.

    /// @dev The template rebuilds the auto-earn v1.1 setup data Fluidkey publishes, byte for byte.
    function test_setupData_isProductionV1_1() public view {
        assertEq(
            verifier.setupData(FluidkeyVectors.PROD_CONFIG_HASH), FluidkeyVectors.PROD_SETUP_DATA
        );
    }

    /// @dev Every Safe setup and parity combination, and the Safe address from the kit's owner.
    function test_vectors() public view {
        for (uint256 i; i < vectors.length; ++i) {
            FluidkeyVectors.Vector memory v = vectors[i];
            assertEq(_verify(v.metaAddress, v.verificationData), v.stealthAddress, vm.toString(i));
            assertEq(
                verifier.safeAddress(v.owner, _configHash(v.metaAddress)),
                v.stealthAddress,
                vm.toString(i)
            );
        }
    }

    function testFuzz_verified_independentOfClaimed(
        uint8 i,
        bytes32 n,
        uint256 coinType,
        address claimed
    ) public view {
        FluidkeyVectors.Vector memory v = vectors[i % vectors.length];
        assertEq(
            verifier.verify(n, coinType, v.metaAddress, v.verificationData, claimed),
            v.stealthAddress
        );
    }

    /// @dev The configHash in the record decides the Safe: the same keys under another setup give
    ///      another address, so the gateway cannot choose the setup.
    function test_configHashSelectsSafe() public view {
        FluidkeyVectors.Vector memory v = vectors[0];
        bytes memory meta = bytes.concat(_slice(v.metaAddress, 0, 33), bytes32(uint256(1)));
        address other = _verify(meta, v.verificationData);
        assertTrue(other != v.stealthAddress);
        assertEq(other, verifier.safeAddress(v.owner, 1));
    }

    function test_metaAddressMalformed() public {
        bytes memory meta = vectors[0].metaAddress;
        bytes memory vd = vectors[0].verificationData;
        bytes4 err = FluidkeyVerifier.MalformedMetaAddress.selector;
        _expectVerifyRevert(err, _slice(meta, 0, 64), vd);
        _expectVerifyRevert(err, abi.encodePacked(meta, hex"00"), vd);
        bytes memory m = bytes.concat(meta);
        m[0] = 0x04;
        _expectVerifyRevert(err, m, vd);
        _expectVerifyRevert(err, _withWord(meta, 1, 0), vd);
        _expectVerifyRevert(err, _withWord(meta, 1, N), vd);
        _expectVerifyRevert(err, _withWord(meta, 1, 5), vd); // x = 5 is off the curve
    }

    function test_verificationDataMalformed() public {
        bytes memory meta = vectors[0].metaAddress;
        bytes memory vd = vectors[0].verificationData;
        bytes4 err = FluidkeyVerifier.InvalidVerificationData.selector;
        _expectVerifyRevert(err, meta, _slice(vd, 0, 95));
        _expectVerifyRevert(err, meta, abi.encodePacked(vd, hex"00"));
        _expectVerifyRevert(err, meta, _withWord(vd, 0, 0));
        _expectVerifyRevert(err, meta, _withWord(vd, 0, N));
    }

    function test_wrongSharedSecret() public {
        bytes memory meta = vectors[0].metaAddress;
        bytes memory vd = vectors[0].verificationData;
        bytes4 err = FluidkeyVerifier.InvalidSharedSecret.selector;
        bytes memory other =
            bytes.concat(_slice(vd, 0, 32), _slice(vectors[1].verificationData, 32, 64));
        _expectVerifyRevert(err, meta, other);
        uint256 y = uint256(bytes32(_slice(vd, 64, 32)));
        _expectVerifyRevert(err, meta, _withWord(vd, 64, P - y)); // -S
    }

    // Unverified mode: signed responses.

    function _sign(
        uint256 key,
        address forResolver,
        bytes32 forNode,
        uint256 coinType,
        address claimed,
        uint64 expires
    ) internal view returns (bytes memory) {
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
                forResolver,
                forNode,
                coinType,
                claimed,
                expires
            )
        );
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(key, keccak256(abi.encodePacked(hex"1901", domain, structHash)));
        return abi.encodePacked(r, s, v);
    }

    function _signed(uint256 key, address claimed, uint64 expires)
        internal
        view
        returns (bytes memory)
    {
        return abi.encode(expires, _sign(key, resolver, node, 60, claimed, expires));
    }

    /// @dev Calls verify in unverified mode as `caller`; returns the revert selector, or 0.
    function _unverified(address caller, bytes32 n, uint256 coinType, bytes memory vd, address c)
        internal
        returns (bytes4)
    {
        vm.prank(caller);
        (bool ok, bytes memory err) = address(verifier).call(
            abi.encodeCall(FluidkeyVerifier.verify, (n, coinType, "", vd, c))
        );
        return ok ? bytes4(0) : bytes4(err);
    }

    function test_unverified_signed() public {
        address claimed = makeAddr("safe");
        uint64 expires = uint64(block.timestamp + 300);
        vm.prank(resolver);
        assertEq(
            verifier.verify(node, 60, "", _signed(SIGNER_KEY, claimed, expires), claimed), claimed
        );
    }

    /// @dev A signed zero address is an unset record.
    function test_unverified_signedZero() public {
        uint64 expires = uint64(block.timestamp);
        vm.prank(resolver);
        assertEq(
            verifier.verify(node, 60, "", _signed(SIGNER_KEY, address(0), expires), address(0)),
            address(0)
        );
    }

    function test_unverified_expired() public {
        address claimed = makeAddr("safe");
        uint64 expires = uint64(block.timestamp + 300);
        bytes memory vd = _signed(SIGNER_KEY, claimed, expires);
        vm.warp(expires + 1);
        vm.prank(resolver);
        vm.expectRevert(abi.encodeWithSelector(FluidkeyVerifier.SignatureExpired.selector, expires));
        verifier.verify(node, 60, "", vd, claimed);
    }

    function test_unverified_notASigner() public {
        address claimed = makeAddr("safe");
        uint64 expires = uint64(block.timestamp + 300);
        vm.prank(resolver);
        vm.expectRevert(
            abi.encodeWithSelector(FluidkeyVerifier.UnknownSigner.selector, vm.addr(0xBAD))
        );
        verifier.verify(node, 60, "", _signed(0xBAD, claimed, expires), claimed);
    }

    function test_unverified_removedSigner() public {
        address claimed = makeAddr("safe");
        uint64 expires = uint64(block.timestamp + 300);
        bytes memory vd = _signed(SIGNER_KEY, claimed, expires);
        signers.setSigner(vm.addr(SIGNER_KEY), false);
        assertEq(
            _unverified(resolver, node, 60, vd, claimed), FluidkeyVerifier.UnknownSigner.selector
        );
    }

    /// @dev A signature binds the resolver, node, coin type, address and expiry.
    function test_unverified_noReplay() public {
        address claimed = makeAddr("safe");
        uint64 expires = uint64(block.timestamp + 300);
        bytes memory vd = _signed(SIGNER_KEY, claimed, expires);
        bytes4 unknown = FluidkeyVerifier.UnknownSigner.selector;
        assertEq(
            _unverified(makeAddr("other resolver"), node, 60, vd, claimed), unknown, "resolver"
        );
        assertEq(_unverified(resolver, keccak256("x"), 60, vd, claimed), unknown, "node");
        assertEq(_unverified(resolver, node, 0x80002105, vd, claimed), unknown, "coin type");
        assertEq(_unverified(resolver, node, 60, vd, makeAddr("x")), unknown, "address");
        (, bytes memory sig) = abi.decode(vd, (uint64, bytes));
        assertEq(
            _unverified(resolver, node, 60, abi.encode(expires + 1, sig), claimed),
            unknown,
            "expiry"
        );
    }

    /// @dev The high-s twin of a valid signature is refused (OpenZeppelin ECDSA).
    function test_unverified_malleableSignature() public {
        address claimed = makeAddr("safe");
        uint64 expires = uint64(block.timestamp + 300);
        (, bytes memory sig) = abi.decode(_signed(SIGNER_KEY, claimed, expires), (uint64, bytes));
        bytes32 r = bytes32(_slice(sig, 0, 32));
        uint256 s = uint256(bytes32(_slice(sig, 32, 32)));
        uint8 v = uint8(sig[64]);
        bytes memory twin = abi.encodePacked(r, bytes32(N - s), v == 27 ? uint8(28) : uint8(27));
        assertEq(
            _unverified(resolver, node, 60, abi.encode(expires, twin), claimed),
            ECDSA.ECDSAInvalidSignatureS.selector
        );
    }

    /// @dev No signature at all: the response does not decode.
    function test_unverified_unsignedReverts() public {
        vm.prank(resolver);
        vm.expectRevert();
        verifier.verify(node, 60, "", "", makeAddr("safe"));
    }

    // Signer registry.

    function test_signers_onlyOwner() public {
        address stranger = makeAddr("stranger");
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger)
        );
        signers.setSigner(stranger, true);
    }

    function test_signers_setAndTwoStepTransfer() public {
        address signer = makeAddr("signer");
        vm.expectEmit(address(signers));
        emit FluidkeySigners.SignerChanged(signer, true);
        signers.setSigner(signer, true);
        assertTrue(signers.isSigner(signer));

        address next = makeAddr("next");
        signers.transferOwnership(next);
        assertEq(signers.owner(), address(this), "pending until accepted");
        vm.prank(next);
        signers.acceptOwnership();
        assertEq(signers.owner(), next);
    }

    // Helpers.

    function _slice(bytes memory b, uint256 start, uint256 len)
        internal
        pure
        returns (bytes memory r)
    {
        r = new bytes(len);
        for (uint256 i; i < len; ++i) {
            r[i] = b[start + i];
        }
    }

    function _withWord(bytes memory b, uint256 at, uint256 word)
        internal
        pure
        returns (bytes memory r)
    {
        r = bytes.concat(b);
        bytes32 w = bytes32(word);
        for (uint256 i; i < 32; ++i) {
            r[at + i] = w[i];
        }
    }
}
