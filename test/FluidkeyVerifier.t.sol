// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test} from "forge-std/Test.sol";

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {FluidkeySigners, IFluidkeySigners} from "../src/verifiers/FluidkeySigners.sol";
import {FluidkeyVerifier} from "../src/verifiers/FluidkeyVerifier.sol";
import {FluidkeyVectors} from "./utils/FluidkeyVectors.sol";

/// @dev FluidkeyVerifier against derivations by Fluidkey's stealth-account-kit, every rejection,
///      the supported chains, and the signatures of both modes.
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

    /// @dev Ethereum, Base, OP Mainnet, Arbitrum One, Polygon PoS, Gnosis, BNB Smart Chain.
    uint256[7] internal chains =
        [uint256(60), 0x80002105, 0x8000000a, 0x8000a4b1, 0x80000089, 0x80000064, 0x80000038];

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

    function _listed(uint256 coinType) internal view returns (bool) {
        for (uint256 i; i < chains.length; ++i) {
            if (chains[i] == coinType) return true;
        }
        return false;
    }

    // Signatures, built independently of the verifier.

    function _signStruct(uint256 key, bytes32 structHash) internal view returns (bytes memory) {
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
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(key, keccak256(abi.encodePacked(hex"1901", domain, structHash)));
        return abi.encodePacked(r, s, v);
    }

    /// @dev A signature over a verified response: the Safe the derivation gives.
    function _signVerified(
        uint256 key,
        address forResolver,
        bytes32 forNode,
        uint256 coinType,
        address stealth
    ) internal view returns (bytes memory) {
        return _signStruct(
            key,
            keccak256(
                abi.encode(
                    keccak256(
                        "VerifiedStealthResolution(address resolver,bytes32 node,uint256 coinType,address stealthAddress)"
                    ),
                    forResolver,
                    forNode,
                    coinType,
                    stealth
                )
            )
        );
    }

    /// @dev A signature over an unverified response.
    function _sign(
        uint256 key,
        address forResolver,
        bytes32 forNode,
        uint256 coinType,
        address claimed,
        uint64 expires
    ) internal view returns (bytes memory) {
        return _signStruct(
            key,
            keccak256(
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
            )
        );
    }

    /// @dev A vector's verification data as Fluidkey's gateway sends it for `resolver`, `node` and
    ///      Ethereum: the derivation, then the signature over its Safe.
    function _signedVd(FluidkeyVectors.Vector memory v) internal view returns (bytes memory) {
        return bytes.concat(
            v.verificationData, _signVerified(SIGNER_KEY, resolver, node, 60, v.stealthAddress)
        );
    }

    /// @dev Verified mode as `resolver`, for `node` and Ethereum.
    function _verify(bytes memory meta, bytes memory vd) internal returns (address) {
        vm.prank(resolver);
        return verifier.verify(node, 60, meta, vd, address(0xdead));
    }

    function _expectVerifyRevert(bytes4 error, bytes memory meta, bytes memory vd) internal {
        vm.expectRevert(error);
        _verify(meta, vd);
    }

    /// @dev Calls verify in verified mode as `caller`; returns the revert selector, or 0.
    function _verified(
        address caller,
        bytes32 n,
        uint256 coinType,
        bytes memory meta,
        bytes memory vd
    ) internal returns (bytes4) {
        vm.prank(caller);
        (bool ok, bytes memory err) = address(verifier).call(
            abi.encodeCall(FluidkeyVerifier.verify, (n, coinType, meta, vd, address(0xdead)))
        );
        return ok ? bytes4(0) : bytes4(err);
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

    // Chains.

    function test_isSupportedChain() public view {
        for (uint256 i; i < chains.length; ++i) {
            assertTrue(verifier.isSupportedChain(chains[i]), vm.toString(chains[i]));
        }
        assertFalse(verifier.isSupportedChain(0x80000000), "default EVM coin type");
        assertFalse(verifier.isSupportedChain(0x80000001), "chain 1 under ENSIP-19 encoding");
        assertFalse(verifier.isSupportedChain(0), "Bitcoin");
        assertFalse(verifier.isSupportedChain(0x80aa36a7), "Sepolia");
        assertFalse(verifier.isSupportedChain(0x80000144), "zkSync Era");
    }

    /// @dev Both modes refuse any other coin type, even with a signature for it.
    function testFuzz_unsupportedChain(uint256 coinType) public {
        vm.assume(!_listed(coinType));
        FluidkeyVectors.Vector memory v = vectors[4];
        bytes memory vd = bytes.concat(
            v.verificationData,
            _signVerified(SIGNER_KEY, resolver, node, coinType, v.stealthAddress)
        );
        bytes memory err =
            abi.encodeWithSelector(FluidkeyVerifier.UnsupportedChain.selector, coinType);
        vm.startPrank(resolver);
        vm.expectRevert(err);
        verifier.verify(node, coinType, v.metaAddress, vd, v.stealthAddress);

        uint64 expires = uint64(block.timestamp + 300);
        vd = abi.encode(
            expires, _sign(SIGNER_KEY, resolver, node, coinType, v.stealthAddress, expires)
        );
        vm.expectRevert(err);
        verifier.verify(node, coinType, "", vd, v.stealthAddress);
        vm.stopPrank();
    }

    // Verified mode: the derivation.

    /// @dev The template rebuilds the auto-earn v1.1 setup data Fluidkey publishes, byte for byte.
    function test_setupData_isKitV1_1() public view {
        assertEq(
            verifier.setupData(FluidkeyVectors.PROD_CONFIG_HASH), FluidkeyVectors.PROD_SETUP_DATA
        );
    }

    /// @dev Every Safe setup and parity combination, and the Safe address from the kit's owner.
    function test_vectors() public {
        for (uint256 i; i < vectors.length; ++i) {
            FluidkeyVectors.Vector memory v = vectors[i];
            assertEq(_verify(v.metaAddress, _signedVd(v)), v.stealthAddress, vm.toString(i));
            assertEq(
                verifier.safeAddress(v.owner, _configHash(v.metaAddress)),
                v.stealthAddress,
                vm.toString(i)
            );
        }
    }

    /// @dev Any node and supported chain, whatever the gateway claims.
    function testFuzz_verified_independentOfClaimed(
        uint8 i,
        bytes32 n,
        uint8 chain,
        address claimed
    ) public {
        FluidkeyVectors.Vector memory v = vectors[i % vectors.length];
        uint256 coinType = chains[chain % chains.length];
        bytes memory vd = bytes.concat(
            v.verificationData, _signVerified(SIGNER_KEY, resolver, n, coinType, v.stealthAddress)
        );
        vm.prank(resolver);
        assertEq(verifier.verify(n, coinType, v.metaAddress, vd, claimed), v.stealthAddress);
    }

    /// @dev The configHash in the record decides the Safe: the same keys under another setup give
    ///      another address, so the gateway cannot choose the setup.
    function test_configHashSelectsSafe() public {
        FluidkeyVectors.Vector memory v = vectors[0];
        bytes memory meta = bytes.concat(_slice(v.metaAddress, 0, 33), bytes32(uint256(1)));
        address other = verifier.safeAddress(v.owner, 1);
        assertTrue(other != v.stealthAddress);
        bytes memory vd =
            bytes.concat(v.verificationData, _signVerified(SIGNER_KEY, resolver, node, 60, other));
        assertEq(_verify(meta, vd), other);
        // A signature over the Safe of the other setup does not carry over.
        assertEq(
            _verified(resolver, node, 60, meta, _signedVd(v)),
            FluidkeyVerifier.UnknownSigner.selector
        );
    }

    function test_metaAddressMalformed() public {
        bytes memory meta = vectors[0].metaAddress;
        bytes memory vd = _signedVd(vectors[0]);
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
        bytes memory vd = _signedVd(vectors[0]);
        bytes4 err = FluidkeyVerifier.InvalidVerificationData.selector;
        _expectVerifyRevert(err, meta, _slice(vd, 0, 160));
        _expectVerifyRevert(err, meta, abi.encodePacked(vd, hex"00"));
        _expectVerifyRevert(err, meta, _withWord(vd, 0, 0));
        _expectVerifyRevert(err, meta, _withWord(vd, 0, N));
    }

    function test_wrongSharedSecret() public {
        bytes memory meta = vectors[0].metaAddress;
        bytes memory vd = _signedVd(vectors[0]);
        bytes4 err = FluidkeyVerifier.InvalidSharedSecret.selector;
        bytes memory other = bytes.concat(
            _slice(vd, 0, 32), _slice(vectors[1].verificationData, 32, 64), _slice(vd, 96, 65)
        );
        _expectVerifyRevert(err, meta, other);
        uint256 y = uint256(bytes32(_slice(vd, 64, 32)));
        _expectVerifyRevert(err, meta, _withWord(vd, 64, P - y)); // -S
    }

    // Verified mode: the signature.

    /// @dev Any `e` with its point passes the curve checks, so only a signer's signature makes a
    ///      derivation Fluidkey's: one from a batch gateway's own `e`, which Fluidkey cannot
    ///      regenerate, is refused unsigned or signed by anyone else.
    function test_verified_unsignedOrNotASigner() public {
        FluidkeyVectors.Vector memory v = vectors[4];
        _expectVerifyRevert(
            FluidkeyVerifier.InvalidVerificationData.selector, v.metaAddress, v.verificationData
        );
        bytes memory vd = bytes.concat(
            v.verificationData, _signVerified(0xBAD, resolver, node, 60, v.stealthAddress)
        );
        vm.expectRevert(
            abi.encodeWithSelector(FluidkeyVerifier.UnknownSigner.selector, vm.addr(0xBAD))
        );
        _verify(v.metaAddress, vd);
    }

    /// @dev The signature binds the resolver, node, coin type and Safe; an unverified-mode
    ///      signature over the same fields is not one.
    function test_verified_signatureBinds() public {
        FluidkeyVectors.Vector memory v = vectors[4];
        bytes memory meta = v.metaAddress;
        bytes memory vd = _signedVd(v);
        bytes4 unknown = FluidkeyVerifier.UnknownSigner.selector;
        assertEq(_verified(resolver, node, 60, meta, vd), bytes4(0), "control");
        assertEq(_verified(makeAddr("other resolver"), node, 60, meta, vd), unknown, "resolver");
        assertEq(_verified(resolver, keccak256("x"), 60, meta, vd), unknown, "node");
        assertEq(_verified(resolver, node, 0x80002105, meta, vd), unknown, "coin type");
        bytes memory otherSafe = bytes.concat(
            v.verificationData, _signVerified(SIGNER_KEY, resolver, node, 60, makeAddr("x"))
        );
        assertEq(_verified(resolver, node, 60, meta, otherSafe), unknown, "Safe");
        bytes memory unverifiedType = bytes.concat(
            v.verificationData,
            _sign(SIGNER_KEY, resolver, node, 60, v.stealthAddress, type(uint64).max)
        );
        assertEq(_verified(resolver, node, 60, meta, unverifiedType), unknown, "type");
    }

    /// @dev A malformed signature (high s, bad v) is `UnknownSigner(0)`: the error carries no word
    ///      the gateway chose, even if the zero address were ever listed as a signer.
    function test_verified_malformedSignature() public {
        FluidkeyVectors.Vector memory v = vectors[4];
        signers.setSigner(address(0), true);
        bytes32 highS =
            bytes32(abi.encodePacked(bytes8(0xffffffffffffffff), makeAddr("x"), bytes4(0)));
        bytes[2] memory sigs = [
            abi.encodePacked(bytes32(uint256(1)), highS, uint8(27)),
            abi.encodePacked(bytes32(uint256(1)), bytes32(uint256(1)), uint8(29))
        ];
        for (uint256 i; i < sigs.length; ++i) {
            vm.expectRevert(
                abi.encodeWithSelector(FluidkeyVerifier.UnknownSigner.selector, address(0))
            );
            _verify(v.metaAddress, bytes.concat(v.verificationData, sigs[i]));
        }
    }

    /// @dev A verified response does not expire: replayed later, it answers the same Safe.
    function test_verified_doesNotExpire() public {
        FluidkeyVectors.Vector memory v = vectors[4];
        bytes memory vd = _signedVd(v);
        vm.warp(block.timestamp + 3650 days);
        assertEq(_verify(v.metaAddress, vd), v.stealthAddress);
    }

    /// @dev Removing a signer refuses its responses from then on.
    function test_verified_removedSigner() public {
        FluidkeyVectors.Vector memory v = vectors[4];
        bytes memory vd = _signedVd(v);
        signers.setSigner(vm.addr(SIGNER_KEY), false);
        assertEq(
            _verified(resolver, node, 60, v.metaAddress, vd),
            FluidkeyVerifier.UnknownSigner.selector
        );
    }

    // Unverified mode: signed responses.

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

    /// @dev `expires` at most `MAX_VALIDITY` ahead, so a kept response is served again for that
    ///      long at most.
    function test_unverified_expiryCap() public {
        address claimed = makeAddr("safe");
        uint64 limit = uint64(block.timestamp + verifier.MAX_VALIDITY());
        assertEq(verifier.MAX_VALIDITY(), 10 minutes);
        assertEq(
            _unverified(resolver, node, 60, _signed(SIGNER_KEY, claimed, limit), claimed), bytes4(0)
        );
        vm.prank(resolver);
        vm.expectRevert(abi.encodeWithSelector(FluidkeyVerifier.ExpiryTooFar.selector, limit + 1));
        verifier.verify(node, 60, "", _signed(SIGNER_KEY, claimed, limit + 1), claimed);
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

    /// @dev A signature binds the resolver, node, coin type, address and expiry; a verified-mode
    ///      signature over the same fields is not one.
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
        bytes memory verifiedType =
            abi.encode(expires, _signVerified(SIGNER_KEY, resolver, node, 60, claimed));
        assertEq(_unverified(resolver, node, 60, verifiedType, claimed), unknown, "type");
    }

    /// @dev The high-s twin of a valid signature is refused as malformed: `UnknownSigner(0)`.
    function test_unverified_malleableSignature() public {
        address claimed = makeAddr("safe");
        uint64 expires = uint64(block.timestamp + 300);
        (, bytes memory sig) = abi.decode(_signed(SIGNER_KEY, claimed, expires), (uint64, bytes));
        bytes32 r = bytes32(_slice(sig, 0, 32));
        uint256 s = uint256(bytes32(_slice(sig, 32, 32)));
        uint8 v = uint8(sig[64]);
        bytes memory twin = abi.encodePacked(r, bytes32(N - s), v == 27 ? uint8(28) : uint8(27));
        vm.prank(resolver);
        vm.expectRevert(abi.encodeWithSelector(FluidkeyVerifier.UnknownSigner.selector, address(0)));
        verifier.verify(node, 60, "", abi.encode(expires, twin), claimed);
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
