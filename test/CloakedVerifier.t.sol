// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test, Vm} from "forge-std/Test.sol";

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {CloakedSigners, ICloakedSigners} from "../src/verifiers/CloakedSigners.sol";
import {CloakedVerifier} from "../src/verifiers/CloakedVerifier.sol";
import {CloakedVectors} from "./utils/CloakedVectors.sol";

/// @dev CloakedVerifier against the known answers in clkd-stealth's own tests and against
///      derivations computed from private keys, as its `genStealthPrivateKey` does, every
///      rejection, and the signatures of both modes.
contract CloakedVerifierTest is Test {
    uint256 internal constant N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 internal constant P =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    /// @dev Placeholder scheme ID, ASCII "CLK1", until Cloaked's is declared.
    uint256 internal constant SCHEME_ID = 0x434C4B31;
    uint256 internal constant SIGNER_KEY = 0xC1;

    /// @dev One derivation: what the record and the gateway carry, and the result.
    struct Vector {
        bytes metaAddress;
        bytes verificationData;
        address stealthAddress;
        uint256 stealthKey;
    }

    CloakedSigners internal signers;
    CloakedVerifier internal verifier;
    Vector[4] internal vectors;

    address internal resolver = makeAddr("resolver");
    bytes32 internal node = keccak256("bob.cloaked.eth");

    function setUp() public {
        signers = new CloakedSigners(address(this));
        signers.setSigner(vm.addr(SIGNER_KEY), true);
        verifier = new CloakedVerifier(SCHEME_ID, signers);
        // One vector per parity of the spending key (bit 1) and shared secret point (bit 0).
        uint256 found;
        for (uint256 i; found < 4; ++i) {
            Vector memory v = _vector(_key("spend", i), _key("ephemeral", i));
            uint256 slot = (uint8(v.metaAddress[0]) - 2) * 2 + (uint8(v.verificationData[95]) & 1);
            if (vectors[slot].stealthAddress != address(0)) continue;
            vectors[slot] = v;
            ++found;
        }
    }

    function _key(string memory label, uint256 i) internal pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(label, i))) % (N - 1) + 1;
    }

    /// @dev The derivation from the private keys, without the verifier's `ecrecover` route:
    ///      S = (e·p_spend)·G, h = keccak256(S.x || S.y) mod n, stealth key = p_spend·h mod n.
    function _vector(uint256 spendKey, uint256 e) internal returns (Vector memory v) {
        Vm.Wallet memory spend = vm.createWallet(spendKey);
        Vm.Wallet memory shared = vm.createWallet(mulmod(e, spendKey, N));
        v.metaAddress = abi.encodePacked(uint8(2 + (spend.publicKeyY & 1)), spend.publicKeyX);
        v.verificationData = abi.encodePacked(e, shared.publicKeyX, shared.publicKeyY);
        uint256 h = uint256(keccak256(abi.encodePacked(shared.publicKeyX, shared.publicKeyY))) % N;
        v.stealthKey = mulmod(spendKey, h, N);
        v.stealthAddress = vm.addr(v.stealthKey);
    }

    // Signatures, built independently of the verifier.

    function _signStruct(uint256 key, bytes32 structHash) internal view returns (bytes memory) {
        bytes32 domain = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256("CloakedVerifier"),
                keccak256("1"),
                block.chainid,
                address(verifier)
            )
        );
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(key, keccak256(abi.encodePacked(hex"1901", domain, structHash)));
        return abi.encodePacked(r, s, v);
    }

    /// @dev A signature over a verified response: the address the derivation gives.
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

    /// @dev A vector's verification data as Cloaked's gateway sends it for `resolver`, `node` and
    ///      Ethereum: the derivation, then the signature over its address.
    function _signedVd(Vector memory v) internal view returns (bytes memory) {
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
        (bool ok, bytes memory err) = address(verifier)
            .call(abi.encodeCall(CloakedVerifier.verify, (n, coinType, meta, vd, address(0xdead))));
        return ok ? bytes4(0) : bytes4(err);
    }

    // Deployment.

    function test_schemeId() public view {
        assertEq(verifier.schemeId(), SCHEME_ID);
    }

    function test_constructor_rejects() public {
        vm.expectRevert(abi.encodeWithSelector(CloakedVerifier.InvalidSchemeId.selector, 0));
        new CloakedVerifier(0, signers);
        vm.expectRevert(abi.encodeWithSelector(CloakedVerifier.InvalidSchemeId.selector, 1));
        new CloakedVerifier(1, signers);
        address eoa = makeAddr("eoa");
        vm.expectRevert(abi.encodeWithSelector(CloakedVerifier.InvalidSigners.selector, eoa));
        new CloakedVerifier(SCHEME_ID, ICloakedSigners(eoa));
    }

    // Chains: no list in the verifier; the signature, bound to the coin type, is the gate.

    /// @dev Any coin type verifies when a signer signed for it, in both modes.
    function testFuzz_anyCoinTypeWhenSigned(uint256 coinType) public {
        Vector memory v = vectors[0];
        bytes memory vd = bytes.concat(
            v.verificationData,
            _signVerified(SIGNER_KEY, resolver, node, coinType, v.stealthAddress)
        );
        vm.startPrank(resolver);
        assertEq(
            verifier.verify(node, coinType, v.metaAddress, vd, v.stealthAddress), v.stealthAddress
        );

        uint64 expires = uint64(block.timestamp + 300);
        vd = abi.encode(
            expires, _sign(SIGNER_KEY, resolver, node, coinType, v.stealthAddress, expires)
        );
        assertEq(verifier.verify(node, coinType, "", vd, v.stealthAddress), v.stealthAddress);
        vm.stopPrank();
    }

    // Verified mode: the derivation.

    /// @dev The addresses (and keys) Cloaked's own tests expect: the verifier returns each one
    ///      from its spending key in the record and its ephemeral key in the response.
    function test_cloakedVectors() public {
        CloakedVectors.Vector[] memory all = CloakedVectors.all();
        for (uint256 i; i < all.length; ++i) {
            CloakedVectors.Vector memory c = all[i];
            Vector memory v = _vector(c.spendKey, c.ephemeralKey);
            assertEq(_verify(v.metaAddress, _signedVd(v)), c.stealthAddress, c.label);
            if (c.stealthKey != 0) assertEq(v.stealthKey, c.stealthKey, c.label);
        }
    }

    /// @dev Every parity combination.
    function test_vectors() public {
        for (uint256 i; i < vectors.length; ++i) {
            assertEq(
                _verify(vectors[i].metaAddress, _signedVd(vectors[i])), vectors[i].stealthAddress
            );
        }
    }

    /// @dev Any spending key and ephemeral key: the address of the key Cloaked's client derives.
    function testFuzz_derivation(uint256 spendKey, uint256 e) public {
        Vector memory v = _vector(bound(spendKey, 1, N - 1), bound(e, 1, N - 1));
        assertEq(_verify(v.metaAddress, _signedVd(v)), v.stealthAddress);
    }

    /// @dev Any node and coin type, whatever the gateway claims.
    function testFuzz_verified_independentOfClaimed(
        uint8 i,
        bytes32 n,
        uint256 coinType,
        address claimed
    ) public {
        Vector memory v = vectors[i % vectors.length];
        bytes memory vd = bytes.concat(
            v.verificationData, _signVerified(SIGNER_KEY, resolver, n, coinType, v.stealthAddress)
        );
        vm.prank(resolver);
        assertEq(verifier.verify(n, coinType, v.metaAddress, vd, claimed), v.stealthAddress);
    }

    function test_metaAddressMalformed() public {
        bytes memory meta = vectors[0].metaAddress;
        bytes memory vd = _signedVd(vectors[0]);
        bytes4 err = CloakedVerifier.MalformedMetaAddress.selector;
        _expectVerifyRevert(err, _slice(meta, 0, 32), vd);
        _expectVerifyRevert(err, abi.encodePacked(meta, hex"00"), vd);
        // Two keys, as a scheme 1 meta-address has.
        _expectVerifyRevert(err, abi.encodePacked(meta, vectors[1].metaAddress), vd);
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
        bytes4 err = CloakedVerifier.InvalidVerificationData.selector;
        _expectVerifyRevert(err, meta, _slice(vd, 0, 160));
        _expectVerifyRevert(err, meta, abi.encodePacked(vd, hex"00"));
        _expectVerifyRevert(err, meta, _withWord(vd, 0, 0));
        _expectVerifyRevert(err, meta, _withWord(vd, 0, N));
    }

    function test_wrongSharedSecret() public {
        bytes memory meta = vectors[0].metaAddress;
        bytes memory vd = _signedVd(vectors[0]);
        bytes4 err = CloakedVerifier.InvalidSharedSecret.selector;
        bytes memory other = bytes.concat(
            _slice(vd, 0, 32), _slice(vectors[1].verificationData, 32, 64), _slice(vd, 96, 65)
        );
        _expectVerifyRevert(err, meta, other);
        uint256 y = uint256(bytes32(_slice(vd, 64, 32)));
        _expectVerifyRevert(err, meta, _withWord(vd, 64, P - y)); // -S
    }

    // Verified mode: the signature.

    /// @dev Any `e` with its point passes the curve checks, so only a signer's signature makes a
    ///      derivation Cloaked's: one from a batch gateway's own `e`, which Cloaked cannot
    ///      regenerate, is refused unsigned or signed by anyone else.
    function test_verified_unsignedOrNotASigner() public {
        Vector memory v = vectors[0];
        _expectVerifyRevert(
            CloakedVerifier.InvalidVerificationData.selector, v.metaAddress, v.verificationData
        );
        bytes memory vd = bytes.concat(
            v.verificationData, _signVerified(0xBAD, resolver, node, 60, v.stealthAddress)
        );
        vm.expectRevert(abi.encodeWithSelector(CloakedVerifier.UnknownSigner.selector));
        _verify(v.metaAddress, vd);
    }

    /// @dev The signature binds the resolver, node, coin type and address; an unverified-mode
    ///      signature over the same fields is not one.
    function test_verified_signatureBinds() public {
        Vector memory v = vectors[0];
        bytes memory meta = v.metaAddress;
        bytes memory vd = _signedVd(v);
        bytes4 unknown = CloakedVerifier.UnknownSigner.selector;
        assertEq(_verified(resolver, node, 60, meta, vd), bytes4(0), "control");
        assertEq(_verified(makeAddr("other resolver"), node, 60, meta, vd), unknown, "resolver");
        assertEq(_verified(resolver, keccak256("x"), 60, meta, vd), unknown, "node");
        assertEq(_verified(resolver, node, 0x80002105, meta, vd), unknown, "coin type");
        bytes memory otherAddress = bytes.concat(
            v.verificationData, _signVerified(SIGNER_KEY, resolver, node, 60, makeAddr("x"))
        );
        assertEq(_verified(resolver, node, 60, meta, otherAddress), unknown, "address");
        bytes memory unverifiedType = bytes.concat(
            v.verificationData,
            _sign(SIGNER_KEY, resolver, node, 60, v.stealthAddress, type(uint64).max)
        );
        assertEq(_verified(resolver, node, 60, meta, unverifiedType), unknown, "type");
    }

    /// @dev A signature for the same address over another meta-address does not carry over: the
    ///      derivation with another spending key gives another address.
    function test_verified_signatureForOtherKey() public {
        Vector memory v = vectors[0];
        Vector memory w = vectors[1];
        bytes memory vd = bytes.concat(
            w.verificationData, _signVerified(SIGNER_KEY, resolver, node, 60, v.stealthAddress)
        );
        assertEq(
            _verified(resolver, node, 60, v.metaAddress, vd),
            CloakedVerifier.InvalidSharedSecret.selector
        );
    }

    /// @dev A malformed signature (high s, bad v) is `UnknownSigner`, even if the zero address were
    ///      ever listed as a signer.
    function test_verified_malformedSignature() public {
        Vector memory v = vectors[0];
        signers.setSigner(address(0), true);
        bytes32 highS =
            bytes32(abi.encodePacked(bytes8(0xffffffffffffffff), makeAddr("x"), bytes4(0)));
        bytes[2] memory sigs = [
            abi.encodePacked(bytes32(uint256(1)), highS, uint8(27)),
            abi.encodePacked(bytes32(uint256(1)), bytes32(uint256(1)), uint8(29))
        ];
        for (uint256 i; i < sigs.length; ++i) {
            vm.expectRevert(abi.encodeWithSelector(CloakedVerifier.UnknownSigner.selector));
            _verify(v.metaAddress, bytes.concat(v.verificationData, sigs[i]));
        }
    }

    /// @dev A verified response does not expire: replayed later, it answers the same address.
    function test_verified_doesNotExpire() public {
        Vector memory v = vectors[0];
        bytes memory vd = _signedVd(v);
        vm.warp(block.timestamp + 3650 days);
        assertEq(_verify(v.metaAddress, vd), v.stealthAddress);
    }

    /// @dev Removing a signer refuses its responses from then on.
    function test_verified_removedSigner() public {
        Vector memory v = vectors[0];
        bytes memory vd = _signedVd(v);
        signers.setSigner(vm.addr(SIGNER_KEY), false);
        assertEq(
            _verified(resolver, node, 60, v.metaAddress, vd), CloakedVerifier.UnknownSigner.selector
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
        (bool ok, bytes memory err) =
            address(verifier).call(abi.encodeCall(CloakedVerifier.verify, (n, coinType, "", vd, c)));
        return ok ? bytes4(0) : bytes4(err);
    }

    function test_unverified_signed() public {
        address claimed = makeAddr("stealth");
        uint64 expires = uint64(block.timestamp + 300);
        vm.prank(resolver);
        assertEq(
            verifier.verify(node, 60, "", _signed(SIGNER_KEY, claimed, expires), claimed), claimed
        );
    }

    /// @dev 65 bytes r || s || v, v 27 or 28. The same signature with v as 0 or 1, or in EIP-2098
    ///      compact form, is refused.
    function test_unverified_signatureFormat() public {
        address claimed = makeAddr("stealth");
        uint64 expires = uint64(block.timestamp + 300);
        bytes memory sig = _sign(SIGNER_KEY, resolver, node, 60, claimed, expires);
        (bytes32 r, bytes32 s) = abi.decode(sig, (bytes32, bytes32));
        uint8 v = uint8(sig[64]);
        bytes32 vs = bytes32(uint256(s) | (uint256(v - 27) << 255));
        bytes[2] memory refused = [abi.encodePacked(r, s, v - 27), abi.encodePacked(r, vs)];
        assertEq(_unverified(resolver, node, 60, abi.encode(expires, sig), claimed), bytes4(0));
        for (uint256 i; i < refused.length; ++i) {
            assertEq(
                _unverified(resolver, node, 60, abi.encode(expires, refused[i]), claimed),
                CloakedVerifier.UnknownSigner.selector
            );
        }
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
        address claimed = makeAddr("stealth");
        uint64 expires = uint64(block.timestamp + 300);
        bytes memory vd = _signed(SIGNER_KEY, claimed, expires);
        vm.warp(expires + 1);
        vm.prank(resolver);
        vm.expectRevert(abi.encodeWithSelector(CloakedVerifier.SignatureExpired.selector));
        verifier.verify(node, 60, "", vd, claimed);
    }

    /// @dev `expires` at most `MAX_VALIDITY` ahead, so a kept response is served again for that
    ///      long at most.
    function test_unverified_expiryCap() public {
        address claimed = makeAddr("stealth");
        uint64 limit = uint64(block.timestamp + verifier.MAX_VALIDITY());
        assertEq(verifier.MAX_VALIDITY(), 10 minutes);
        assertEq(
            _unverified(resolver, node, 60, _signed(SIGNER_KEY, claimed, limit), claimed), bytes4(0)
        );
        vm.prank(resolver);
        vm.expectRevert(abi.encodeWithSelector(CloakedVerifier.ExpiryTooFar.selector));
        verifier.verify(node, 60, "", _signed(SIGNER_KEY, claimed, limit + 1), claimed);
    }

    function test_unverified_notASigner() public {
        address claimed = makeAddr("stealth");
        uint64 expires = uint64(block.timestamp + 300);
        vm.prank(resolver);
        vm.expectRevert(abi.encodeWithSelector(CloakedVerifier.UnknownSigner.selector));
        verifier.verify(node, 60, "", _signed(0xBAD, claimed, expires), claimed);
    }

    function test_unverified_removedSigner() public {
        address claimed = makeAddr("stealth");
        uint64 expires = uint64(block.timestamp + 300);
        bytes memory vd = _signed(SIGNER_KEY, claimed, expires);
        signers.setSigner(vm.addr(SIGNER_KEY), false);
        assertEq(
            _unverified(resolver, node, 60, vd, claimed), CloakedVerifier.UnknownSigner.selector
        );
    }

    /// @dev A signature binds the resolver, node, coin type, address and expiry; a verified-mode
    ///      signature over the same fields is not one.
    function test_unverified_noReplay() public {
        address claimed = makeAddr("stealth");
        uint64 expires = uint64(block.timestamp + 300);
        bytes memory vd = _signed(SIGNER_KEY, claimed, expires);
        bytes4 unknown = CloakedVerifier.UnknownSigner.selector;
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

    /// @dev The high-s twin of a valid signature is refused as malformed: `UnknownSigner`.
    function test_unverified_malleableSignature() public {
        address claimed = makeAddr("stealth");
        uint64 expires = uint64(block.timestamp + 300);
        (, bytes memory sig) = abi.decode(_signed(SIGNER_KEY, claimed, expires), (uint64, bytes));
        bytes32 r = bytes32(_slice(sig, 0, 32));
        uint256 s = uint256(bytes32(_slice(sig, 32, 32)));
        uint8 v = uint8(sig[64]);
        bytes memory twin = abi.encodePacked(r, bytes32(N - s), v == 27 ? uint8(28) : uint8(27));
        vm.prank(resolver);
        vm.expectRevert(abi.encodeWithSelector(CloakedVerifier.UnknownSigner.selector));
        verifier.verify(node, 60, "", abi.encode(expires, twin), claimed);
    }

    /// @dev No signature at all: the response does not decode.
    function test_unverified_unsignedReverts() public {
        vm.prank(resolver);
        vm.expectRevert();
        verifier.verify(node, 60, "", "", makeAddr("stealth"));
    }

    /// @dev The signer domains are separate: a Fluidkey-shaped signature for this verifier's
    ///      fields under another verifier's domain name is refused.
    function test_otherDomainRefused() public {
        address claimed = makeAddr("stealth");
        uint64 expires = uint64(block.timestamp + 300);
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
                resolver,
                node,
                uint256(60),
                claimed,
                expires
            )
        );
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(SIGNER_KEY, keccak256(abi.encodePacked(hex"1901", domain, structHash)));
        assertEq(
            _unverified(
                resolver, node, 60, abi.encode(expires, abi.encodePacked(r, s, v)), claimed
            ),
            CloakedVerifier.UnknownSigner.selector
        );
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

    /// @dev The owner cannot renounce: the signer set, leaked keys included, would be frozen.
    function test_signers_renounceDisabled() public {
        vm.expectRevert(CloakedSigners.RenounceDisabled.selector);
        signers.renounceOwnership();
        assertEq(signers.owner(), address(this));
    }

    function test_signers_setAndTwoStepTransfer() public {
        address signer = makeAddr("signer");
        vm.expectEmit(address(signers));
        emit CloakedSigners.SignerChanged(signer, true);
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
