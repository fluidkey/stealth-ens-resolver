// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test} from "forge-std/Test.sol";

import {Scheme1Verifier} from "../src/verifiers/Scheme1Verifier.sol";
import {Scheme1Vectors} from "./utils/Scheme1Vectors.sol";

/// @dev Scheme1Verifier against derivations by the ScopeLift SDK, and every rejection.
contract Scheme1VerifierTest is Test {
    uint256 internal constant N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 internal constant P =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    /// @dev x³ + 7 is not a square mod p: no curve point has this x-coordinate.
    uint256 internal constant OFF_CURVE_X = 5;

    Scheme1Verifier internal verifier;
    Scheme1Vectors.Vector[] internal vectors;

    function setUp() public {
        verifier = new Scheme1Verifier();
        Scheme1Vectors.Vector[] memory all = Scheme1Vectors.all();
        for (uint256 i; i < all.length; ++i) {
            vectors.push(all[i]);
        }
    }

    function _verify(bytes memory meta, bytes memory vd) internal view returns (address) {
        return verifier.verify(bytes32(0), 60, meta, vd, address(0xdead));
    }

    function _expectVerifyRevert(bytes4 error, bytes memory meta, bytes memory vd) internal {
        vm.expectRevert(error);
        _verify(meta, vd);
    }

    function test_schemeId() public view {
        assertEq(verifier.schemeId(), 1);
    }

    /// @dev Every parity combination of spending key, viewing key and shared secret point.
    function test_vectors() public view {
        for (uint256 i; i < vectors.length; ++i) {
            Scheme1Vectors.Vector memory v = vectors[i];
            assertEq(_verify(v.metaAddress, v.verificationData), v.stealthAddress, vm.toString(i));
        }
    }

    /// @dev Verified mode never reads `claimed`, the node or the coin type.
    function testFuzz_independentOfClaimed(uint8 i, bytes32 node, uint256 coinType, address claimed)
        public
        view
    {
        Scheme1Vectors.Vector memory v = vectors[i % vectors.length];
        assertEq(
            verifier.verify(node, coinType, v.metaAddress, v.verificationData, claimed),
            v.stealthAddress
        );
    }

    /// @dev Unverified mode returns the gateway's address, whatever the verification data.
    function testFuzz_unverifiedReturnsClaimed(bytes calldata vd, address claimed) public view {
        assertEq(verifier.verify(bytes32(0), 60, "", vd, claimed), claimed);
    }

    // Malformed meta-addresses (ENSIP-30 Section 1 failure semantics).

    function test_metaAddressLength() public {
        bytes memory meta = vectors[0].metaAddress;
        bytes memory vd = vectors[0].verificationData;
        bytes4 err = Scheme1Verifier.MalformedMetaAddress.selector;
        _expectVerifyRevert(err, abi.encodePacked(meta, hex"00"), vd);
        _expectVerifyRevert(err, _slice(meta, 0, 65), vd);
        _expectVerifyRevert(err, _slice(meta, 0, 33), vd);
    }

    /// @dev Each key: bad prefix, x zero, x at or above n, x off the curve.
    function test_badKeys() public {
        bytes memory vd = vectors[0].verificationData;
        bytes4 err = Scheme1Verifier.MalformedMetaAddress.selector;
        for (uint256 k; k < 2; ++k) {
            bytes memory meta = vectors[0].metaAddress;
            uint256 at = k * 33;
            bytes memory m = bytes.concat(meta);
            m[at] = 0x04;
            _expectVerifyRevert(err, m, vd);
            m[at] = 0x00;
            _expectVerifyRevert(err, m, vd);
            _expectVerifyRevert(err, _withX(meta, at, 0), vd);
            _expectVerifyRevert(err, _withX(meta, at, N), vd);
            _expectVerifyRevert(err, _withX(meta, at, type(uint256).max), vd);
            _expectVerifyRevert(err, _withX(meta, at, OFF_CURVE_X), vd);
        }
    }

    // Malformed verification data.

    function test_verificationDataLength() public {
        bytes memory meta = vectors[0].metaAddress;
        bytes memory vd = vectors[0].verificationData;
        bytes4 err = Scheme1Verifier.InvalidVerificationData.selector;
        _expectVerifyRevert(err, meta, "");
        _expectVerifyRevert(err, meta, _slice(vd, 0, 32));
        _expectVerifyRevert(err, meta, _slice(vd, 0, 95));
        _expectVerifyRevert(err, meta, abi.encodePacked(vd, hex"00"));
    }

    /// @dev The ephemeral key must be in [1, n - 1]; e + n is the same point but not canonical.
    function test_ephemeralKeyRange() public {
        bytes memory meta = vectors[0].metaAddress;
        bytes memory vd = vectors[0].verificationData;
        bytes4 err = Scheme1Verifier.InvalidVerificationData.selector;
        uint256 e = uint256(bytes32(_slice(vd, 0, 32)));
        _expectVerifyRevert(err, meta, _withWord(vd, 0, 0));
        _expectVerifyRevert(err, meta, _withWord(vd, 0, N));
        if (e < type(uint256).max - N) _expectVerifyRevert(err, meta, _withWord(vd, 0, e + N));
    }

    // Wrong shared secret: the gateway cannot choose S.

    function test_sharedSecretFromAnotherDerivation() public {
        bytes memory vd = bytes.concat(
            _slice(vectors[0].verificationData, 0, 32), _slice(vectors[1].verificationData, 32, 64)
        );
        _expectVerifyRevert(
            Scheme1Verifier.InvalidSharedSecret.selector, vectors[0].metaAddress, vd
        );
    }

    /// @dev -S has the same x and the other parity: a different point, so a different address.
    function test_negatedSharedSecret() public {
        bytes memory vd = vectors[0].verificationData;
        uint256 y = uint256(bytes32(_slice(vd, 64, 32)));
        _expectVerifyRevert(
            Scheme1Verifier.InvalidSharedSecret.selector,
            vectors[0].metaAddress,
            _withWord(vd, 64, P - y)
        );
    }

    function test_otherEphemeralKey() public {
        bytes memory vd = vectors[0].verificationData;
        uint256 e = uint256(bytes32(_slice(vd, 0, 32)));
        _expectVerifyRevert(
            Scheme1Verifier.InvalidSharedSecret.selector,
            vectors[0].metaAddress,
            _withWord(vd, 0, e % (N - 1) + 1)
        );
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

    /// @dev The meta-address with the x-coordinate of the key at `at` replaced.
    function _withX(bytes memory meta, uint256 at, uint256 x) internal pure returns (bytes memory) {
        return _withWord(meta, at + 1, x);
    }
}
