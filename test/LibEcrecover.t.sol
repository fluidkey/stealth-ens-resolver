// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test, Vm} from "forge-std/Test.sol";

import {LibEcrecover} from "../src/verifiers/LibEcrecover.sol";
import {VRF} from "./reference/ChainlinkVRF.sol";

/// @dev Exposes Chainlink VRF's internal `ecrecover` checks.
contract ChainlinkVRFHarness is VRF {
    function linearCombination(uint256 c, uint256[2] memory p, uint256 s, address witness)
        external
        pure
        returns (bool)
    {
        return _verifyLinearCombinationWithGenerator(c, p, s, witness);
    }

    function ecmulVerify(uint256[2] memory multiplicand, uint256 scalar, uint256[2] memory product)
        external
        pure
        returns (bool)
    {
        return _ecmulVerify(multiplicand, scalar, product);
    }
}

/// @dev LibEcrecover against two independent references: direct key derivation (a·G + b·qG is
///      the public key of a + b·q) and Chainlink VRF's production `ecrecover` checks.
contract LibEcrecoverTest is Test {
    uint256 internal constant N = LibEcrecover.N;

    ChainlinkVRFHarness internal chainlink;

    function setUp() public {
        chainlink = new ChainlinkVRFHarness();
    }

    /// @dev The point Q = q·G, by Foundry's own key derivation.
    function _point(uint256 q) internal returns (uint256 x, uint256 y) {
        Vm.Wallet memory w = vm.createWallet(q);
        (x, y) = (w.publicKeyX, w.publicKeyY);
    }

    function testFuzz_mulAdd_isKeyDerivation(uint256 a, uint256 b, uint256 q) public {
        a = bound(a, 0, N - 1);
        b = bound(b, 1, N - 1);
        q = bound(q, 1, N - 1);
        uint256 k = addmod(a, mulmod(b, q, N), N);
        vm.assume(k != 0);
        (uint256 x, uint256 y) = _point(q);
        vm.assume(x < N);
        assertEq(LibEcrecover.mulAdd(a, b, x, uint8(y & 1)), vm.addr(k));
    }

    function testFuzz_mulAdd_agreesWithChainlinkLinearCombination(uint256 a, uint256 b, uint256 q)
        public
    {
        a = bound(a, 0, N - 1);
        b = bound(b, 1, N - 1);
        q = bound(q, 1, N - 1);
        vm.assume(addmod(a, mulmod(b, q, N), N) != 0);
        (uint256 x, uint256 y) = _point(q);
        vm.assume(x < N);
        address ours = LibEcrecover.mulAdd(a, b, x, uint8(y & 1));
        assertTrue(chainlink.linearCombination(b, [x, y], a, ours));
    }

    function testFuzz_mulAdd_agreesWithChainlinkEcmul(uint256 b, uint256 q) public {
        b = bound(b, 1, N - 1);
        q = bound(q, 1, N - 1);
        (uint256 x, uint256 y) = _point(q);
        (uint256 px, uint256 py) = _point(mulmod(b, q, N));
        vm.assume(x < N);
        assertEq(LibEcrecover.mulAdd(0, b, x, uint8(y & 1)), vm.addr(mulmod(b, q, N)));
        assertTrue(chainlink.ecmulVerify([x, y], b, [px, py]));
    }

    /// @dev x = 5 has no curve point: x³ + 7 is not a square mod p.
    function test_mulAdd_offCurveIsZero() public pure {
        assertEq(LibEcrecover.mulAdd(1, 1, 5, 0), address(0));
    }

    function parse(bytes calldata key) external pure returns (bool, uint256, uint8) {
        return LibEcrecover.compressedKey(key);
    }

    function testFuzz_compressedKey(uint256 q) public {
        q = bound(q, 1, N - 1);
        (uint256 x, uint256 y) = _point(q);
        vm.assume(x < N);
        (bool ok, uint256 px, uint8 parity) =
            this.parse(abi.encodePacked(uint8(2 + (y & 1)), bytes32(x)));
        assertTrue(ok);
        assertEq(px, x);
        assertEq(parity, y & 1);
    }

    function test_compressedKey_rejects() public view {
        bytes32 x = bytes32(uint256(1));
        bool ok;
        (ok,,) = this.parse(abi.encodePacked(hex"04", x));
        assertFalse(ok, "prefix");
        (ok,,) = this.parse(abi.encodePacked(hex"02", bytes32(0)));
        assertFalse(ok, "x zero");
        (ok,,) = this.parse(abi.encodePacked(hex"02", bytes32(N)));
        assertFalse(ok, "x at n");
        (ok,,) = this.parse(abi.encodePacked(hex"02", x, hex"00"));
        assertFalse(ok, "length");
    }

    function test_pointAddress() public {
        (uint256 x, uint256 y) = _point(7);
        assertEq(this.addressOf(abi.encodePacked(x, y)), vm.addr(7));
    }

    function addressOf(bytes calldata xy) external pure returns (address) {
        return LibEcrecover.pointAddress(xy);
    }
}
