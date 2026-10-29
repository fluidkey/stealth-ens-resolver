// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Vm} from "forge-std/Test.sol";

import {IAddrResolver} from "@ens/contracts/resolvers/profiles/IAddrResolver.sol";
import {IAddressResolver} from "@ens/contracts/resolvers/profiles/IAddressResolver.sol";

import {StealthResolver} from "../src/StealthResolver.sol";
import {CloakedSigners} from "../src/verifiers/CloakedSigners.sol";
import {CloakedVerifier} from "../src/verifiers/CloakedVerifier.sol";
import {StealthResolverFixture} from "./utils/StealthResolverFixture.sol";

/// @dev StealthResolver with CloakedVerifier: both ENSIP-30 Section 4 modes end to end. The
///      fixture's mock verifier is replaced in place, so every name keeps its setup.
contract CloakedVerifierResolverTest is StealthResolverFixture {
    uint256 internal constant N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 internal constant SIGNER_KEY = 0xC1;
    uint256 internal constant SPEND_KEY = uint256(keccak256("cloaked spend"));
    uint256 internal constant EPHEMERAL_KEY = uint256(keccak256("cloaked ephemeral"));

    CloakedSigners internal signers;
    bytes internal meta;
    bytes internal derivation;
    address internal stealth;

    function setUp() public override {
        super.setUp();
        signers = new CloakedSigners(address(this));
        signers.setSigner(vm.addr(SIGNER_KEY), true);
        vm.etch(address(verifier), address(new CloakedVerifier(0x434C4B31, signers)).code);

        // As in CloakedVerifierTest: S = (e·p_spend)·G, stealth key = p_spend·keccak256(S) mod n.
        Vm.Wallet memory spend = vm.createWallet(SPEND_KEY);
        Vm.Wallet memory shared = vm.createWallet(mulmod(EPHEMERAL_KEY, SPEND_KEY, N));
        meta = abi.encodePacked(uint8(2 + (spend.publicKeyY & 1)), spend.publicKeyX);
        derivation = abi.encodePacked(EPHEMERAL_KEY, shared.publicKeyX, shared.publicKeyY);
        uint256 h = uint256(keccak256(abi.encodePacked(shared.publicKeyX, shared.publicKeyY))) % N;
        stealth = vm.addr(mulmod(SPEND_KEY, h, N));

        setConfig(alice, "alice.fkey.eth", address(aliceRecords), STEALTH_GW);
        setChain(alice, "alice.fkey.eth", COIN_ETH, true);
        setMeta(alice, "alice.fkey.eth", abi.encodePacked(hex"00", meta));
    }

    function _addr(string memory name) internal view returns (bool ok, bytes memory result) {
        (ok, result) = ccipCall(
            address(resolver),
            abi.encodeCall(
                resolver.resolve, (dns(name), abi.encodeCall(IAddrResolver.addr, (node(name))))
            )
        );
    }

    /// @dev A Cloaked signer's EIP-712 signature, as the unit tests build it.
    function _sig(uint256 key, bytes32 structHash) internal view returns (bytes memory) {
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
        (uint8 sv, bytes32 r, bytes32 s) =
            vm.sign(key, keccak256(abi.encodePacked(hex"1901", domain, structHash)));
        return abi.encodePacked(r, s, sv);
    }

    /// @dev The Cloaked gateway's verified response for `forNode` and `coinType`: the derivation
    ///      and a signature over its address.
    function _signedDerivation(bytes32 forNode, uint256 coinType)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "VerifiedStealthResolution(address resolver,bytes32 node,uint256 coinType,address stealthAddress)"
                ),
                address(resolver),
                forNode,
                coinType,
                stealth
            )
        );
        return bytes.concat(derivation, _sig(SIGNER_KEY, structHash));
    }

    /// @dev The Cloaked gateway's unverified response for `forNode` on Ethereum.
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
        return abi.encode(expires, _sig(SIGNER_KEY, structHash));
    }

    function test_verified() public {
        gwClaimed = stealth;
        gwVerificationData = _signedDerivation(aliceNode, COIN_ETH);
        (bool ok, bytes memory result) = _addr("alice.fkey.eth");
        assertTrue(ok);
        assertEq(abi.decode(abi.decode(result, (bytes)), (address)), stealth);
    }

    function test_verified_lyingGatewayRejected() public {
        gwClaimed = makeAddr("attacker");
        gwVerificationData = _signedDerivation(aliceNode, COIN_ETH);
        (bool ok, bytes memory result) = _addr("alice.fkey.eth");
        assertFalse(ok);
        assertEq(result, abi.encodeWithSelector(StealthResolver.StealthAddressMismatch.selector));
    }

    /// @dev A derivation without the signature, as a batch gateway answering from its own
    ///      ephemeral key would send, or signed for another name, is refused.
    function test_verified_unsignedOrOtherNameRejected() public {
        gwClaimed = stealth;
        gwVerificationData = derivation;
        (bool ok, bytes memory result) = _addr("alice.fkey.eth");
        assertFalse(ok);
        assertEq(bytes4(result), CloakedVerifier.InvalidVerificationData.selector);

        gwVerificationData = _signedDerivation(bobNode, COIN_ETH);
        (ok, result) = _addr("alice.fkey.eth");
        assertFalse(ok);
        assertEq(bytes4(result), CloakedVerifier.UnknownSigner.selector);
    }

    /// @dev The same EOA on another chain the name lists, when Cloaked's gateway signs for it.
    function test_verified_otherChain() public {
        uint256 base = 0x80002105;
        setChain(alice, "alice.fkey.eth", base, true);
        gwClaimed = stealth;
        gwVerificationData = _signedDerivation(aliceNode, base);
        (bool ok, bytes memory result) = ccipCall(
            address(resolver),
            abi.encodeCall(
                resolver.resolve,
                (dns("alice.fkey.eth"), abi.encodeCall(IAddressResolver.addr, (aliceNode, base)))
            )
        );
        assertTrue(ok);
        assertEq(abi.decode(abi.decode(result, (bytes)), (bytes)), abi.encodePacked(stealth));
    }

    /// @dev bob.fkey.eth has no record: the signed response is accepted.
    function test_unverified_signed() public {
        gwClaimed = makeAddr("bob's stealth address");
        gwVerificationData = _signed(bobNode, gwClaimed, uint64(block.timestamp + 300));
        (bool ok, bytes memory result) = _addr("bob.fkey.eth");
        assertTrue(ok);
        assertEq(abi.decode(abi.decode(result, (bytes)), (address)), gwClaimed);
    }

    /// @dev A response signed for another name, or not signed, is refused.
    function test_unverified_unsignedOrOtherNameRejected() public {
        gwClaimed = makeAddr("bob's stealth address");
        gwVerificationData = _signed(aliceNode, gwClaimed, uint64(block.timestamp + 300));
        (bool ok, bytes memory result) = _addr("bob.fkey.eth");
        assertFalse(ok);
        assertEq(bytes4(result), CloakedVerifier.UnknownSigner.selector);

        gwVerificationData = "";
        (ok,) = _addr("bob.fkey.eth");
        assertFalse(ok);
    }

    /// @dev The verifier's own cost in verified mode, written to `snapshots/Gas.json`. Each mode
    ///      is its own test, so each starts cold, as the first call in a transaction does.
    function test_gas_verified() public {
        bytes memory call = abi.encodeCall(
            CloakedVerifier.verify,
            (aliceNode, COIN_ETH, meta, _signedDerivation(aliceNode, COIN_ETH), stealth)
        );
        vm.prank(address(resolver));
        uint256 before = gasleft();
        (bool ok,) = address(verifier).staticcall(call);
        vm.snapshotValue("Gas", "CloakedVerifier_verify_verified", before - gasleft());
        assertTrue(ok);
    }

    /// @dev The verifier's own cost for a signed unverified response.
    function test_gas_signed() public {
        address claimed = makeAddr("bob's stealth address");
        bytes memory call = abi.encodeCall(
            CloakedVerifier.verify,
            (bobNode, COIN_ETH, "", _signed(bobNode, claimed, uint64(block.timestamp)), claimed)
        );
        vm.prank(address(resolver));
        uint256 before = gasleft();
        (bool ok,) = address(verifier).staticcall(call);
        vm.snapshotValue("Gas", "CloakedVerifier_verify_signed", before - gasleft());
        assertTrue(ok);
    }
}
