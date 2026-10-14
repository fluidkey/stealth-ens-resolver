// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {EIP3668} from "@ens/contracts/ccipRead/EIP3668.sol";
import {IAddrResolver} from "@ens/contracts/resolvers/profiles/IAddrResolver.sol";
import {ITextResolver} from "@ens/contracts/resolvers/profiles/ITextResolver.sol";

import {IStealthResolver} from "../src/interfaces/IStealthResolver.sol";
import {StealthResolverFixture} from "./utils/StealthResolverFixture.sol";

/// @dev Gas of StealthResolver's own work, written to `snapshots/Gas.json` and checked in CI.
///      Reads are what an `eth_call` costs; verified-mode numbers use MockVerifier and exclude the
///      scheme's curve arithmetic. Measured with `gasleft()` around the call: Foundry's gas
///      snapshots misreport calls that revert, and every `OffchainLookup` is a revert.
contract GasTest is StealthResolverFixture {
    bytes internal constant VD = hex"c0ffee";

    function _measure(string memory name, address target, bytes memory call)
        internal
        returns (bool ok)
    {
        uint256 before = gasleft();
        (ok,) = target.staticcall(call);
        vm.snapshotValue("Gas", name, before - gasleft());
    }

    function test_gas_setConfig() public {
        vm.prank(alice);
        uint256 before = gasleft();
        resolver.setConfig(dns("alice.fkey.eth"), address(aliceRecords), urls(STEALTH_GW));
        vm.snapshotValue("Gas", "setConfig_recordsResolver_oneUrl", before - gasleft());
    }

    function test_gas_setMetaAddress() public {
        vm.prank(alice);
        uint256 before = gasleft();
        resolver.setMetaAddress(dns("alice.fkey.eth"), META);
        vm.snapshotValue("Gas", "setMetaAddress_67bytes", before - gasleft());
    }

    function test_gas_setChains() public {
        uint256[] memory coinTypes = new uint256[](1);
        coinTypes[0] = COIN_BASE;
        vm.prank(alice);
        uint256 before = gasleft();
        resolver.setChains(dns("alice.fkey.eth"), coinTypes, true);
        vm.snapshotValue("Gas", "setChains_oneChain", before - gasleft());
    }

    function test_gas_reads() public {
        setUpAliceVerified(COIN_ETH);
        vm.prank(fluidkey);
        fkeyRecords.setText(bobNode, "avatar", "ipfs://bob");

        bytes memory wildcardAddr = abi.encodeCall(
            resolver.resolve, (dns("bob.fkey.eth"), abi.encodeCall(IAddrResolver.addr, (bobNode)))
        );
        _measure("resolve_wildcardAddr_offchainLookup", address(resolver), wildcardAddr);
        EIP3668.Params memory p = expectLookup(address(resolver), wildcardAddr);
        assertTrue(
            _measure(
                "resolveStealthCallback_unverified",
                address(resolver),
                abi.encodeWithSelector(
                    p.callbackFunction, abi.encode(makeAddr("x"), bytes("ok")), p.extraData
                )
            )
        );

        bytes memory verifiedAddr = abi.encodeCall(
            resolver.resolve,
            (dns("alice.fkey.eth"), abi.encodeCall(IAddrResolver.addr, (aliceNode)))
        );
        _measure("resolve_registeredAddr_offchainLookup", address(resolver), verifiedAddr);
        p = expectLookup(address(resolver), verifiedAddr);
        assertTrue(
            _measure(
                "resolveStealthCallback_verified_mockVerifier",
                address(resolver),
                abi.encodeWithSelector(
                    p.callbackFunction,
                    abi.encode(verifier.derive(metaWithoutFlag(), VD), VD),
                    p.extraData
                )
            )
        );

        assertTrue(
            _measure(
                "resolve_forwardedText_PermissionedResolver",
                address(resolver),
                abi.encodeCall(
                    resolver.resolve,
                    (dns("bob.fkey.eth"), abi.encodeCall(ITextResolver.text, (bobNode, "avatar")))
                )
            )
        );
        assertTrue(
            _measure(
                "PermissionedResolver_text_direct_reference",
                address(fkeyRecords),
                abi.encodeCall(ITextResolver.text, (bobNode, "avatar"))
            )
        );
        assertTrue(
            _measure(
                "resolve_verifyStealthResolution_mockVerifier",
                address(resolver),
                abi.encodeCall(
                    resolver.resolve,
                    (
                        dns("alice.fkey.eth"),
                        abi.encodeCall(
                            IStealthResolver.verifyStealthResolution,
                            (aliceNode, COIN_ETH, verifier.derive(metaWithoutFlag(), VD), VD)
                        )
                    )
                )
            )
        );
    }
}
