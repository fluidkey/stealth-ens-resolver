// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test} from "forge-std/Test.sol";

import {EIP3668, OffchainLookup} from "@ens/contracts/ccipRead/EIP3668.sol";
import {IBatchGateway} from "@ens/contracts/ccipRead/IBatchGateway.sol";
import {BytesUtils} from "@ens/contracts/utils/BytesUtils.sol";

/// @dev An ERC-3668 client that plays the gateways and ENS's batch gateway.
abstract contract CCIPClient is Test {
    string internal constant STEALTH_GW = "https://gw.stealth";
    string internal constant RECORDS_GW = "https://gw.records";

    /// @dev What the simulated gateways answer.
    address internal gwClaimed;
    bytes internal gwVerificationData;
    bytes internal recordsAnswer;

    /// @dev Calls `target` and returns the `OffchainLookup` it reverts with.
    function expectLookup(address target, bytes memory call)
        internal
        view
        returns (EIP3668.Params memory p)
    {
        (bool ok, bytes memory v) = target.staticcall(call);
        assertFalse(ok, "expected OffchainLookup, call succeeded");
        assertEq(bytes4(v), OffchainLookup.selector, "expected OffchainLookup");
        p = EIP3668.decode(BytesUtils.substring(v, 4, v.length - 4));
    }

    /// @dev Invokes the lookup's callback with `response`.
    function callback(EIP3668.Params memory p, bytes memory response)
        internal
        view
        returns (bool ok, bytes memory v)
    {
        (ok, v) =
            p.sender.staticcall(abi.encodeWithSelector(p.callbackFunction, response, p.extraData));
    }

    /// @dev Full ERC-3668 client: follows lookups (including batch-gateway lookups) to the end.
    function ccipCall(address target, bytes memory call)
        internal
        view
        returns (bool ok, bytes memory v)
    {
        (ok, v) = target.staticcall(call);
        for (uint256 i; i < 8 && !ok && bytes4(v) == OffchainLookup.selector; ++i) {
            EIP3668.Params memory p = EIP3668.decode(BytesUtils.substring(v, 4, v.length - 4));
            (ok, v) = callback(p, _serve(p.urls, p.callData));
        }
    }

    function _serve(string[] memory lookupUrls, bytes memory callData)
        internal
        view
        returns (bytes memory)
    {
        if (bytes4(callData) == IBatchGateway.query.selector) {
            IBatchGateway.Request[] memory requests = abi.decode(
                BytesUtils.substring(callData, 4, callData.length - 4), (IBatchGateway.Request[])
            );
            bool[] memory failures = new bool[](requests.length);
            bytes[] memory responses = new bytes[](requests.length);
            for (uint256 i; i < requests.length; ++i) {
                responses[i] = _serve(requests[i].urls, requests[i].data);
            }
            return abi.encode(failures, responses);
        }
        return gateway(lookupUrls[0], callData);
    }

    /// @dev The simulated gateways: the stealth gateway answers ENSIP-30 Section 4 step 2,
    ///      the records gateway answers with the ABI-encoded record.
    function gateway(string memory url, bytes memory)
        internal
        view
        virtual
        returns (bytes memory)
    {
        if (keccak256(bytes(url)) == keccak256(bytes(STEALTH_GW))) {
            return abi.encode(gwClaimed, gwVerificationData);
        }
        if (keccak256(bytes(url)) == keccak256(bytes(RECORDS_GW))) return recordsAnswer;
        revert("unknown gateway");
    }
}
