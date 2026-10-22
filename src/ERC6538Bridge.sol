// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IDataResolver} from "@ens/contracts/resolvers/profiles/IDataResolver.sol";
import {IUniversalResolver} from "@ens/contracts/universalResolver/IUniversalResolver.sol";
import {BytesUtils} from "@ens/contracts/utils/BytesUtils.sol";
import {NameCoder} from "@ens/contracts/utils/NameCoder.sol";

import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

/// @title ERC6538Bridge
/// @notice Reads an ENS name's stealth meta-address (ENSIP-30 Section 1) in the shape of the
///         ERC-6538 registry's `stealthMetaAddressOf`, for contracts and clients that derive
///         stealth addresses themselves (ENSIP-30 Section 3).
/// @dev Stateless, no owner. The record is read through ENS's UniversalResolver, so the name's
///      resolver is found per ENSIP-10, wildcard names included, whatever resolver serves it.
///      Coin type 60 only: ENS lives on Ethereum mainnet, and an onchain caller there pays on
///      mainnet; a name that does not enable 60 has no record here.
///
///      Returns the meta-address only when the name permits client-side derivation: the record's
///      flag byte is exactly 0x01 (bit 0 set, reserved bits zero; ENSIP-30 Sections 1 and 2).
///      Otherwise, and whenever the lookup fails, it returns empty, as the ERC-6538 registry does
///      for an unregistered account: no resolver, a resolver that answers offchain (an onchain
///      caller cannot follow `OffchainLookup`), a malformed answer. For scheme 1 the meta-address
///      must also be 66 bytes, two compressed keys; other schemes' encodings are not checked.
///
///      The name is the DNS-encoded name, so the selector differs from ERC-6538's
///      `stealthMetaAddressOf(address,uint256)`: this is not a drop-in for the registry.
///      An absent record is never filled from the ERC-6538 registry: ENSIP-30 Section 1 treats
///      a name without a record as not supporting client-side derivation.
contract ERC6538Bridge {
    /// @notice ENS's UniversalResolver, through which every name is resolved.
    IUniversalResolver public immutable UNIVERSAL_RESOLVER;

    /// @notice The UniversalResolver must be a contract.
    error InvalidUniversalResolver(address universalResolver);

    /// @param universalResolver ENS's UniversalResolver on Ethereum mainnet.
    constructor(IUniversalResolver universalResolver) {
        if (address(universalResolver).code.length == 0) {
            revert InvalidUniversalResolver(address(universalResolver));
        }
        UNIVERSAL_RESOLVER = universalResolver;
    }

    /// @notice The stealth meta-address of `name` for `schemeId`, without the flag byte, or empty.
    /// @dev ENSIP-30 Sections 1 to 3: the record `stealth-meta-address[<schemeId>][60]` of `name`,
    ///      returned only if it permits client-side derivation. ERC-6538 shape, keyed by name.
    /// @param name The DNS-encoded ENS name.
    /// @param schemeId The ERC-5564 scheme ID.
    /// @return The scheme's meta-address encoding (66 bytes for scheme 1), or empty.
    function stealthMetaAddressOf(bytes calldata name, uint256 schemeId)
        external
        view
        returns (bytes memory)
    {
        string memory key =
            string.concat("stealth-meta-address[", Strings.toString(schemeId), "][60]");
        (bool ok, bytes memory ret) = address(UNIVERSAL_RESOLVER).staticcall(
            abi.encodeCall(
                IUniversalResolver.resolve,
                (name, abi.encodeCall(IDataResolver.data, (NameCoder.namehash(name, 0), key)))
            )
        );
        if (!ok || ret.length < 64) return "";
        (bytes memory result,) = abi.decode(ret, (bytes, address));
        bytes memory record = _decodeBytes(result);
        if (record.length < 2 || uint8(record[0]) != 1) return "";
        if (schemeId == 1 && record.length != 67) return "";
        return BytesUtils.substring(record, 1, record.length - 1);
    }

    /// @dev `abi.decode(v, (bytes))` that yields empty instead of reverting: `v` is whatever the
    ///      name's resolver answered.
    function _decodeBytes(bytes memory v) internal pure returns (bytes memory) {
        if (v.length < 64 || uint256(BytesUtils.readBytes32(v, 0)) != 32) return "";
        uint256 length = uint256(BytesUtils.readBytes32(v, 32));
        if (length > v.length - 64) return "";
        return BytesUtils.substring(v, 64, length);
    }
}
