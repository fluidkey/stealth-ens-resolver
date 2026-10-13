// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {CCIPReader} from "@ens/contracts/ccipRead/CCIPReader.sol";
import {OffchainLookup} from "@ens/contracts/ccipRead/EIP3668.sol";
import {IGatewayProvider} from "@ens/contracts/ccipRead/IGatewayProvider.sol";
import {IMulticallable} from "@ens/contracts/resolvers/IMulticallable.sol";
import {ResolverFeatures} from "@ens/contracts/resolvers/ResolverFeatures.sol";
import {IAddrResolver} from "@ens/contracts/resolvers/profiles/IAddrResolver.sol";
import {IAddressResolver} from "@ens/contracts/resolvers/profiles/IAddressResolver.sol";
import {ICompositeResolver} from "@ens/contracts/resolvers/profiles/ICompositeResolver.sol";
import {IDataResolver} from "@ens/contracts/resolvers/profiles/IDataResolver.sol";
import {IExtendedResolver} from "@ens/contracts/resolvers/profiles/IExtendedResolver.sol";
import {IUniversalResolver} from "@ens/contracts/universalResolver/IUniversalResolver.sol";
import {ResolverCaller} from "@ens/contracts/universalResolver/ResolverCaller.sol";
import {BytesUtils} from "@ens/contracts/utils/BytesUtils.sol";
import {COIN_TYPE_ETH} from "@ens/contracts/utils/ENSIP19.sol";
import {IERC7996} from "@ens/contracts/utils/IERC7996.sol";
import {NameCoder} from "@ens/contracts/utils/NameCoder.sol";
import {IPermissionedRegistry} from "@ensv2/registry/interfaces/IPermissionedRegistry.sol";
import {IRegistry} from "@ensv2/registry/interfaces/IRegistry.sol";
import {RegistryRolesLib} from "@ensv2/registry/libraries/RegistryRolesLib.sol";
import {LibRegistry} from "@ensv2/universalResolver/libraries/LibRegistry.sol";

import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";

import {IStealthResolver} from "./interfaces/IStealthResolver.sol";
import {IStealthVerifier} from "./interfaces/IStealthVerifier.sol";

/// @title StealthResolver
/// @notice ENSIP-30 (Stealth Address Resolution) verifying resolver for the ENSv2 registry.
/// @dev Stores no records. Each name's config points at a records resolver, an unmodified ENS
///      resolver chosen by whoever may set the name's resolver (its own `PermissionedResolver`,
///      `PublicResolverV2`, an offchain resolver, ...). Every query is forwarded to it through ENS's
///      `ResolverCaller`, as ENS's mirror resolvers do. Added on top, as the ENSIP requires:
///      address queries for names with gateway URLs resolve through ERC-3668 and are verified
///      against the meta-address record served by the name's own records resolver.
///
///      Queried only through ENSIP-10 `resolve()`; no profile is answered directly.
///
///      Per query for a DNS-encoded name N (own config of N, else the nearest ancestor's, per field):
///      - Address record, effective gateway URLs non-empty: `OffchainLookup` to them; the callback
///        verifies if N's own records resolver serves the ENSIP record for the coin type,
///        otherwise the verifier decides (unverified mode).
///      - Anything else: forwarded to the effective records resolver.
contract StealthResolver is
    ERC165,
    IStealthResolver,
    ICompositeResolver,
    IERC7996,
    ResolverCaller
{
    ////////////////////////////////////////////////////////////////////////
    // Types, immutables, storage
    ////////////////////////////////////////////////////////////////////////

    /// @dev Per-name configuration.
    struct Config {
        address recordsResolver;
        string[] gatewayURLs;
    }

    /// @notice The ENSv2 root registry, used to find who may set a name's resolver.
    IRegistry public immutable ROOT_REGISTRY;

    /// @notice Verifier for this resolver's single scheme (ENSIP-30 Section 5).
    IStealthVerifier public immutable VERIFIER;

    /// @notice Batch gateways for forwarded and multicall lookups (ENS runs one per chain).
    IGatewayProvider public immutable BATCH_GATEWAY_PROVIDER;

    /// @dev The verifier's scheme ID, read once at deployment: one scheme per resolver, for good.
    uint256 private immutable _SCHEME_ID;

    mapping(bytes32 node => Config) private _configs;

    ////////////////////////////////////////////////////////////////////////
    // Events and errors
    ////////////////////////////////////////////////////////////////////////

    /// @notice The config of `node` changed.
    event ConfigChanged(bytes32 indexed node, bytes name, address recordsResolver, string[] urls);

    /// @notice `account` may not set the config of `name`.
    error Unauthorized(bytes name, address account);

    /// @notice The node in the resolver calldata is not the namehash of the DNS-encoded name.
    error NodeMismatch(bytes32 node, bytes32 nameNode);

    /// @notice The gateway's address does not derive from the name's meta-address.
    error StealthAddressMismatch(address claimed, address derived);

    /// @notice No stealth meta-address record for `node` and `coinType`.
    error NoStealthRecord(bytes32 node, uint256 coinType);

    /// @notice The records resolver claims ENSIP-24 support but did not answer `data()`.
    error RecordUnavailable(bytes32 node, uint256 coinType);

    /// @notice The stealth meta-address record is malformed (ENSIP-30 Section 1).
    error MalformedRecord(bytes record);

    ////////////////////////////////////////////////////////////////////////
    // Initialization
    ////////////////////////////////////////////////////////////////////////

    /// @param rootRegistry The ENSv2 root registry.
    /// @param verifier The verifier for this resolver's scheme.
    /// @param batchGatewayProvider Shared batch gateways.
    constructor(
        IRegistry rootRegistry,
        IStealthVerifier verifier,
        IGatewayProvider batchGatewayProvider
    ) CCIPReader(DEFAULT_UNSAFE_CALL_GAS) {
        ROOT_REGISTRY = rootRegistry;
        VERIFIER = verifier;
        BATCH_GATEWAY_PROVIDER = batchGatewayProvider;
        _SCHEME_ID = verifier.schemeId();
    }

    /// @inheritdoc ERC165
    /// @dev ENSIP-30 Section 5: MUST report `IStealthResolver`.
    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return interfaceId == type(IStealthResolver).interfaceId
            || interfaceId == type(IExtendedResolver).interfaceId
            || interfaceId == type(ICompositeResolver).interfaceId
            || interfaceId == type(IERC7996).interfaceId || super.supportsInterface(interfaceId);
    }

    /// @inheritdoc IERC7996
    function supportsFeature(bytes4 feature) external pure returns (bool) {
        return feature == ResolverFeatures.RESOLVE_MULTICALL;
    }

    ////////////////////////////////////////////////////////////////////////
    // Config
    ////////////////////////////////////////////////////////////////////////

    /// @notice Sets the records resolver and gateway URLs of `name`.
    /// @dev ENSIP-30 Section 5: gateway URLs are stored per name; the setter is
    ///      implementation-defined. Allowed for whoever may set `name`'s resolver in the ENSv2
    ///      registry (see `canSetConfig`). Empty `urls` / zero `recordsResolver` inherit
    ///      the nearest ancestor's on the `resolve()` path.
    /// @param name The DNS-encoded name.
    /// @param recordsResolver The resolver holding the name's records.
    /// @param urls ERC-3668 gateway URLs for stealth address resolution.
    function setConfig(bytes calldata name, address recordsResolver, string[] memory urls)
        external
    {
        if (!canSetConfig(name, msg.sender)) revert Unauthorized(name, msg.sender);
        bytes32 node = NameCoder.namehash(name, 0);
        Config storage c = _configs[node];
        c.recordsResolver = recordsResolver;
        c.gatewayURLs = urls;
        emit ConfigChanged(node, name, recordsResolver, urls);
    }

    /// @notice Whether `account` may set the config of `name`: the same rule as
    ///         `PermissionedRegistry.setResolver`, i.e. `ROLE_SET_RESOLVER` on the name's token in
    ///         its parent registry (resource or registry-wide), name not expired. Top-level
    ///         names are excluded: their config would reach every name below them.
    /// @param name The DNS-encoded name.
    /// @param account The account to check.
    function canSetConfig(bytes memory name, address account) public view returns (bool) {
        IRegistry parent = LibRegistry.findParentRegistry(ROOT_REGISTRY, name, 0);
        if (
            address(parent) == address(0) || parent == ROOT_REGISTRY
                || !ERC165Checker.supportsInterface(
                    address(parent), type(IPermissionedRegistry).interfaceId
                )
        ) return false;
        (bytes32 labelHash,) = NameCoder.readLabel(name, 0);
        IPermissionedRegistry.State memory state =
            IPermissionedRegistry(address(parent)).getState(uint256(labelHash));
        if (block.timestamp >= state.expiry) return false;
        return IPermissionedRegistry(address(parent)).hasRoles(
            state.resource, RegistryRolesLib.ROLE_SET_RESOLVER, account
        );
    }

    /// @notice The config set on `node` itself.
    function config(bytes32 node)
        external
        view
        returns (address recordsResolver, string[] memory urls)
    {
        Config storage c = _configs[node];
        return (c.recordsResolver, c.gatewayURLs);
    }

    ////////////////////////////////////////////////////////////////////////
    // IStealthResolver (ENSIP-30 Section 5)
    ////////////////////////////////////////////////////////////////////////

    /// @inheritdoc IStealthResolver
    /// @dev ENSIP-30 Section 5. The verifier's scheme ID, fixed at deployment.
    function schemeId() public view returns (uint256) {
        return _SCHEME_ID;
    }

    /// @inheritdoc IStealthResolver
    /// @dev ENSIP-30 Sections 2 and 5. The name's own URLs; through `resolve()` the effective
    ///      URLs, which may be inherited from an ancestor.
    function gatewayURLs(bytes32 node) external view returns (string[] memory) {
        return _configs[node].gatewayURLs;
    }

    /// @inheritdoc IStealthResolver
    /// @dev ENSIP-30 Section 5. The record is read onchain from `node`'s own records resolver.
    function verifyStealthResolution(
        bytes32 node,
        uint256 coinType,
        address stealthAddress,
        bytes calldata verificationData
    ) external view returns (address) {
        bytes memory record = _stealthRecord(node, coinType);
        if (record.length == 0) revert NoStealthRecord(node, coinType);
        return _verify(node, coinType, record, verificationData, stealthAddress);
    }

    ////////////////////////////////////////////////////////////////////////
    // ENSIP-10 resolve, ICompositeResolver
    ////////////////////////////////////////////////////////////////////////

    /// @notice Resolves `data` for the DNS-encoded `name`, including names absent from the registry.
    /// @dev ENSIP-10; ENSIP-30 Section 4. `multicall(bytes[])` is answered as a batch.
    function resolve(bytes calldata name, bytes calldata data)
        external
        view
        returns (bytes memory)
    {
        if (bytes4(data) == IMulticallable.multicall.selector) {
            _resolveMulticall(name, data);
        }
        return _resolveOne(name, data);
    }

    /// @inheritdoc ICompositeResolver
    /// @dev The effective records resolver: where `name`'s records are read and edited.
    function getResolver(bytes calldata name) external view returns (address, bool) {
        (address recordsResolver,) = _effectiveConfig(name);
        return (recordsResolver, false);
    }

    /// @notice ERC-3668 callback for address records.
    /// @dev ENSIP-30 Section 4, step 3: verified if `node`'s own records resolver serves the
    ///      record for `coinType`, read onchain here; otherwise the verifier decides.
    /// @param response `abi.encode(address stealthAddress, bytes verificationData)` from the gateway.
    /// @param extraData `abi.encode(node, coinType, legacy)`; `legacy` = `addr(bytes32)` was queried.
    /// @return The ABI-encoded result of the queried address profile.
    function resolveStealthCallback(bytes calldata response, bytes calldata extraData)
        external
        view
        returns (bytes memory)
    {
        (bytes32 node, uint256 coinType, bool legacy) =
            abi.decode(extraData, (bytes32, uint256, bool));
        (address claimed, bytes memory verificationData) = abi.decode(response, (address, bytes));
        bytes memory record = _stealthRecord(node, coinType);
        address resolved = record.length == 0
            ? VERIFIER.verify(node, coinType, "", verificationData, claimed)
            : _verify(node, coinType, record, verificationData, claimed);
        return legacy ? abi.encode(resolved) : abi.encode(abi.encodePacked(resolved));
    }

    /// @notice CCIP-Read success callback for `resolve(name, multicall(...))`.
    /// @param response `abi.encode(Batch)` with every lookup done.
    /// @return The ABI-encoded `bytes[]` of per-call results; failed calls carry their error data.
    function resolveMulticallCallback(bytes calldata response, bytes calldata)
        external
        pure
        returns (bytes memory)
    {
        return abi.encode(_toResponseArray(abi.decode(response, (Batch)).lookups, true));
    }

    ////////////////////////////////////////////////////////////////////////
    // Internal
    ////////////////////////////////////////////////////////////////////////

    /// @dev One non-multicall query. Returns, reverts `OffchainLookup`, or forwards (never returns
    ///      normally from `callResolver`, which returns the records resolver's answer directly).
    function _resolveOne(bytes calldata name, bytes calldata data)
        internal
        view
        returns (bytes memory)
    {
        bytes4 selector = bytes4(data);
        (address recordsResolver, string[] memory urls) = _effectiveConfig(name);
        if (selector == IStealthResolver.gatewayURLs.selector) {
            return abi.encode(urls);
        }
        bool legacy = selector == IAddrResolver.addr.selector;
        bool isAddr = legacy || selector == IAddressResolver.addr.selector;
        if (isAddr && urls.length > 0) {
            bytes32 node = NameCoder.namehash(name, 0);
            if (bytes32(data[4:36]) != node) revert NodeMismatch(bytes32(data[4:36]), node);
            uint256 coinType = legacy ? COIN_TYPE_ETH : uint256(bytes32(data[36:68]));
            revert OffchainLookup(
                address(this),
                urls,
                abi.encodeCall(IExtendedResolver.resolve, (name, data)),
                this.resolveStealthCallback.selector,
                abi.encode(node, coinType, legacy)
            );
        }
        if (recordsResolver == address(0)) {
            // No records anywhere: unset address records, as standard ENS semantics (Section 4).
            if (legacy) return abi.encode(address(0));
            if (isAddr) return abi.encode(bytes(""));
            revert IUniversalResolver.UnsupportedResolverProfile(selector);
        }
        return
            callResolver(recordsResolver, name, data, false, "", BATCH_GATEWAY_PROVIDER.gateways());
    }

    /// @dev `resolve(name, multicall(calls))`: every call resolved as a single `resolve()` on this
    ///      contract, offchain lookups combined through the batch gateway. Never returns normally.
    function _resolveMulticall(bytes calldata name, bytes calldata data) internal view {
        bytes[] memory calls = abi.decode(data[4:], (bytes[]));
        for (uint256 i; i < calls.length; ++i) {
            calls[i] = abi.encodeCall(IExtendedResolver.resolve, (name, calls[i]));
        }
        ccipRead(
            address(this),
            abi.encodeCall(
                this.ccipBatch,
                (createBatch(address(this), calls, BATCH_GATEWAY_PROVIDER.gateways()))
            ),
            this.resolveMulticallCallback.selector,
            IDENTITY_FUNCTION,
            ""
        );
    }

    /// @dev Per field, the name's own value, else the nearest ancestor's (root excluded).
    function _effectiveConfig(bytes memory name)
        internal
        view
        returns (address recordsResolver, string[] memory urls)
    {
        uint256 offset;
        bool haveUrls;
        while (true) {
            (uint8 size, uint256 next) = NameCoder.nextLabel(name, offset);
            if (size == 0) break;
            Config storage c = _configs[NameCoder.namehash(name, offset)];
            if (recordsResolver == address(0)) recordsResolver = c.recordsResolver;
            if (!haveUrls && c.gatewayURLs.length > 0) {
                urls = c.gatewayURLs;
                haveUrls = true;
            }
            if (recordsResolver != address(0) && haveUrls) break;
            offset = next;
        }
    }

    /// @dev The ENSIP-30 Section 1 record for `node`, from `node`'s own records resolver only.
    ///      A records resolver without ENSIP-24 support has no record; one that claims support but
    ///      reverts fails the resolution.
    function _stealthRecord(bytes32 node, uint256 coinType)
        internal
        view
        returns (bytes memory record)
    {
        address recordsResolver = _configs[node].recordsResolver;
        if (
            recordsResolver == address(0)
                || !ERC165Checker.supportsInterface(recordsResolver, type(IDataResolver).interfaceId)
        ) return "";
        (bool ok, bytes memory v) = recordsResolver.staticcall(
            abi.encodeCall(IDataResolver.data, (node, _stealthKey(coinType)))
        );
        if (!ok || v.length < 64) revert RecordUnavailable(node, coinType);
        record = abi.decode(v, (bytes));
        if (record.length == 0) return record;
        // Flag byte plus a non-empty meta-address; reserved flag bits zero.
        if (record.length < 2 || uint8(record[0]) & 0xfe != 0) revert MalformedRecord(record);
    }

    /// @dev Verified mode: the verifier rederives from the record; the result must equal `claimed`.
    function _verify(
        bytes32 node,
        uint256 coinType,
        bytes memory record,
        bytes memory verificationData,
        address claimed
    ) internal view returns (address) {
        address derived = VERIFIER.verify(
            node,
            coinType,
            BytesUtils.substring(record, 1, record.length - 1),
            verificationData,
            claimed
        );
        if (derived != claimed) revert StealthAddressMismatch(claimed, derived);
        return claimed;
    }

    /// @dev ENSIP-30 Section 1 key: decimal, no leading zeros, no `0x`.
    function _stealthKey(uint256 coinType) internal view returns (string memory) {
        return string.concat(
            "stealth-meta-address[",
            Strings.toString(_SCHEME_ID),
            "][",
            Strings.toString(coinType),
            "]"
        );
    }
}
