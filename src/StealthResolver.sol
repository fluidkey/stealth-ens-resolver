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
import {COIN_TYPE_DEFAULT, COIN_TYPE_ETH, ENSIP19} from "@ens/contracts/utils/ENSIP19.sol";
import {IERC7996} from "@ens/contracts/utils/IERC7996.sol";
import {NameCoder} from "@ens/contracts/utils/NameCoder.sol";
import {IPermissionedRegistry} from "@ensv2/registry/interfaces/IPermissionedRegistry.sol";
import {IRegistry} from "@ensv2/registry/interfaces/IRegistry.sol";
import {RegistryRolesLib} from "@ensv2/registry/libraries/RegistryRolesLib.sol";
import {LibResolution} from "@ensv2/universalResolver/libraries/LibResolution.sol";

import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";

import {IStealthResolver} from "./interfaces/IStealthResolver.sol";
import {IStealthVerifier} from "./interfaces/IStealthVerifier.sol";

/// @title StealthResolver
/// @notice ENSIP-30 (Stealth Address Resolution) verifying resolver for the ENSv2 registry.
/// @dev Stores one stealth meta-address per name (the ENSIP-30 Section 1 record value) and, per
///      registered name, a config: a records resolver (an unmodified ENS resolver chosen by the
///      name's owner, such as its own `PermissionedResolver`, `PublicResolverV2` or an offchain
///      resolver), gateway URLs, and a chain list (the EVM coin types on which the name is
///      stealth). Every other record is forwarded to the records resolver through ENS's
///      `ResolverCaller`, as ENS's mirror resolvers do.
///
///      Queried only through ENSIP-10 `resolve()`; no profile is answered directly, the ENSIP-30
///      Section 5 functions included (a node alone cannot be walked to the name's authority),
///      except `schemeId()`, which is not name-scoped.
///
///      Authority. All state is written under the ENSv2 rule for setting a name's resolver
///      (`ROLE_SET_RESOLVER` on the name's token, not expired), applied to the nearest registered
///      name at or above the name written: a registered name writes its own state, an
///      unregistered (wildcard) name's record is written by its nearest registered ancestor. A
///      reserved name counts as registered: it exists in the registry in its own right. State is
///      keyed by that authority's registry resource and status, so a previous holder's state is
///      never read: ENSv2 renews the resource when an expired name is registered again, and what
///      was written while a name was reserved is not read once it is registered. A transfer keeps
///      the resource, and the state with it, as ENS's resolvers keep a name's records; the new
///      holder clears it with `clearRecords`. So does a label reserved again after its reservation
///      lapsed: it reads what the previous reservation left until it is cleared.
///
///      Per query for a DNS-encoded name N, with the config of N's authority (nothing is inherited
///      past a registered name, so an ancestor never governs a registered descendant):
///      - Address record for a coin type on the chain list, gateway URLs non-empty:
///        `OffchainLookup` to them; the callback verifies if N has a meta-address, otherwise the
///        verifier decides (unverified mode).
///      - Address record for any other coin type: forwarded to the records resolver, so a name can
///        be stealth on some chains and keep a static address on others.
///      - ENSIP-30 Section 1 record of this resolver's scheme: N's meta-address if the coin type
///        is on the chain list, otherwise empty; the same value the callback verifies against.
///      - Anything else: forwarded to the records resolver.
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

    /// @dev Configuration of a registered name.
    struct Config {
        address recordsResolver;
        string[] gatewayURLs;
    }

    /// @dev What the registry says about a name (`_context`).
    struct NameState {
        /// @dev Storage key of the authority: `resourceKey` and its version; zero if none.
        bytes32 key;
        /// @dev `keccak256(registry, resource, reserved)`: what `_versions` is keyed by.
        bytes32 resourceKey;
        /// @dev The registry holding the authority's token.
        IPermissionedRegistry registry;
        /// @dev The authority's EAC resource in `registry`.
        uint256 resource;
        /// @dev The authority is the name itself (the name is registered or reserved).
        bool exact;
    }

    /// @notice The ENSv2 root registry, used to find who may write a name's state.
    IRegistry public immutable ROOT_REGISTRY;

    /// @notice Verifier for this resolver's single scheme (ENSIP-30 Section 5).
    IStealthVerifier public immutable VERIFIER;

    /// @notice Batch gateways for forwarded and multicall lookups (ENS runs one per chain).
    IGatewayProvider public immutable BATCH_GATEWAY_PROVIDER;

    /// @dev The verifier's scheme ID, read once at deployment: one scheme per resolver, for good.
    uint256 private immutable _SCHEME_ID;

    /// @dev Config of a registered name, by its authority key.
    mapping(bytes32 key => Config) private _configs;

    /// @dev Chain list of a registered name, by its authority key: the EVM coin types on which the
    ///      name and the unregistered names below it are stealth.
    mapping(bytes32 key => mapping(uint256 coinType => bool)) private _chains;

    /// @dev Meta-address records (flag byte and the scheme's meta-address), by the authority key of
    ///      the nearest registered name at or above `node`.
    mapping(bytes32 key => mapping(bytes32 node => bytes)) private _metaAddresses;

    /// @dev How many times an authority's state was cleared (`clearRecords`), by its
    ///      `resourceKey`; part of the authority key.
    mapping(bytes32 resourceKey => uint64 version) private _versions;

    ////////////////////////////////////////////////////////////////////////
    // Events and errors
    ////////////////////////////////////////////////////////////////////////

    /// @notice The config of `node` changed.
    event ConfigChanged(bytes32 indexed node, bytes name, address recordsResolver, string[] urls);

    /// @notice `coinType` was added to or removed from the chain list of `node`.
    event ChainChanged(bytes32 indexed node, bytes name, uint256 indexed coinType, bool enabled);

    /// @notice The meta-address record of `node` changed.
    event MetaAddressChanged(bytes32 indexed node, bytes name, bytes value);

    /// @notice All state of `node` was cleared (`clearRecords`). The event of ENS's
    ///         `IVersionableResolver`.
    event VersionChanged(bytes32 indexed node, uint64 newVersion);

    /// @notice `account` may not write this state of `name`.
    error Unauthorized(bytes name, address account);

    /// @notice A records resolver must be a contract other than this resolver.
    error InvalidRecordsResolver(address recordsResolver);

    /// @notice Only EVM coin types can be on a chain list: the verifier answers with an EVM address.
    error InvalidChain(uint256 coinType);

    /// @notice `coinType` is no longer on the chain list or the gateway was removed: the gateway's
    ///         answer for it is not accepted.
    error ChainNotStealth(uint256 coinType);

    /// @notice The name's authority or gateway URLs changed since the lookup: the answer is not
    ///         accepted.
    error StaleLookup();

    /// @notice The node in the resolver calldata is not the namehash of the DNS-encoded name.
    error NodeMismatch(bytes32 node, bytes32 nameNode);

    /// @notice `selector` is answered only through ENSIP-10 `resolve(name, data)`: a node alone
    ///         cannot be walked through the registry to the name's authority.
    error ResolveOnly(bytes4 selector);

    /// @notice The gateway's address does not derive from the name's meta-address. No arguments:
    ///         in a multicall a failed item is returned as data, and an argument the gateway
    ///         chose could read as an address to a client that skips the error marker.
    error StealthAddressMismatch();

    /// @notice No stealth meta-address record for `node` and `coinType`.
    error NoStealthRecord(bytes32 node, uint256 coinType);

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
    /// @dev ENSIP-10 batched resolution: `resolve(name, multicall(...))` (see `resolve`).
    function supportsFeature(bytes4 feature) external pure returns (bool) {
        return feature == ResolverFeatures.RESOLVE_MULTICALL;
    }

    ////////////////////////////////////////////////////////////////////////
    // Writes
    ////////////////////////////////////////////////////////////////////////

    /// @notice Sets the records resolver and gateway URLs of the registered name `name`.
    /// @dev ENSIP-30 Section 5: gateway URLs are stored per name; the setter is
    ///      implementation-defined. Allowed for whoever may set `name`'s resolver in the ENSv2
    ///      registry (see `canSetConfig`). Empty `urls`: no gateway, address records are
    ///      forwarded. Applies to `name` and to the unregistered (wildcard) names below it; a
    ///      registered name below it uses its own config only.
    /// @param name The DNS-encoded name.
    /// @param recordsResolver The resolver holding the name's other records.
    /// @param urls ERC-3668 gateway URLs for stealth address resolution.
    function setConfig(bytes calldata name, address recordsResolver, string[] memory urls)
        external
    {
        NameState memory ctx = _context(name);
        if (!ctx.exact || !_isAuthority(ctx, msg.sender)) revert Unauthorized(name, msg.sender);
        // Not this resolver (every query would recurse); not an account without code (forwarded
        // reads would fail while the name silently resolved unverified).
        if (
            recordsResolver == address(this)
                || (recordsResolver != address(0) && recordsResolver.code.length == 0)
        ) revert InvalidRecordsResolver(recordsResolver);
        bytes32 node = NameCoder.namehash(name, 0);
        Config storage c = _configs[ctx.key];
        c.recordsResolver = recordsResolver;
        c.gatewayURLs = urls;
        emit ConfigChanged(node, name, recordsResolver, urls);
    }

    /// @notice Adds or removes EVM coin types on the chain list of the registered name `name`.
    /// @dev ENSIP-30 Sections 1 and 4. The list says on which chains `name` and the unregistered
    ///      (wildcard) names below it are stealth: an address query for a listed coin type goes to
    ///      the gateway, verified if the name has a meta-address; any other coin type is forwarded
    ///      to the records resolver. `data()` serves the meta-address record only for listed coin
    ///      types. The ENSIP-19 default coin type may be listed: queries for it then go to the
    ///      gateway too, while a chain that is not listed never falls back to it. `0x80000001`,
    ///      Ethereum in ENSIP-11 form, cannot be listed: chain 1 is 60, and a query for it is
    ///      forwarded like any other unlisted coin type. Same authority as `setConfig`.
    /// @param name The DNS-encoded name.
    /// @param coinTypes ENSIP-11 EVM coin types, or the ENSIP-19 default.
    /// @param enabled Add (true) or remove (false).
    function setChains(bytes calldata name, uint256[] calldata coinTypes, bool enabled) external {
        NameState memory ctx = _context(name);
        if (!ctx.exact || !_isAuthority(ctx, msg.sender)) revert Unauthorized(name, msg.sender);
        bytes32 node = NameCoder.namehash(name, 0);
        for (uint256 i; i < coinTypes.length; ++i) {
            uint256 coinType = coinTypes[i];
            if (!ENSIP19.isEVMCoinType(coinType) || coinType == COIN_TYPE_DEFAULT | 1) {
                revert InvalidChain(coinType);
            }
            _chains[ctx.key][coinType] = enabled;
            emit ChainChanged(node, name, coinType, enabled);
        }
    }

    /// @notice Sets the stealth meta-address record of `name`, served for every coin type on its
    ///         authority's chain list.
    /// @dev ENSIP-30 Section 1: one value stored, exposed under each enabled coin type. Allowed for
    ///      whoever may set the resolver of the nearest registered name at or above `name` (see
    ///      `canSetMetaAddress`): the name itself if registered, otherwise its nearest registered
    ///      ancestor (wildcard names). A record written by an ancestor is no longer read once the
    ///      name is registered.
    /// @param name The DNS-encoded name.
    /// @param value Flag byte (reserved bits zero) and the scheme's meta-address, or empty to clear.
    function setMetaAddress(bytes calldata name, bytes calldata value) external {
        NameState memory ctx = _context(name);
        if (!_isAuthority(ctx, msg.sender)) revert Unauthorized(name, msg.sender);
        // A flag byte with reserved bits zero, then a non-empty meta-address: a flag-only record
        // would reach the verifier as an empty meta-address, i.e. unverified mode.
        if (value.length != 0 && (value.length < 2 || uint8(value[0]) & 0xfe != 0)) {
            revert MalformedRecord(value);
        }
        bytes32 node = NameCoder.namehash(name, 0);
        _metaAddresses[ctx.key][node] = value;
        emit MetaAddressChanged(node, name, value);
    }

    /// @notice Clears all state of the registered name `name`: its config, its chain list and every
    ///         meta-address record written under it, its wildcard names' included.
    /// @dev ENS's `clearRecords(node)` (ENSv1 `PublicResolver`, `PublicResolverV2`), by name and for
    ///      everything the name governs. State stays with a name when its token is transferred, as
    ///      records do in ENS's resolvers, so a new holder drops what the previous one left with
    ///      one call. Same authority as `setConfig`.
    /// @param name The DNS-encoded name.
    function clearRecords(bytes calldata name) external {
        NameState memory ctx = _context(name);
        if (!ctx.exact || !_isAuthority(ctx, msg.sender)) revert Unauthorized(name, msg.sender);
        uint64 version = ++_versions[ctx.resourceKey];
        emit VersionChanged(NameCoder.namehash(name, 0), version);
    }

    /// @notice Whether `account` may set the config of `name`: `name` is registered in an ENSv2
    ///         `PermissionedRegistry` below a top-level name and `account` holds
    ///         `ROLE_SET_RESOLVER` on its token (resource or registry-wide), as for
    ///         `PermissionedRegistry.setResolver`.
    /// @dev ENSIP-30 Section 5: write authorization follows the rules for the name's resolver.
    /// @param name The DNS-encoded name.
    /// @param account The account to check.
    function canSetConfig(bytes calldata name, address account) external view returns (bool) {
        NameState memory ctx = _context(name);
        return ctx.exact && _isAuthority(ctx, account);
    }

    /// @notice Whether `account` may set the meta-address of `name`: as `canSetConfig`, for the
    ///         nearest registered name at or above `name`.
    /// @dev ENSIP-30 Sections 1 and 5: write authorization follows the rules for the name's resolver.
    /// @param name The DNS-encoded name.
    /// @param account The account to check.
    function canSetMetaAddress(bytes calldata name, address account) external view returns (bool) {
        return _isAuthority(_context(name), account);
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
    /// @dev ENSIP-30 Sections 2 and 5. Answered through ENSIP-10 `resolve(name, data)` only, as
    ///      every other query: there the name's authority is located in the registry (for a
    ///      wildcard name, its nearest registered ancestor), which a node alone cannot be. Called
    ///      directly, reverts `ResolveOnly`.
    function gatewayURLs(bytes32) external pure returns (string[] memory) {
        revert ResolveOnly(IStealthResolver.gatewayURLs.selector);
    }

    /// @inheritdoc IStealthResolver
    /// @dev ENSIP-30 Section 5. As `gatewayURLs`: through `resolve(name, data)` only (no CCIP-Read
    ///      is involved). Out-of-flow verifiers and contracts consuming stealth resolutions call it
    ///      through the UniversalResolver, which routes to the name's current resolver; this
    ///      contract does not check that it still is. Called directly, reverts `ResolveOnly`.
    function verifyStealthResolution(bytes32, uint256, address, bytes calldata)
        external
        pure
        returns (address)
    {
        revert ResolveOnly(IStealthResolver.verifyStealthResolution.selector);
    }

    ////////////////////////////////////////////////////////////////////////
    // ENSIP-10 resolve, ICompositeResolver
    ////////////////////////////////////////////////////////////////////////

    /// @notice Resolves `data` for the DNS-encoded `name`, including names absent from the registry.
    /// @dev ENSIP-10; ENSIP-30 Sections 1 and 4. `multicall(bytes[])` and
    ///      `multicallWithNodeCheck(bytes32, bytes[])` are answered as a batch; the latter checks
    ///      that its node is the name's and that every item carries it, as ENS's `Multicallable`
    ///      does.
    function resolve(bytes calldata name, bytes calldata data)
        external
        view
        returns (bytes memory)
    {
        bytes4 selector = bytes4(data);
        if (selector == IMulticallable.multicall.selector) {
            _resolveMulticall(name, abi.decode(data[4:], (bytes[])));
        }
        if (selector == IMulticallable.multicallWithNodeCheck.selector) {
            bytes32 node = _checkNode(name, data);
            (, bytes[] memory calls) = abi.decode(data[4:], (bytes32, bytes[]));
            for (uint256 i; i < calls.length; ++i) {
                bytes32 itemNode =
                    calls[i].length < 36 ? bytes32(0) : BytesUtils.readBytes32(calls[i], 4);
                if (itemNode != node) revert NodeMismatch(itemNode, node);
            }
            _resolveMulticall(name, calls);
        }
        return _resolveOne(name, data);
    }

    /// @inheritdoc ICompositeResolver
    /// @dev ENSIP-10. The records resolver of `name`'s authority: where its other records are read
    ///      and edited.
    function getResolver(bytes calldata name) external view returns (address, bool) {
        return (_configs[_context(name).key].recordsResolver, false);
    }

    /// @notice ERC-3668 callback for address records.
    /// @dev ENSIP-30 Section 4, step 3: verified if `name` has a meta-address, read here; otherwise
    ///      the verifier decides. Reverts if the coin type is no longer stealth for `name` (chain
    ///      removed or gateway cleared since the lookup), and if its authority or gateway URLs
    ///      changed since (`StaleLookup`): the answer is bound to the lookup, as ENS's
    ///      UniversalResolver sends a callback to the resolver it looked up. The zero address is
    ///      an unset record.
    /// @param response `abi.encode(address stealthAddress, bytes verificationData)` from the gateway.
    /// @param extraData `abi.encode(name, coinType, legacy, binding)`; `legacy` = `addr(bytes32)`
    ///        was queried; `binding` = the authority and gateway URLs of the lookup, hashed.
    /// @return The ABI-encoded result of the queried address profile.
    function resolveStealthCallback(bytes calldata response, bytes calldata extraData)
        external
        view
        returns (bytes memory)
    {
        (bytes memory name, uint256 coinType, bool legacy, bytes32 binding) =
            abi.decode(extraData, (bytes, uint256, bool, bytes32));
        (address claimed, bytes memory verificationData) = abi.decode(response, (address, bytes));
        bytes32 node = NameCoder.namehash(name, 0);
        bytes32 key = _context(name).key;
        if (!_isStealth(key, coinType)) revert ChainNotStealth(coinType);
        if (_lookupBinding(key) != binding) revert StaleLookup();
        address resolved = _metaAddresses[key][node].length == 0
            ? VERIFIER.verify(node, coinType, "", verificationData, claimed)
            : _verifyResolution(key, node, coinType, claimed, verificationData);
        if (legacy) return abi.encode(resolved);
        return abi.encode(resolved == address(0) ? bytes("") : abi.encodePacked(resolved));
    }

    /// @notice CCIP-Read success callback for `resolve(name, multicall(...))` and the
    ///         `multicallWithNodeCheck` form.
    /// @dev ENSIP-10 batched resolution; ENSIP-30 Section 4 lookups inside it are verified by
    ///      `resolveStealthCallback` before this runs.
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
        // A nested resolve() would reach a records resolver that executes inner calldata, and
        // with it a static address on a listed chain; ENS's PermissionedResolver refuses it too.
        if (selector == IExtendedResolver.resolve.selector) {
            revert IUniversalResolver.UnsupportedResolverProfile(selector);
        }
        // ENSIP-30 Section 5: the functions of IStealthResolver are resolved through resolve().
        if (selector == IStealthResolver.schemeId.selector) return abi.encode(_SCHEME_ID);
        NameState memory ctx = _context(name);
        Config storage c = _configs[ctx.key];
        if (selector == IStealthResolver.gatewayURLs.selector) {
            _checkNode(name, data);
            return abi.encode(c.gatewayURLs);
        }
        if (selector == IStealthResolver.verifyStealthResolution.selector) {
            (, uint256 vCoinType, address stealthAddress, bytes memory verificationData) =
                abi.decode(data[4:], (bytes32, uint256, address, bytes));
            return abi.encode(
                _verifyResolution(
                    ctx.key, _checkNode(name, data), vCoinType, stealthAddress, verificationData
                )
            );
        }
        if (selector == IDataResolver.data.selector) {
            (, string memory key) = abi.decode(data[4:], (bytes32, string));
            (bool isStealthKey, uint256 keyCoinType) = _parseStealthKey(key);
            if (isStealthKey) {
                return abi.encode(_record(ctx.key, _checkNode(name, data), keyCoinType));
            }
        }
        bool legacy = selector == IAddrResolver.addr.selector;
        bool isAddr = legacy || selector == IAddressResolver.addr.selector;
        uint256 coinType = isAddr && !legacy ? uint256(bytes32(data[36:68])) : COIN_TYPE_ETH;
        if (isAddr && _isStealth(ctx.key, coinType)) {
            _stealthLookup(name, data, ctx.key, coinType, legacy);
        }
        address recordsResolver = c.recordsResolver;
        if (recordsResolver == address(0)) {
            // No records resolver: unset address records, as standard ENS semantics (Section 4).
            if (legacy) return abi.encode(address(0));
            if (isAddr) return abi.encode(bytes(""));
            revert IUniversalResolver.UnsupportedResolverProfile(selector);
        }
        return
            callResolver(recordsResolver, name, data, false, "", BATCH_GATEWAY_PROVIDER.gateways());
    }

    /// @dev ENSIP-30 Section 4, step 1: the `OffchainLookup` to the gateway of the authority `key`.
    function _stealthLookup(
        bytes calldata name,
        bytes calldata data,
        bytes32 key,
        uint256 coinType,
        bool legacy
    ) internal view {
        _checkNode(name, data);
        revert OffchainLookup(
            address(this),
            _configs[key].gatewayURLs,
            abi.encodeCall(IExtendedResolver.resolve, (name, data)),
            this.resolveStealthCallback.selector,
            abi.encode(name, coinType, legacy, _lookupBinding(key))
        );
    }

    /// @dev `resolve(name, multicall(calls))` and the `multicallWithNodeCheck` form: every call
    ///      resolved as a single `resolve()` on this contract, offchain lookups combined through
    ///      the batch gateway. Never returns normally. Safety, not convenience: forwarded whole, an
    ///      address call inside the batch would reach the records resolver and bypass the gateway
    ///      path.
    function _resolveMulticall(bytes calldata name, bytes[] memory calls) internal view {
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

    /// @dev Walks `name` through the ENSv2 registry from the leaf up. The authority is the nearest
    ///      registered name at or above the leaf, top-level names excluded (their parent is the
    ///      root registry). Its config and records are the name's; nothing is read further up.
    function _context(bytes memory name) internal view returns (NameState memory ctx) {
        // registries[i]: the subregistry of the name at label i (leaf = 0); the last entry is the
        // root registry. Label i sits in registries[i + 1].
        IRegistry[] memory registries = LibResolution.findRegistries(ROOT_REGISTRY, name, 0);
        uint256 offset;
        for (uint256 i; i + 2 < registries.length; ++i) {
            (bytes32 labelHash, uint256 next) = NameCoder.readLabel(name, offset);
            offset = next;
            IRegistry parent = registries[i + 1];
            if (address(parent) == address(0)) continue;
            (uint256 status, uint256 resource) = _registered(parent, labelHash);
            if (status == uint256(IPermissionedRegistry.Status.AVAILABLE)) continue;
            bool reserved = status == uint256(IPermissionedRegistry.Status.RESERVED);
            ctx.resourceKey = keccak256(abi.encode(parent, resource, reserved));
            ctx.key = keccak256(abi.encode(ctx.resourceKey, _versions[ctx.resourceKey]));
            ctx.registry = IPermissionedRegistry(address(parent));
            ctx.resource = resource;
            ctx.exact = i == 0;
            break;
        }
    }

    /// @dev The status of `labelHash` in `registry` (AVAILABLE for an expired name, and for any
    ///      registry that is not a `PermissionedRegistry`) and its EAC resource. A reserved name
    ///      has no token: its resolver, and so its state, is set by whoever holds
    ///      `ROLE_SET_RESOLVER` registry-wide, never by its parent's holder. ENSv2 renews the
    ///      resource when an expired name is registered again, but not when a reserved one is
    ///      registered, nor when a lapsed reservation's label is; the status is therefore part of
    ///      the state key.
    function _registered(IRegistry registry, bytes32 labelHash)
        internal
        view
        returns (uint256 status, uint256 resource)
    {
        (bool ok, bytes memory v) = address(registry).staticcall(
            abi.encodeCall(IPermissionedRegistry.getState, (uint256(labelHash)))
        );
        if (!ok || v.length < 160) return (0, 0);
        (status,,,, resource) = abi.decode(v, (uint256, uint256, uint256, uint256, uint256));
    }

    /// @dev Every batch-gateway failure is wrapped as `UnsafeBatchGatewayResponse(bytes)`, which
    ///      reads as no address. ENS's default passes failures starting with `HttpError` or
    ///      `Error(string)` through unwrapped, checking the selector only, so a batch gateway could
    ///      put bytes of its choosing into a failed multicall item, and a client that decodes the
    ///      item without checking the error marker would read an address it chose.
    function _isSafeBatchGatewayError(bytes4) internal pure override returns (bool) {
        return false;
    }

    /// @dev What a lookup is bound to: the authority `key` and the gateway URLs it was sent to.
    function _lookupBinding(bytes32 key) internal view returns (bytes32) {
        return keccak256(abi.encode(key, _configs[key].gatewayURLs));
    }

    /// @dev Whether address queries for `coinType` go to the gateway under the authority `key`:
    ///      on its chain list, gateway URLs set. Chain lists hold EVM coin types only.
    function _isStealth(bytes32 key, uint256 coinType) internal view returns (bool) {
        return _chains[key][coinType] && _configs[key].gatewayURLs.length > 0;
    }

    /// @dev The ENSIP-30 Section 1 record of `node` for `coinType` under the authority `key`: its
    ///      meta-address if `coinType` is on the chain list, otherwise empty.
    function _record(bytes32 key, bytes32 node, uint256 coinType)
        internal
        view
        returns (bytes memory)
    {
        return _chains[key][coinType] ? _metaAddresses[key][node] : bytes("");
    }

    /// @dev Whether `account` holds `ROLE_SET_RESOLVER` on the authority of `ctx`.
    function _isAuthority(NameState memory ctx, address account) internal view returns (bool) {
        return ctx.key != bytes32(0)
            && ctx.registry.hasRoles(ctx.resource, RegistryRolesLib.ROLE_SET_RESOLVER, account);
    }

    /// @dev The namehash of `name`; reverts unless the profile calldata carries the same node.
    function _checkNode(bytes calldata name, bytes calldata data) internal pure returns (bytes32) {
        bytes32 node = NameCoder.namehash(name, 0);
        if (bytes32(data[4:36]) != node) revert NodeMismatch(bytes32(data[4:36]), node);
        return node;
    }

    /// @dev `verifyStealthResolution` under the authority `key`, shared by the `resolve()` path and
    ///      the callback's verified mode (ENSIP-30 Section 4: the callback is a thin wrapper over
    ///      it).
    function _verifyResolution(
        bytes32 key,
        bytes32 node,
        uint256 coinType,
        address stealthAddress,
        bytes memory verificationData
    ) internal view returns (address) {
        bytes memory record = _record(key, node, coinType);
        if (record.length == 0) revert NoStealthRecord(node, coinType);
        return _verify(node, coinType, record, verificationData, stealthAddress);
    }

    /// @dev Verified mode: the verifier rederives from the record (flag byte and length checked
    ///      when written, the rest by the verifier); the result must equal `claimed`.
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
        if (derived != claimed) revert StealthAddressMismatch();
        return claimed;
    }

    /// @dev ENSIP-30 Section 1 key: decimal, no leading zeros, no `0x`.
    function _stealthKey(uint256 coinType) internal view returns (string memory) {
        return string.concat(_stealthKeyPrefix(), Strings.toString(coinType), "]");
    }

    /// @dev `stealth-meta-address[<schemeId>][`.
    function _stealthKeyPrefix() internal view returns (string memory) {
        return string.concat("stealth-meta-address[", Strings.toString(_SCHEME_ID), "][");
    }

    /// @dev Whether `key` is this scheme's ENSIP-30 Section 1 key in canonical form, and its coin
    ///      type. Non-canonical spellings (`[060]`, `[0x3c]`) are not the record and are forwarded.
    function _parseStealthKey(string memory key)
        internal
        view
        returns (bool ok, uint256 coinType)
    {
        bytes memory k = bytes(key);
        uint256 start = bytes(_stealthKeyPrefix()).length;
        if (k.length <= start + 1 || k[k.length - 1] != "]") return (false, 0);
        for (uint256 i = start; i < k.length - 1; ++i) {
            uint8 digit;
            unchecked {
                digit = uint8(k[i]) - 48; // wraps above 9 for bytes below '0'
            }
            if (digit > 9 || coinType > (type(uint256).max - digit) / 10) return (false, 0);
            coinType = coinType * 10 + digit;
        }
        ok = keccak256(k) == keccak256(bytes(_stealthKey(coinType)));
    }
}
