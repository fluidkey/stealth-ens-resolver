# stealth-resolver

Reference contracts for the ENSIP on stealth address resolution
([ensdomains/ensips#88](https://github.com/ensdomains/ensips/pull/88)): an ENS resolver that resolves
a name to a fresh ERC-5564 stealth address on every lookup and, for names that publish a stealth
meta-address, verifies the gateway's address onchain before resolution completes.

The ENSIP is the specification. Where this code and the ENSIP disagree, the ENSIP wins and the
disagreement is raised against the ENSIP.

> Status: work in progress, not audited, not deployed. Built for ENSv2.

## Design

`StealthResolver` stores one stealth meta-address per name (the ENSIP's record value) and a small
config per registered name: records resolver, gateway URLs and a **chain list**, the EVM coin types on
which the name is stealth. Every other record stays in an unmodified ENS resolver of the
owner's choice, its **records resolver**: the per-account `PermissionedResolver` ENSv2 gives new
names, `PublicResolverV2` for names migrated from ENSv1, an offchain resolver, or any other ENS
resolver. `StealthResolver` is the name's resolver in the ENSv2 registry and forwards those queries
through ENS's own `ResolverCaller`, as ENS's mirror resolvers do.

```
ENSv2 registry ── resolver ──▶ StealthResolver (immutable, one per scheme)
                                 │   meta-addresses; per registered name: records resolver, gateway URLs, chain list
  address on a listed chain ─────┼──▶ OffchainLookup → gateway → callback
                                 │       verified:   against the stored meta-address
                                 │       unverified: the scheme's verifier decides
  stealth record ────────────────┼──▶ answered from storage, for listed chains
  everything else ───────────────┴──▶ forwarded unchanged to the records resolver
  (incl. addresses on other chains)
```

### Resolution rules

`StealthResolver` is queried through ENSIP-10 `resolve()` only. A name N resolves with the config
and records of its **authority** (see "Who may write"): N itself if registered, otherwise its nearest
registered ancestor. Nothing is inherited past a registered name.

| Query | Result |
|---|---|
| Address record (`addr`, `addr(coinType)`) for a coin type on the chain list, gateway URLs set | ERC-3668 lookup to the gateway. **Verified** if N has a meta-address: the verifier rederives the address and it must equal the gateway's. Otherwise **unverified**: the verifier decides. The zero address is an unset record. |
| Address record for any other coin type, or no gateway URLs | Forwarded to the records resolver (the name's static address); unset if there is none. |
| `data(node, "stealth-meta-address[<scheme>][<coinType>]")` | N's meta-address if the coin type is on the chain list, otherwise empty: the value the callback verifies against. |
| Any other record | Forwarded to the records resolver, including offchain ones. |
| `resolve(name, multicall(...))`, `resolve(name, multicallWithNodeCheck(node, ...))` | Answered as one batch (ERC-7996 `RESOLVE_MULTICALL`); each item resolved as above. The node-checked form requires the name's node in every item, as ENS's `Multicallable` does. |
| `gatewayURLs(node)` | N's authority's URLs. Through `resolve()` only: called directly it reverts `ResolveOnly` (see Section 5 by name). |
| `schemeId()` | This resolver's scheme, for any name, as the ENSIP requires of `IStealthResolver`'s functions through `resolve()`; also answered directly. |
| `verifyStealthResolution(node, coinType, address, verificationData)` | Verified against N's record, located by name like every other query, wildcard names included. Through `resolve()` only, as above; no CCIP-Read is involved, so contracts can call it onchain. Answered only while `StealthResolver` is the name's resolver in the registry (`NotNamesResolver` otherwise), so a record the name abandoned by moving to another resolver no longer verifies. |
| `getResolver(name)` (`ICompositeResolver`) | The records resolver, so apps know where to edit other records. |

**The record served is the record verified**, for every name, wildcard names included. Only the
scheme's key in canonical form is the record; other spellings (`[060]`, `[0x3c]`) are ordinary data,
forwarded. The stealth key written into the records resolver with standard tooling is not the record
and is ignored.

**Chain lists.** One meta-address serves every listed chain (the ENSIP's rationale allows storing the
key material once and exposing it under each coin type enabled for the name). Only EVM coin types can
be listed, since the verifier answers with an EVM address. A name is stealth on listed chains and
keeps its static address on all others, so stealth on Base and static on Ethereum is one list entry.
The ENSIP-19 default coin type (`0x80000000`) can be listed too, as an opt-in: a query for the
default then goes to the gateway, so the recipient must detect payments on any EVM chain, and a
chain that is not listed still never falls back to it. This departs from the ENSIP draft, which
allows only ENSIP-11 coin types, and is raised against it. `0x80000001`, Ethereum in ENSIP-11 form,
is answered as 60 (its record, its gateway path) and cannot be listed. A records resolver that
holds an ENSIP-19 default address answers every chain without its own record, listed ones queried
under the default included unless the default is listed: keep no default record on a name with
listed chains.
Removing a chain falls back to the static address, never to unverified resolution: a lookup in
flight when the chain or the gateway is removed is rejected (`ChainNotStealth`). A lookup is also
bound to the authority and gateway URLs it was sent to, as ENS's UniversalResolver sends each
callback to the resolver it looked up. If they change before the callback (new URLs, `clearRecords`,
or a lapse that makes the parent the authority), the answer is rejected (`StaleLookup`). The
record, and with it the mode, is still read in the callback, as the ENSIP requires. For Fluidkey,
the list of `fkey.eth` covers every username: adding a chain is one transaction.

Records are checked when written: empty (cleared), or a flag byte with reserved bits zero followed by
a non-empty meta-address. The scheme's verifier checks the meta-address itself when verifying, and a
malformed one fails the resolution.

Only `addr`, `addr(coinType)` and the two multicall forms (`multicall`, `multicallWithNodeCheck`,
both split into single queries) take the gateway path. Other selectors, such as `hasAddr`, are
forwarded, so a static address left in the records resolver for a listed chain is readable through
them (it is public onchain anyway). Do not keep one there; static addresses for unlisted chains are
intended. A nested `resolve(name, resolve(...))` is refused (`UnsupportedResolverProfile`), as ENS's
`PermissionedResolver` refuses it, so it cannot reach that address through a records resolver that
executes inner calldata.

**Batched lookups.** A single address lookup goes from the client to the stealth gateway. In
`resolve(name, multicall(...))` every lookup is batched through ENS's batch gateway, as the
UniversalResolver does for batched resolutions, unless the client batches locally
(`x-batch-gateway:true`). That gateway then sees the stealth gateway's response, including
`verificationData`, and in unverified mode it could replace the address: a verifier that checks
nothing in unverified mode also trusts the batch gateway; one that authenticates the response, such
as a signature by the stealth gateway, does not. In verified mode it cannot change whose address it
is, but it can answer with a derivation from an ephemeral key of its own, which the recipient finds
only if it learns that key. Scheme 1 trusts the batch gateway for this; FK1 requires the stealth
gateway's signature in both modes. A batch gateway can also fail an item; a failed item comes
back as error data, marked by a length of 4 more than a multiple of 32. `StealthResolver` wraps
every batch-gateway failure as `UnsafeBatchGatewayResponse(bytes)` (ENS's default lets ones
starting with `HttpError` or `Error(string)` through), and its own errors and the verifiers'
carry no word a gateway chose (`StealthAddressMismatch()` has no arguments; FK1 reports a
malformed signature as `UnknownSigner(address(0))`). A client that decodes a failed item as an
address without checking the marker therefore reads no address rather than one a gateway picked.
Clients should still check the marker.

### Who may write

All state is written under the ENSv2 rule for setting a name's resolver: `ROLE_SET_RESOLVER` on the
name's token, name not expired, the same check as `PermissionedRegistry.setResolver`. It applies to
the **authority** of a name, the nearest registered name at or above it. Top-level names are never an
authority: their state would reach every name below them. A name in a registry that is not an ENSv2
`PermissionedRegistry` counts as unregistered and takes its nearest registered ancestor as authority.
A reserved name counts as registered, as ENSv2 treats it: it exists in the registry in its own right,
so it is its own authority, written by whoever may set its resolver there (registry-wide
`ROLE_SET_RESOLVER` holders, since it has no token yet) and never by its parent's holder.
Registering it keeps its resource, and with it its state.

| Function | Name | Written by |
|---|---|---|
| `setConfig(name, recordsResolver, gatewayURLs)` | registered names only | the name's own authority |
| `setChains(name, coinTypes, enabled)` | registered names only | the name's own authority |
| `setMetaAddress(name, value)` | any name below a registered one | its authority: the name itself if registered, otherwise its nearest registered ancestor |
| `clearRecords(name)` | registered names only | the name's own authority |

A parent such as `fkey.eth` therefore writes the meta-addresses of its wildcard usernames, which exist only
in its gateway. Once a username is registered, only its holder writes its record, and a record the
parent wrote before is no longer read. `clearRecords(name)` drops all of a registered name's state at
once: its config, its chain list and every record written under it, its wildcard names' included. A
records resolver must be a contract other than `StealthResolver`.

**Trust.** A name is governed by its authority: records, gateway, chain list and, in verified mode,
the meta-address it is verified against. This is the ENSIP's trust model for wildcard names. A
registered name is its own authority and reads nothing from its ancestors, so a parent's config never
reaches it: no gateway URLs means no gateway, and its static address records are forwarded as set.
To use a parent's gateway, a registered name sets the same URLs itself. Its owner should be the only
holder of `ROLE_SET_RESOLVER` on it. A parent that can still change the name's registry entry (swap
its subregistry, unregister it, grant roles in it) governs it anyway, as the ENSIP's trust model
says.

**Re-registration and transfer.** State is keyed by the authority's ENSv2 resource, which the
registry renews when an expired name is registered again, to anyone. A previous holder's config and
records are therefore never read, and the new holder starts empty. A transfer keeps the resource,
and the state with it, as ENS's resolvers keep a name's records: the buyer drops what the seller
left with one `clearRecords(name)`, as with `clearRecords(node)` on ENS's `PublicResolver`. The
same holds when a reserved name is registered. An expired name that is not registered again resolves
as a wildcard name of its parent, and a record the parent wrote for it before it was registered is
served again, as ENS falls back to the parent's resolver. A parent therefore clears a username's
wildcard record before registering the username; it cannot while the username is registered.

**Section 5 by name.** `gatewayURLs(node)` and `verifyStealthResolution(node, ...)` are answered
only through ENSIP-10 `resolve(name, data)`, directly or through the UniversalResolver, which wraps
every profile call that way. A node alone cannot be walked through the registry to the name's
authority, so a direct call reverts `ResolveOnly`; the interface is still reported through ERC-165.
Out-of-flow verifiers and contracts consuming stealth resolutions call
`resolve(name, verifyStealthResolution(...))`. The ENSIP allows this for deployments such as ENSv2,
where the authority over a name is reachable only by name.

### Setting up a name for verified resolution

1. Deploy (or reuse) a records resolver for the name's other records, for example a
   `PermissionedResolver` through ENS's `VerifiableFactory`.
2. `setConfig(name, recordsResolver, gatewayURLs)` with the gateway's URLs (for a Fluidkey user,
   Fluidkey's); empty URLs mean no gateway.
3. `setChains(name, coinTypes, true)` with the chains the recipient scans.
4. `setMetaAddress(name, value)`.
5. Set the name's resolver in its ENSv2 registry to `StealthResolver`.

A smart account can batch all five. For a name acquired by transfer, call `clearRecords(name)`
first. For a wildcard username, the parent's holder calls `setMetaAddress` for the username's name;
the parent's records resolver can be an offchain one.

### Scheme 1

`Scheme1Verifier` verifies ERC-5564 scheme 1 (secp256k1 with view tags) as the ScopeLift
stealth-address SDK derives it: for meta-address `(P_spend, P_view)` and ephemeral private key `e`,

```
S   = e·P_view                         shared secret point (ECDH)
s_h = keccak256(compressed S) mod n    33 bytes hashed: 0x02 or 0x03 prefix, then x
stealth address = address(P_spend + s_h·G)
```

ERC-5564 leaves the hashed encoding open and implementations differ; the compressed point is what
the SDK, and wallets built on it, use.

The EVM has no secp256k1 arithmetic except `ecrecover`, which can compute `a·G + b·Q` but returns
only the result's address. That covers the last step. Hashing `S` needs its coordinates, so the
gateway sends `S` and the verifier checks that its address is that of `e·P_view`. Passing a wrong
`S` takes about 2^80 work (the gateway also picks `e`) and gains nothing a gateway cannot get by
choosing its own `e`. Two `ecrecover` calls, no curve library: `LibEcrecover` holds the
construction, the one Chainlink's VRF verifier uses in production, and its tests check it against
Chainlink's code and against direct key derivation. Scheme 1's `verificationData` is therefore 96
bytes, `e || S.x || S.y` (the ENSIP leaves the format to each scheme); a gateway computes `S`
anyway.

The meta-address must be two compressed keys whose x-coordinates are below the group order `n`;
anything else, including the one in about 2^128 valid keys at or above `n` that `ecrecover` cannot
take, is malformed and fails the resolution. With no meta-address the verifier returns the
gateway's address unchecked: unverified mode trusts the gateway and, for batched lookups, the batch
gateway. A verifier must be as immutable as the resolver, since it decides the derived address:
`Scheme1Verifier` has no state and no owner.

### Fluidkey stealth Safe (FK1)

`FluidkeyVerifier` verifies Fluidkey's scheme as fluidkey-stealth-account-kit 1.1.1 derives it. It
is not scheme 1: the key exchange uses the spending key, the stealth key is a multiple of it, and
the stealth address is a counterfactual 1-of-1 Safe owned by that key:

```
S     = e·P_spend                       shared secret point (ECDH with the spending key)
h     = keccak256(S.x || S.y) mod n     uncompressed point, no prefix
owner = address(h·P_spend)
stealth address = CREATE2 address of a Safe 1.3.0 proxy owned by `owner`, threshold 1
```

The Safe uses the default Safe 1.3.0 deployments (factory, L1 singleton, compatibility fallback
handler, MultiSend, SafeModuleSetup), so a stealth Safe has the same address on every chain. It is
the recipient's only where those contracts are deployed: elsewhere the address can be out of reach,
or deployable without its setup by whoever knows `owner`. The verifier therefore answers only for
the chains below, which all have them, and for the ENSIP-19 default, and reverts `UnsupportedChain`
for any other coin type in both modes. The list is immutable: a name that lists another chain fails
lookups on it.

| Chain | Coin type |
|---|---|
| Ethereum | `60` |
| Base | `0x80002105` |
| OP Mainnet | `0x8000000a` |
| Arbitrum One | `0x8000a4b1` |
| Polygon PoS | `0x80000089` |
| Gnosis | `0x80000064` |
| BNB Smart Chain | `0x80000038` |
| ENSIP-19 default (any EVM chain) | `0x80000000` |

The default is answered for authorities that list it (see "Chain lists"), so that wallets asking
only for the default get a stealth Safe. Its answer names no chain, so a payer can use it on any EVM
chain, including one where the Safe is not the recipient's: out of reach on zkSync-family chains,
and on a chain without the Safe contracts deployable without its setup by anyone who saw the
lookup. Fluidkey derives the same Safe for every chain, so on the seven chains above the payment
is found. An authority lists the default only if it accepts that risk for payers whose wallets ask
for it.

The Safe's setup `to` and `data` follow the account's auto-earn setting and affect who can move
funds, so they are fixed by the scheme and selected by the record, never by the gateway (ENSIP-30
Section 5). The meta-address is 65 bytes, the compressed spending key followed by a `configHash`: 0
means auto-earn off and an empty setup; any other value means a setup that enables Fluidkey's Earn
module and installs that `configHash`, rebuilt from a fixed template that reproduces the setup data
of Fluidkey's production Safes. The `configHash` is part of the Safe's address, so the record
carries the one new Safes are installed with, not the value the module stores for an existing Safe,
which can change after deployment. Changing auto-earn settings is a record write; a new Earn module
or Safe version is a new scheme, FK2, with its own verifier and resolver.

Any `configHash` is accepted: the name's authority, which writes the record, chooses it. A
`configHash` stands for a list of (chain, token, vault) entries registered in the Earn module by its
owner, a Fluidkey multisig, and lets the relayers the owner appoints deposit the Safe's listed
tokens into the listed vaults. The module's owner and relayers are therefore trusted for auto-earn
Safes, and an authority writes only a `configHash` whose list it has checked. On BNB Smart Chain the
Earn module is not deployed yet, so an auto-earn Safe there enables a module address with no code,
and whoever deploys code at that address would control those Safes. This relies on that address
being deployable only by Fluidkey's multisig.

Both modes require a signature by an account that `FluidkeySigners` lists (EIP-712, domain
`FluidkeyVerifier`, version `1`), bound to the resolver, name and chain:

- Verified mode: `verificationData` is `e || S.x || S.y || signature`, 161 bytes. The derivation is
  checked as for scheme 1, with two `ecrecover` calls, and the signature is over
  `VerifiedStealthResolution(address resolver, bytes32 node, uint256 coinType, address
  stealthAddress)` for the derived Safe. Any `e` with its point passes the curve checks, so without
  the signature a batch gateway could answer from an ephemeral key of its own: the Safe would still
  be the recipient's, but Fluidkey, which finds payments by regenerating its own ephemeral keys,
  would not find it. The signature does not expire: the record fixes the Safe for each `e`, so a
  replayed response answers the same Safe again, and the payers it is replayed to share one address.
- Unverified mode (no record): `verificationData` is `abi.encode(uint64 expires, bytes signature)`,
  over `StealthResolution(address resolver, bytes32 node, uint256 coinType, address stealthAddress,
  uint64 expires)`. That stops a batch gateway from substituting the address; it authenticates
  Fluidkey and is not verification under the ENSIP. `expires` may be at most 10 minutes
  (`MAX_VALIDITY`) after the block's timestamp: a relay that kept a response can serve it until
  then, also after the name changes hands. The gateway signs well inside the limit, such as 5
  minutes, to allow for clock skew and lagging RPCs.

`FluidkeySigners` is owned by Fluidkey so signing keys rotate without redeploying. Its ownership
can be transferred (in two steps) but not renounced, which would freeze the signer set, leaked keys
included. In verified mode a signer can refuse a derivation but cannot make the verifier return a
Safe the record does not derive. The scheme ID, FK1 (`0x464B31`, 4606769), is a constructor
argument: the scheme's ERC declares it.

Fluidkey's gateway answers with the Safe address and, if the name has a record (read onchain as the
callback reads it), `e || S.x || S.y` and the signature; otherwise the signed expiry. Records
written for FK1 keep the client-side derivation flag clear: Fluidkey finds payments by regenerating
its own ephemeral keys and cannot detect ones a sender derived.

## Contracts

| Contract | Role |
|---|---|
| `StealthResolver` | The verifying resolver |
| `interfaces/IStealthResolver` | ENSIP Section 5, verbatim |
| `interfaces/IStealthVerifier` | Scheme-specific verification, one verifier per scheme |
| `verifiers/Scheme1Verifier` | ERC-5564 scheme 1 (see Scheme 1) |
| `verifiers/FluidkeyVerifier` | Fluidkey stealth Safe, FK1 (see Fluidkey stealth Safe) |
| `verifiers/FluidkeySigners` | Fluidkey gateway signers for FK1, owned by Fluidkey |
| `verifiers/LibEcrecover` | secp256k1 `a·G + b·Q` on `ecrecover`, shared by the verifiers |

ENS code used unchanged: `ResolverCaller`, `CCIPReader`, `CCIPBatcher`, `NameCoder`, `ENSIP19`
(ens-contracts); `LibResolution`, `RegistryRolesLib` and the registry interfaces (namechain).

## Size and gas

| Contract | Runtime bytes | Margin to 24,576 |
|---|---|---|
| `StealthResolver` | 22,128 | 2,448 |
| `Scheme1Verifier` | 1,657 | 22,919 |
| `FluidkeyVerifier` | 5,803 | 18,773 |
| `FluidkeySigners` | 927 | 23,649 |

Measured by `test/Gas.t.sol`, stored in `snapshots/Gas.json`, checked in CI. Reads are what an
`eth_call` costs; verified-mode numbers use a mock verifier, and the verifier's own cost is listed
separately.
Every `resolve()` looks the name up in the registry to find its authority, which is most of the
read cost.

| Path | Gas |
|---|---|
| `resolve` wildcard name, address, `OffchainLookup` revert | 44,877 |
| `resolve` registered name, address, `OffchainLookup` revert | 25,276 |
| `resolveStealthCallback`, unverified (wildcard name) | 49,278 + verifier |
| `resolveStealthCallback`, verified (registered name) | 30,703 + verifier |
| `resolve` registered name, `verifyStealthResolution` | 43,773 + verifier |
| `Scheme1Verifier.verify`, verified mode (the "+ verifier" for scheme 1) | 16,130 |
| `FluidkeyVerifier.verify`, verified mode, auto-earn Safe, signed | 27,683 |
| `FluidkeyVerifier.verify`, unverified mode, signed | 14,923 |
| `resolve` text, forwarded to a `PermissionedResolver` | 43,907 |
| `resolve` text on the `PermissionedResolver` directly (reference) | 6,426 |
| `setConfig`, records resolver and one URL (transaction) | 143,390 |
| `setChains`, one chain (transaction) | 91,449 |
| `setMetaAddress`, 67-byte scheme-1 record (transaction) | 158,920 |

## Build and test

Requires [Foundry](https://book.getfoundry.sh/).

```bash
git clone --recurse-submodules <repo>
forge build
forge test
./script/verify-canonical-build.sh
./script/check-ensip-sync.sh
```

Tests run on namechain's own ENSv1 and ENSv2 fixtures, including resolution through
UniversalResolverV2. Two fork tests are pinned to blocks, so their RPCs must serve historical
state: one against ENS's ENSv2 deployment on Sepolia when `SEPOLIA_RPC_URL` is set, one checking
`FluidkeyVerifier`'s Safe constants against Ethereum mainnet (the live factory deploys the Safe at
the predicted address) when `MAINNET_RPC_URL` is set:

```bash
SEPOLIA_RPC_URL=<rpc> MAINNET_RPC_URL=<rpc> forge test --match-path "test/fork/*"
```

The scheme 1 test vectors in `test/utils/Scheme1Vectors.sol` are derivations by the ScopeLift SDK,
each also rederived from the curve operations by the generator. To regenerate them:

```bash
npm install --prefix <dir> --ignore-scripts @scopelift/stealth-address-sdk@1.0.0-beta.5
node script/vectors/scheme1.mjs <dir> > test/utils/Scheme1Vectors.sol && forge fmt
```

The FK1 vectors in `test/utils/FluidkeyVectors.sol` come from Fluidkey's stealth-account-kit the
same way, for three Safe setups (auto-earn off, the kit's auto-earn v1.1 `configHash`, another one):

```bash
npm install --prefix <dir> --ignore-scripts @fluidkey/stealth-account-kit@1.1.1
node script/vectors/fluidkey.mjs <dir> > test/utils/FluidkeyVectors.sol && forge fmt
```

`test/reference/ChainlinkVRF.sol` is Chainlink's `VRF.sol`, vendored unchanged at a pinned commit as
the reference `LibEcrecover` is tested against; it is never imported by `src/` and is excluded from
formatting.

Running a subset of tests rewrites `snapshots/` without the gas file; run the full suite before
committing, or restore it with `git checkout snapshots/`.

`check-ensip-sync.sh` checks that `src/interfaces/IStealthResolver.sol` contains the ENSIP's Section 5
interface verbatim, against the pinned ENSIP commit (override with `ENSIP_REF`, or point `ENSIP_FILE`
at a local draft). `verify-canonical-build.sh` checks that this repo's dependency setup compiles ENS's
`PublicResolverV2` byte-for-byte as namechain does. Both run in CI.

## Dependencies

| Dependency | Pin | Notes |
|---|---|---|
| [ensdomains/namechain](https://github.com/ensdomains/namechain) | `62778d8`, tag `v2-mainnet-deployment-1` (2026-10-02) | ENSv2 contracts and test fixtures |
| [ensdomains/ens-contracts](https://github.com/ensdomains/ens-contracts) | `121dc23`, the commit namechain pins | resolver interfaces, CCIP-Read helpers |
| [OpenZeppelin/openzeppelin-contracts](https://github.com/OpenZeppelin/openzeppelin-contracts) | `e4f7021` (v5) and `54b3f14` (v4), as namechain pins | |
| [foundry-rs/forge-std](https://github.com/foundry-rs/forge-std) | latest at setup | tests only |

ens-contracts and OpenZeppelin are used from namechain's own submodules, so their versions cannot
drift from what ENSv2 is built and audited against. Compiler settings match ENSv2's production
build: solc 0.8.25, EVM `cancun`, optimizer at 1000 runs. namechain is pinned to its ENSv2 mainnet
release tag; the Sepolia fork test uses the deployment that tag's `docs/addresses/sepolia.md`
lists (2026-10-01).

`remappings.txt` mirrors namechain's. Two of namechain's lines (OpenZeppelin v4 for ens-contracts,
and an `mcopy` variant of ens-contracts' `LibMem`) do not take effect under Foundry in either repo;
`verify-canonical-build.sh` confirms both builds resolve the same sources.

## Deployment

`script/DeployScheme1Verifier.s.sol` deploys `Scheme1Verifier` through the canonical CREATE2
deployer with salt `keccak256("ENSIP-30 Scheme1Verifier")`. It has no constructor arguments, so it
has one address on every chain, and the script does nothing if it is already there:

```bash
forge script script/DeployScheme1Verifier.s.sol --fork-url $RPC_URL
```

`script/DeployFluidkeyVerifier.s.sol` deploys `FluidkeySigners` (owned by `SIGNERS_OWNER`) and
`FluidkeyVerifier` the same way, with salts `keccak256("ENSIP-30 FluidkeySigners")` and
`keccak256("ENSIP-30 FluidkeyVerifier")`. Deploy it only once the scheme's ERC declares the ID:

```bash
SIGNERS_OWNER=<a> SCHEME_ID=4606769 forge script script/DeployFluidkeyVerifier.s.sol --fork-url $RPC_URL
```

`script/Deploy.s.sol` then deploys `StealthResolver` through the canonical CREATE2 deployer
(`0x4e59b44847b379578588920cA78FbF26c0B4956C`) with salt `keccak256("ENSIP-30 StealthResolver")`.
The address depends only on the salt, the bytecode and the constructor arguments (ENSv2 root
registry, verifier, batch gateway provider), so there is one resolver per verifier; pass the
verifier's printed address as `VERIFIER`. Without `--broadcast` either script only simulates:

```bash
ROOT_REGISTRY=<a> VERIFIER=<a> BATCH_GATEWAY_PROVIDER=<a> forge script script/Deploy.s.sol --fork-url $RPC_URL
```

## License

[MIT](LICENSE)
