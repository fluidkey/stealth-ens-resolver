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
| `resolve(name, multicall(...))` | Answered as one batch (ERC-7996 `RESOLVE_MULTICALL`). |
| `gatewayURLs(node)` | N's authority's URLs. Through `resolve()` only: called directly it reverts `ResolveOnly` (see Section 5 by name). |
| `verifyStealthResolution(node, coinType, address, verificationData)` | Verified against N's record, located by name like every other query, wildcard names included. Through `resolve()` only, as above; no CCIP-Read is involved, so contracts can call it onchain. |
| `getResolver(name)` (`ICompositeResolver`) | The records resolver, so apps know where to edit other records. |

**The record served is the record verified**, for every name, wildcard names included. Only the
scheme's key in canonical form is the record; other spellings (`[060]`, `[0x3c]`) are ordinary data,
forwarded. The stealth key written into the records resolver with standard tooling is not the record
and is ignored.

**Chain lists.** One meta-address serves every listed chain (the ENSIP's rationale allows storing the
key material once and exposing it under each coin type enabled for the name). Only EVM coin types can
be listed, since the verifier answers with an EVM address. A name is stealth on listed chains and
keeps its static address on all others, so stealth on Base and static on Ethereum is one list entry.
Removing a chain falls back to the static address, never to unverified resolution: a lookup in
flight when the chain or the gateway is removed is rejected (`ChainNotStealth`). For Fluidkey, the
list of `fkey.eth` covers every username: adding a chain is one transaction.

Records are checked when written: empty (cleared), or a flag byte with reserved bits zero followed by
a non-empty meta-address. The scheme's verifier checks the meta-address itself when verifying, and a
malformed one fails the resolution.

Only `addr`, `addr(coinType)` and `multicall` take the gateway path. Other selectors, such as
`multicallWithNodeCheck` or `hasAddr`, are forwarded, so a static address left in the records
resolver for a listed chain is readable through them (it is public onchain anyway). Do not keep one
there; static addresses for unlisted chains are intended.

**Batched lookups.** A single address lookup goes from the client to the stealth gateway. In
`resolve(name, multicall(...))` every lookup is batched through ENS's batch gateway, as the
UniversalResolver does for batched resolutions, unless the client batches locally
(`x-batch-gateway:true`). That gateway then sees the stealth gateway's response, including
`verificationData`, and in unverified mode it could replace the address: a verifier that checks
nothing in unverified mode also trusts the batch gateway; one that authenticates the response, such
as a signature by the stealth gateway, does not. Verified mode is unaffected.

### Who may write

All state is written under the ENSv2 rule for setting a name's resolver: `ROLE_SET_RESOLVER` on the
name's token, name not expired, the same check as `PermissionedRegistry.setResolver`. It applies to
the **authority** of a name, the nearest registered name at or above it. Top-level names are never an
authority: their state would reach every name below them. A name in a registry that is not an ENSv2
`PermissionedRegistry` counts as unregistered and takes its nearest registered ancestor as authority.

| Function | Name | Written by |
|---|---|---|
| `setConfig(name, recordsResolver, gatewayURLs)` | registered names only | the name's own authority |
| `setChains(name, coinTypes, enabled)` | registered names only | the name's own authority |
| `setMetaAddress(name, value)` | any name below a registered one | its authority: the name itself if registered, otherwise its nearest registered ancestor |

A parent such as `fkey.eth` therefore writes the meta-addresses of its wildcard usernames, which exist only
in its gateway. Once a username is registered, only its holder writes its record, and a record the
parent wrote before is no longer read. A records resolver must be a contract other than
`StealthResolver`.

**Trust.** A name is governed by its authority: records, gateway, chain list and, in verified mode,
the meta-address it is verified against. This is the ENSIP's trust model for wildcard names. A
registered name is its own authority and reads nothing from its ancestors, so a parent's config never
reaches it: no gateway URLs means no gateway, and its static address records are forwarded as set.
To use a parent's gateway, a registered name sets the same URLs itself. Its owner should be the only
holder of `ROLE_SET_RESOLVER` on it.

**Re-registration.** State is keyed by the authority's ENSv2 resource, which the registry renews
when an expired name is registered again, to anyone. A previous holder's config and records are
therefore never read, and the new holder starts empty. An expired name that is not registered again
resolves as a wildcard name of its parent.

**Section 5 by name.** `gatewayURLs(node)` and `verifyStealthResolution(node, ...)` are answered
only through ENSIP-10 `resolve(name, data)`, directly or through the UniversalResolver, which wraps
every profile call that way. A node alone cannot be walked through the registry to the name's
authority, so a direct call reverts `ResolveOnly`; the interface is still reported through ERC-165.
Out-of-flow verifiers and contracts consuming stealth resolutions call
`resolve(name, verifyStealthResolution(...))`. This departs from the ENSIP draft, whose Section 2
has clients call `gatewayURLs(node)` and whose Section 5 implies both functions answer a direct
call; it is raised against the ENSIP. The alternative, remembering per node which authority wrote
last, costs a storage write per `setConfig` and `setMetaAddress` and answers for a previous holder
after a re-registration until the new holder writes.

### Setting up a name for verified resolution

1. Deploy (or reuse) a records resolver for the name's other records, for example a
   `PermissionedResolver` through ENS's `VerifiableFactory`.
2. `setConfig(name, recordsResolver, gatewayURLs)` with the gateway's URLs (for a Fluidkey user,
   Fluidkey's); empty URLs mean no gateway.
3. `setChains(name, coinTypes, true)` with the chains the recipient scans.
4. `setMetaAddress(name, value)`.
5. Set the name's resolver in its ENSv2 registry to `StealthResolver`.

A smart account can batch all five. For a wildcard username, the parent's holder calls
`setMetaAddress` for the username's name; the parent's records resolver can be an offchain one.

## Contracts

| Contract | Role |
|---|---|
| `StealthResolver` | The verifying resolver |
| `interfaces/IStealthResolver` | ENSIP Section 5, verbatim |
| `interfaces/IStealthVerifier` | Scheme-specific verification, one verifier per scheme |

ENS code used unchanged: `ResolverCaller`, `CCIPReader`, `CCIPBatcher`, `NameCoder`, `ENSIP19`
(ens-contracts); `LibRegistry`, `RegistryRolesLib` and the registry interfaces (namechain).

## Size and gas

| Contract | Runtime bytes | Margin to 24,576 |
|---|---|---|
| `StealthResolver` | 20,547 | 4,029 |

Measured by `test/Gas.t.sol`, stored in `snapshots/Gas.json`, checked in CI. Reads are what an
`eth_call` costs; verified-mode numbers use a mock verifier and exclude the scheme's curve arithmetic.
Every `resolve()` looks the name up in the registry to find its authority, which is most of the
read cost.

| Path | Gas |
|---|---|
| `resolve` wildcard name, address, `OffchainLookup` revert | 40,792 |
| `resolve` registered name, address, `OffchainLookup` revert | 23,191 |
| `resolveStealthCallback`, unverified (wildcard name) | 43,675 + verifier |
| `resolveStealthCallback`, verified (registered name) | 29,100 + verifier |
| `resolve` registered name, `verifyStealthResolution` | 26,778 + verifier |
| `resolve` text, forwarded to a `PermissionedResolver` | 61,211 |
| `text` on the `PermissionedResolver` directly (reference) | 3,261 |
| `setConfig`, records resolver and one URL (transaction) | 140,884 |
| `setChains`, one chain (transaction) | 88,931 |
| `setMetaAddress`, 67-byte scheme-1 record (transaction) | 156,409 |

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
UniversalResolverV2. A fork test runs against ENS's ENSv2 deployment on Sepolia when
`SEPOLIA_RPC_URL` is set. It is pinned to a block, so the RPC must serve historical state:

```bash
SEPOLIA_RPC_URL=<rpc> forge test --match-path "test/fork/*"
```

Running a subset of tests rewrites `snapshots/` without the gas file; run the full suite before
committing, or restore it with `git checkout snapshots/`.

`check-ensip-sync.sh` checks that `src/interfaces/IStealthResolver.sol` contains the ENSIP's Section 5
interface verbatim, against the pinned ENSIP commit (override with `ENSIP_REF`, or point `ENSIP_FILE`
at a local draft). `verify-canonical-build.sh` checks that this repo's dependency setup compiles ENS's
`PublicResolverV2` byte-for-byte as namechain does. Both run in CI.

## Dependencies

| Dependency | Pin | Notes |
|---|---|---|
| [ensdomains/namechain](https://github.com/ensdomains/namechain) | `48b3e2d` (2026-07-03, post-audit) | ENSv2 contracts and test fixtures |
| [ensdomains/ens-contracts](https://github.com/ensdomains/ens-contracts) | `3b1cc22`, the commit namechain pins | resolver interfaces, CCIP-Read helpers |
| [OpenZeppelin/openzeppelin-contracts](https://github.com/OpenZeppelin/openzeppelin-contracts) | `e4f7021` (v5) and `54b3f14` (v4), as namechain pins | |
| [foundry-rs/forge-std](https://github.com/foundry-rs/forge-std) | latest at setup | tests only |

ens-contracts and OpenZeppelin are used from namechain's own submodules, so their versions cannot
drift from what ENSv2 is built and audited against. Compiler settings match ENSv2's production
build: solc 0.8.25, EVM `cancun`, optimizer at 1000 runs. Re-pin namechain to the ENSv2 mainnet
release before deploying.

`remappings.txt` mirrors namechain's. Two of namechain's lines (OpenZeppelin v4 for ens-contracts,
and an `mcopy` variant of ens-contracts' `LibMem`) do not take effect under Foundry in either repo;
`verify-canonical-build.sh` confirms both builds resolve the same sources.

## Deployment

`script/Deploy.s.sol` deploys through the canonical CREATE2 deployer
(`0x4e59b44847b379578588920cA78FbF26c0B4956C`) with salt `keccak256("ENSIP-30 StealthResolver")`.
The address depends only on the salt, the bytecode and the constructor arguments (ENSv2 root
registry, verifier, batch gateway provider), so there is one resolver per verifier. Without
`--broadcast` the script only simulates:

```bash
ROOT_REGISTRY=<a> VERIFIER=<a> BATCH_GATEWAY_PROVIDER=<a> forge script script/Deploy.s.sol --fork-url $RPC_URL
```

## License

[MIT](LICENSE)
