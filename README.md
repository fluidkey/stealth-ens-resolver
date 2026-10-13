# stealth-resolver

Reference contracts for the ENSIP on stealth address resolution
([ensdomains/ensips#88](https://github.com/ensdomains/ensips/pull/88)): an ENS resolver that resolves
a name to a fresh ERC-5564 stealth address on every lookup and, for names that publish a stealth
meta-address, verifies the gateway's address onchain before resolution completes.

The ENSIP is the specification. Where this code and the ENSIP disagree, the ENSIP wins and the
disagreement is raised against the ENSIP.

> Status: work in progress, not audited, not deployed. Built for ENSv2.

## Design

`StealthResolver` stores one record per name and coin type, the ENSIP's stealth meta-address, and a
small config per registered name. Every other record stays in an unmodified ENS resolver of the
owner's choice, its **records resolver**: the per-account `PermissionedResolver` ENSv2 gives new
names, `PublicResolverV2` for names migrated from ENSv1, an offchain resolver, or any other ENS
resolver. `StealthResolver` is the name's resolver in the ENSv2 registry and forwards those queries
through ENS's own `ResolverCaller`, as ENS's mirror resolvers do.

```
ENSv2 registry ── resolver ──▶ StealthResolver (immutable, one per scheme)
                                 │   stealth records; per registered name: records resolver, gateway URLs
          EVM address, gateway ──┼──▶ OffchainLookup → gateway → callback
                                 │       verified:   against the stored record
                                 │       unverified: the scheme's verifier decides
          stealth record ────────┼──▶ answered from storage
          everything else ───────┴──▶ forwarded unchanged to the records resolver
```

### Resolution rules

`StealthResolver` is queried through ENSIP-10 `resolve()` only. For a name N, each config field is
N's own value, otherwise the nearest ancestor's.

| Query | Result |
|---|---|
| EVM address record (`addr`, `addr(coinType)` for an EVM coin type), gateway URLs set | ERC-3668 lookup to the gateway. **Verified** if N has a stored record for the coin type: the verifier rederives the address and it must equal the gateway's. Otherwise **unverified**: the verifier decides. The zero address is an unset record. |
| Non-EVM address record | Forwarded to the records resolver: the verifier answers with an EVM address. |
| Address record, no gateway URLs | Forwarded to the records resolver; unset if there is none. |
| `data(node, "stealth-meta-address[<scheme>][<coinType>]")` | Answered from storage: the value the callback verifies against. |
| Any other record | Forwarded to the records resolver, including offchain ones. |
| `resolve(name, multicall(...))` | Answered as one batch (ERC-7996 `RESOLVE_MULTICALL`). |
| `gatewayURLs(node)` | N's own URLs; through `resolve()`, the effective URLs. |
| `getResolver(name)` (`ICompositeResolver`) | The records resolver, so apps know where to edit other records. |

**The record served is the record verified**, for every name, wildcard names included. Only the
scheme's key in canonical form is the record; other spellings (`[060]`, `[0x3c]`) are ordinary data,
forwarded. The stealth key written into the records resolver with standard tooling is not the record
and is ignored.

Records are checked when written: empty (cleared), or a flag byte with reserved bits zero followed by
a non-empty meta-address. The scheme's verifier checks the meta-address itself when verifying, and a
malformed one fails the resolution.

Only `addr`, `addr(coinType)` and `multicall` take the gateway path. Other selectors, such as
`multicallWithNodeCheck` or `hasAddr`, are forwarded, so a static address left in the records
resolver of a gateway-configured name is readable through them. Do not keep one there.

**Privacy.** A single address lookup goes from the client to the stealth gateway. In
`resolve(name, multicall(...))` every lookup is batched through ENS's batch gateway, as the
UniversalResolver does for batched resolutions, so that gateway sees the stealth gateway's response,
including `verificationData`.

### Who may write

All state is written under the ENSv2 rule for setting a name's resolver: `ROLE_SET_RESOLVER` on the
name's token, name not expired, the same check as `PermissionedRegistry.setResolver`. It applies to
the **authority** of a name, the nearest registered name at or above it. Top-level names are never an
authority: their state would reach every name below them. A name in a registry that is not an ENSv2
`PermissionedRegistry` counts as unregistered and takes its nearest registered ancestor as authority.

| Function | Name | Written by |
|---|---|---|
| `setConfig(name, recordsResolver, gatewayURLs)` | registered names only | the name's own authority |
| `setStealthRecord(name, coinType, value)` | any name below a registered one | its authority: the name itself if registered, otherwise its nearest registered ancestor |

A parent such as `fkey.eth` therefore writes the records of its wildcard usernames, which exist only
in its gateway. Once a username is registered, only its holder writes its record, and a record the
parent wrote before is no longer read. A records resolver must be a contract other than
`StealthResolver`.

**Trust.** A name is governed by its authority: records, gateway and, in verified mode, the
meta-address it is verified against. This is the ENSIP's trust model for wildcard names. A
registered name escapes its parent by setting its own records resolver, gateway URLs and stealth
records, and its owner should then be the only holder of `ROLE_SET_RESOLVER` on it. A registered
name that sets only its records resolver still inherits the parent's gateway, which then decides,
unverified, every coin type it has no record for.

**Re-registration.** State is keyed by the authority's ENSv2 resource, which the registry renews
when an expired name is registered again, to anyone. `resolve()` therefore never reads a previous
holder's config or records, and the new holder starts empty. An expired name that is not registered
again resolves as a wildcard name of its parent. `gatewayURLs(node)` and
`verifyStealthResolution(node, ...)` take a node, which cannot be walked through the registry: they
read the state last written for that node and so see the previous holder's state until the new
holder writes.

### Setting up a name for verified resolution

1. Deploy (or reuse) a records resolver for the name's other records, for example a
   `PermissionedResolver` through ENS's `VerifiableFactory`.
2. `setConfig(name, recordsResolver, gatewayURLs)`; leave `gatewayURLs` empty to use a parent's.
3. `setStealthRecord(name, coinType, value)` for each coin type.
4. Set the name's resolver in its ENSv2 registry to `StealthResolver`.

A smart account can batch all four. For a wildcard username, the parent's holder calls
`setStealthRecord` for the username's name; the parent's records resolver can be an offchain one.

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
| `StealthResolver` | 20,001 | 4,575 |

Measured by `test/Gas.t.sol`, stored in `snapshots/Gas.json`, checked in CI. Reads are what an
`eth_call` costs; verified-mode numbers use a mock verifier and exclude the scheme's curve arithmetic.
Every `resolve()` walks the name through the registry to find its authority, which is most of the
read cost.

| Path | Gas |
|---|---|
| `resolve` wildcard name, address, `OffchainLookup` revert | 41,747 |
| `resolve` registered name, address, `OffchainLookup` revert | 32,413 |
| `resolveStealthCallback`, unverified (wildcard name) | 39,697 + verifier |
| `resolveStealthCallback`, verified (registered name) | 28,026 + verifier |
| `verifyStealthResolution` | 6,651 + verifier |
| `resolve` text, forwarded to a `PermissionedResolver` | 66,719 |
| `text` on the `PermissionedResolver` directly (reference) | 3,261 |
| `setConfig`, records resolver and one URL (transaction) | 163,230 |
| `setStealthRecord`, 67-byte scheme-1 record (transaction) | 179,224 |

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
