# stealth-resolver

Reference contracts for the ENSIP on stealth address resolution
([ensdomains/ensips#88](https://github.com/ensdomains/ensips/pull/88)): an ENS resolver that resolves
a name to a fresh ERC-5564 stealth address on every lookup and, for names that publish a stealth
meta-address, verifies the gateway's address onchain before resolution completes.

The ENSIP is the specification. Where this code and the ENSIP disagree, the ENSIP wins and the
disagreement is raised against the ENSIP.

> Status: work in progress, not audited, not deployed. Built for ENSv2.

## Design

`StealthResolver` stores no records. A name's records stay in an unmodified ENS resolver of the
owner's choice, its **records resolver**: the per-account `PermissionedResolver` ENSv2 gives new
names, `PublicResolverV2` for names migrated from ENSv1, an offchain resolver, or any other ENS
resolver. `StealthResolver` is the name's resolver in the ENSv2 registry and forwards every query to
the records resolver through ENS's own `ResolverCaller`, as ENS's mirror resolvers do. It adds only
what the ENSIP requires.

```
ENSv2 registry ── resolver ──▶ StealthResolver (immutable, one per scheme)
                                 │   per name: records resolver, gateway URLs
          address, gateway set ──┼──▶ OffchainLookup → gateway → callback
                                 │       verified:   meta-address read onchain from the records resolver
                                 │       unverified: the scheme's verifier decides
          stealth record ────────┼──▶ answered from that same onchain read
          everything else ───────┴──▶ forwarded unchanged to the records resolver
```

### Resolution rules

`StealthResolver` is queried through ENSIP-10 `resolve()` only. For a name N, each config field is
N's own value, otherwise the nearest ancestor's.

| Query | Result |
|---|---|
| Address record, gateway URLs set | ERC-3668 lookup to the gateway. **Verified** if N's records resolver holds the ENSIP record for the coin type: the verifier rederives the address and it must equal the gateway's. Otherwise **unverified**: the verifier decides. |
| Address record, no gateway URLs | Forwarded to the records resolver; zero if there is none. |
| `data(node, "stealth-meta-address[<scheme>][<coinType>]")` | Answered by `StealthResolver` from the same onchain read the callback verifies against. |
| Any other record | Forwarded to the records resolver, including offchain ones. |
| `resolve(name, multicall(...))` | Answered as one batch (ERC-7996 `RESOLVE_MULTICALL`). |
| `gatewayURLs(node)` | N's own URLs; through `resolve()`, the effective URLs. |
| `getResolver(name)` (`ICompositeResolver`) | The records resolver, so apps know where to edit records. |

**The record served is the record verified.** Verification reads the record from N's records
resolver, own or inherited, exactly as `resolve()` serves it. A wildcard username such as
`bob.fkey.eth`, which exists only in the parent's gateway, resolves verified once the parent writes
its record into the parent's records resolver under the username's node. A lying gateway then cannot
redirect its payments.

The record is read onchain with `data(node, key)` on the records resolver, never through its
gateway. A records resolver without the ENSIP-24 `data()` profile, such as an offchain resolver, has
no record (unverified), and the record reads as empty through `resolve()` instead of being fetched
offchain. One that reports the profile but reverts makes the resolution fail. Records that are only a
flag byte, or set reserved flag bits, are rejected. Only the scheme's key in canonical form is the
record; other spellings (`[060]`, `[0x3c]`) are ordinary data, forwarded.

The record is read under N's own node. `PermissionedResolver` aliases apply to forwarded records but
not to the stealth record, so write it under the name itself.

`verifyStealthResolution(node, ...)` cannot walk a node to its ancestors, so it verifies names with
their own records resolver only. Wildcard names are verified in the callback but revert
`NoStealthRecord` there.

**Privacy.** A single address lookup goes from the client to the stealth gateway. In
`resolve(name, multicall(...))` every lookup is batched through ENS's batch gateway, as the
UniversalResolver does for batched resolutions, so that gateway sees the stealth gateway's response,
including `verificationData`.

### Who may configure a name

`setConfig(name, recordsResolver, gatewayURLs)` is allowed for whoever may set the name's resolver in
ENSv2: `ROLE_SET_RESOLVER` on the name's token in its parent registry, name not expired, the same
check as `PermissionedRegistry.setResolver`. Choosing the records resolver is equivalent to choosing
the resolver, so no one gains power they did not have. Top-level names cannot be configured: their
config would reach every name below them. A name cannot use `StealthResolver` as its own records
resolver.

**Trust.** A name without its own config is governed entirely by its nearest configured ancestor:
records, gateway and, in verified mode, the meta-address it is verified against. This is the ENSIP's
trust model for wildcard names. A registered name escapes it by setting its own config, and its owner
should then be the only holder of `ROLE_SET_RESOLVER` on it.

**Re-registration.** Config is keyed by node and outlives a registration. When a name expires and is
registered to someone else, the previous holder's config applies until the new holder calls
`setConfig`. Registrars should not register a reused label with `StealthResolver` as its resolver
before its new holder has configured it.

### Setting up a name for verified resolution

1. Deploy (or reuse) a `PermissionedResolver` you administer, through ENS's `VerifiableFactory`.
2. Write the meta-address record there: `setData(node, "stealth-meta-address[<scheme>][<coinType>]", value)`.
3. `setConfig(name, yourRecordsResolver, gatewayURLs)`; leave `gatewayURLs` empty to use a parent's.
4. Set the name's resolver in its ENSv2 registry to `StealthResolver`.

Configure before pointing the name, so that no earlier config applies in between. Steps 1 and 2 can
be one transaction (`initialize` takes setters); a smart account can batch all four.

For wildcard usernames under a parent, the parent writes each username's record into its own records
resolver, which must hold records onchain (a `PermissionedResolver`, not an offchain resolver).

## Contracts

| Contract | Role |
|---|---|
| `StealthResolver` | The verifying resolver |
| `interfaces/IStealthResolver` | ENSIP Section 5, verbatim |
| `interfaces/IStealthVerifier` | Scheme-specific verification, one verifier per scheme |

ENS code used unchanged: `ResolverCaller`, `CCIPReader`, `CCIPBatcher`, `NameCoder` (ens-contracts);
`LibRegistry`, `RegistryRolesLib` and the registry interfaces (namechain).

## Size and gas

| Contract | Runtime bytes | Margin to 24,576 |
|---|---|---|
| `StealthResolver` | 18,391 | 6,185 |

Measured by `test/Gas.t.sol`, stored in `snapshots/Gas.json`, checked in CI. Reads are what an
`eth_call` costs; verified-mode numbers use a mock verifier and exclude the scheme's curve arithmetic.

| Path | Gas |
|---|---|
| `resolve` wildcard name, address, `OffchainLookup` revert | 22,049 |
| `resolve` registered name, address, `OffchainLookup` revert | 11,944 |
| `resolveStealthCallback`, unverified (wildcard, record looked up in the parent's records resolver) | 40,448 + verifier |
| `resolveStealthCallback`, verified | 30,461 + verifier |
| `verifyStealthResolution` | 19,578 + verifier |
| `resolve` text, forwarded to a `PermissionedResolver` | 45,137 |
| `text` on the `PermissionedResolver` directly (reference) | 3,260 |
| `setConfig`, records resolver and one URL (transaction) | 139,636 |

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
