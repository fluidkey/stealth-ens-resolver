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
                                 │       verified:   meta-address read from the name's own records resolver
                                 │       unverified: the scheme's verifier decides
          everything else ───────┴──▶ forwarded unchanged to the records resolver
```

### Resolution rules

`StealthResolver` is queried through ENSIP-10 `resolve()` only. For a name N, each config field is
N's own value, otherwise the nearest ancestor's.

| Query | Result |
|---|---|
| Address record, gateway URLs set | ERC-3668 lookup to the gateway. **Verified** if N's own records resolver holds the ENSIP record for the coin type: the verifier rederives the address and it must equal the gateway's. Otherwise **unverified**: the verifier decides. |
| Address record, no gateway URLs | Forwarded to the records resolver; zero if there is none. |
| Any other record | Forwarded to the records resolver, including offchain ones. |
| `resolve(name, multicall(...))` | Answered as one batch (ERC-7996 `RESOLVE_MULTICALL`). |
| `gatewayURLs(node)` | N's own URLs; through `resolve()`, the effective URLs. |
| `getResolver(name)` (`ICompositeResolver`) | The records resolver, so apps know where to edit records. |

Verified mode only reads the name's **own** records resolver. An inherited records resolver belongs to
an ancestor, which would otherwise be trusted for safety. Names that are not in the registry
therefore always resolve unverified.

A records resolver without the ENSIP-24 `data()` profile has no record (unverified). One that reports
the profile but reverts makes the resolution fail. Records that are only a flag byte, or set reserved
flag bits, are rejected.

### Who may configure a name

`setConfig(name, recordsResolver, gatewayURLs)` is allowed for whoever may set the name's resolver in
ENSv2: `ROLE_SET_RESOLVER` on the name's token in its parent registry, name not expired, the same
check as `PermissionedRegistry.setResolver`. Choosing the records resolver is equivalent to choosing
the resolver, so no one gains power they did not have. For verified mode the name's owner should be
the only holder of that role.

### Setting up a name for verified resolution

1. Deploy (or reuse) a `PermissionedResolver` you administer, through ENS's `VerifiableFactory`.
2. Write the meta-address record there: `setData(node, "stealth-meta-address[<scheme>][<coinType>]", value)`.
3. Set the name's resolver in its ENSv2 registry to `StealthResolver`.
4. `setConfig(name, yourRecordsResolver, gatewayURLs)`; leave `gatewayURLs` empty to use a parent's.

Steps 1 and 2 can be one transaction (`initialize` takes setters); a smart account can batch all four.

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
| `StealthResolver` | 17,709 | 6,867 |

Measured by `test/Gas.t.sol`, stored in `snapshots/Gas.json`, checked in CI. Reads are what an
`eth_call` costs; verified-mode numbers use a mock verifier and exclude the scheme's curve arithmetic.

| Path | Gas |
|---|---|
| `resolve` wildcard name, address, `OffchainLookup` revert | 21,702 |
| `resolve` registered name, address, `OffchainLookup` revert | 15,595 |
| `resolveStealthCallback`, unverified | 6,729 + verifier |
| `resolveStealthCallback`, verified | 23,129 + verifier |
| `verifyStealthResolution` | 20,045 + verifier |
| `resolve` text, forwarded to a `PermissionedResolver` | 53,092 |
| `text` on the `PermissionedResolver` directly (reference) | 3,260 |
| `setConfig`, records resolver and one URL (transaction) | 139,526 |

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
`SEPOLIA_RPC_URL` is set:

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
