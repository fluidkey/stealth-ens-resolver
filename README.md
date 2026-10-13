# stealth-resolver

Reference contracts for the ENSIP on stealth address resolution
([ensdomains/ensips#88](https://github.com/ensdomains/ensips/pull/88)): an ENS resolver that publishes
ERC-5564 stealth meta-addresses and verifies gateway-provided stealth addresses onchain during
ERC-3668 resolution.

The ENSIP is the specification. Where this code and the ENSIP disagree, the ENSIP wins and the
disagreement is raised against the ENSIP.

> Status: work in progress, not audited, not deployed.

## Design principle

The resolver is derived from the ENSv2 canonical `PublicResolverV2` and changes it only where the
ENSIP requires. Every departure is listed in "Departures from PublicResolverV2" below as the code
lands.

## Build and test

Requires [Foundry](https://book.getfoundry.sh/).

```bash
git clone --recurse-submodules <repo>
forge build
forge test
./script/verify-canonical-build.sh
./script/check-ensip-sync.sh
```

`check-ensip-sync.sh` checks that `src/interfaces/IStealthResolver.sol` contains the ENSIP's
Section 5 interface verbatim, against the pinned ENSIP commit (override with `ENSIP_REF`, or point
`ENSIP_FILE` at a local draft). Both scripts run in CI.

## Dependencies

| Dependency | Pin | Notes |
|---|---|---|
| [ensdomains/namechain](https://github.com/ensdomains/namechain) | `48b3e2d` (2026-07-03, post-audit) | ENSv2 contracts; source of `PublicResolverV2` |
| [ensdomains/ens-contracts](https://github.com/ensdomains/ens-contracts) | `3b1cc22`, the commit namechain pins | resolver profile mixins, CCIP-Read helpers |
| [OpenZeppelin/openzeppelin-contracts](https://github.com/OpenZeppelin/openzeppelin-contracts) | `e4f7021` (v5) and `54b3f14` (v4), as namechain pins | |
| [foundry-rs/forge-std](https://github.com/foundry-rs/forge-std) | latest at setup | tests only |

ens-contracts and OpenZeppelin are used from namechain's own submodules rather than installed a
second time, so their versions cannot drift from what ENSv2 is built and audited against.

Compiler settings match ENSv2's production build: solc 0.8.25, EVM `cancun`, optimizer at 1000
runs. `script/verify-canonical-build.sh` builds `PublicResolverV2` inside namechain and in this repo
and checks the bytecode is identical, so any drift in remappings or settings fails CI.

`remappings.txt` mirrors namechain's. Two of namechain's lines (OpenZeppelin v4 for ens-contracts,
and an `mcopy` variant of ens-contracts' `LibMem`) do not take effect under Foundry in either repo;
`PublicResolverV2` therefore compiles against OpenZeppelin v5 `ERC165` and ens-contracts' own
`LibMem`, identically here and in namechain.

## License

[MIT](LICENSE)
