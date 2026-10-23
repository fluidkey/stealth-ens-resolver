# Changelog

Versions follow [Semantic Versioning](https://semver.org/) as described under
[Versions](README.md#versions): a MAJOR or MINOR release changes the bytecode of at least one
deployed contract, which means a new deployment at a new address; a PATCH release never does.
Each release lists the contracts whose bytecode changed.

## [0.1.0] - 2026-10-23

First tagged version. Not audited, not deployed.

### Contracts

- `StealthResolver`: ENSIP-30 resolver for ENSv2, one deployment per scheme.
- `Scheme1Verifier`: ERC-5564 scheme 1.
- `FluidkeyVerifier` and `FluidkeySigners`: the Fluidkey stealth Safe scheme (FK1, ID 4606769).
- `ERC6538Bridge`: a name's meta-address in ERC-6538's shape.

Bytecode hashes are in `bytecode-hashes.json`. Built with Foundry v1.8.6 and solc 0.8.25 (cancun,
1,000 optimizer runs, no metadata hash), the settings of ENS's canonical ENSv2 contracts.

[0.1.0]: https://github.com/fluidkey/stealth-resolver/releases/tag/v0.1.0
