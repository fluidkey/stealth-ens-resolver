#!/usr/bin/env bash
# Proves that this repo's dependency setup compiles the canonical ENSv2 PublicResolverV2
# byte-for-byte as ensdomains/namechain's own setup does, with the compiler settings in foundry.toml.
# Run after `forge build`. Exits non-zero on any difference.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAMECHAIN="$ROOT/lib/namechain/contracts"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

(
  cd "$NAMECHAIN"
  FOUNDRY_SOLC_VERSION=0.8.25 \
  FOUNDRY_EVM_VERSION=cancun \
  FOUNDRY_OPTIMIZER_RUNS=1000 \
  FOUNDRY_BYTECODE_HASH=none \
  FOUNDRY_CBOR_METADATA=false \
  FOUNDRY_OUT="$TMP/out" \
  FOUNDRY_CACHE_PATH="$TMP/cache" \
    forge build --quiet src/resolver/PublicResolverV2.sol
)

python3 - "$TMP/out" "$ROOT/out" <<'PY'
import json, sys
canonical, ours = sys.argv[1], sys.argv[2]
rel = "PublicResolverV2.sol/PublicResolverV2.json"
a = json.load(open(f"{canonical}/{rel}"))
b = json.load(open(f"{ours}/{rel}"))
ok = all(a[k]["object"] == b[k]["object"] for k in ("bytecode", "deployedBytecode"))
size = len(b["deployedBytecode"]["object"]) // 2 - 1
print(f"PublicResolverV2: identical={ok}, runtime size={size} bytes")
sys.exit(0 if ok else 1)
PY
