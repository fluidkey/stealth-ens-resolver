#!/usr/bin/env bash
# Enforces the versioning rule: the bytecode of a deployed contract changes only with a version bump.
# `bytecode-hashes.json` records, for the version in `VERSION`, keccak256 of each deployed contract's
# creation code (its CREATE2 init code before constructor arguments) and runtime code.
#
#   ./script/check-bytecode.sh           check: fails on any difference with the recorded hashes
#   ./script/check-bytecode.sh --update  record the current hashes under the current VERSION
#
# `--update` refuses to record changed bytecode under the same version, or under a patch bump:
# a patch release never changes deployed bytecode. Run after `forge build`.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACTS=(StealthResolver Scheme1Verifier FluidkeySigners FluidkeyVerifier ERC6538Bridge)

current="{"
for c in "${CONTRACTS[@]}"; do
  art="$ROOT/out/$c.sol/$c.json"
  [[ -f "$art" ]] || { echo "missing $art: run forge build first" >&2; exit 1; }
  read -r init runtime < <(python3 -c '
import json, sys
a = json.load(open(sys.argv[1]))
print(a["bytecode"]["object"], a["deployedBytecode"]["object"])' "$art")
  current+="\"$c\":{\"initcode\":\"$(cast keccak "$init")\",\"runtime\":\"$(cast keccak "$runtime")\"},"
done
current="${current%,}}"

python3 - "$ROOT" "$current" "${1:-}" <<'PY'
import json, os, re, sys
root, current, mode = sys.argv[1], json.loads(sys.argv[2]), sys.argv[3]
version = open(f"{root}/VERSION").read().strip()
if not re.fullmatch(r"\d+\.\d+\.\d+", version):
    sys.exit(f"VERSION {version!r} is not MAJOR.MINOR.PATCH")
if f"## [{version}]" not in open(f"{root}/CHANGELOG.md").read():
    sys.exit(f"CHANGELOG.md has no '## [{version}]' entry")
path = f"{root}/bytecode-hashes.json"
if not os.path.exists(path) and mode != "--update":
    sys.exit("bytecode-hashes.json is missing: run ./script/check-bytecode.sh --update")
recorded = json.load(open(path)) if os.path.exists(path) else {"version": "0.0.0", "contracts": {}}
changed = sorted(c for c in current if recorded["contracts"].get(c) != current[c])
changed += sorted(c for c in recorded["contracts"] if c not in current)

if mode == "--update":
    if changed:
        old = [int(x) for x in recorded["version"].split(".")]
        new = [int(x) for x in version.split(".")]
        if new[:2] <= old[:2]:
            sys.exit(f"bytecode of {', '.join(changed)} changed: bump VERSION past "
                     f"{recorded['version']} by MAJOR or MINOR first (a patch never changes bytecode)")
    json.dump({"version": version, "contracts": current}, open(path, "w"), indent=2)
    open(path, "a").write("\n")
    print(f"recorded {version}; bytecode changed: {', '.join(changed) or 'none'}")
    sys.exit(0)

if changed:
    sys.exit(f"bytecode of {', '.join(changed)} differs from version {recorded['version']}: "
             "bump VERSION (MAJOR or MINOR), add a CHANGELOG.md entry, run "
             "./script/check-bytecode.sh --update")
if recorded["version"] != version:
    sys.exit(f"VERSION is {version} but bytecode-hashes.json records {recorded['version']}: "
             "run ./script/check-bytecode.sh --update")
print(f"bytecode matches version {version}")
PY
