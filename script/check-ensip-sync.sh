#!/usr/bin/env bash
# Checks that src/interfaces/IStealthResolver.sol contains the `interface IStealthResolver { ... }`
# block of the ENSIP draft verbatim.
#
#   ./script/check-ensip-sync.sh                     # against the pinned ENSIP commit on GitHub
#   ENSIP_REF=<commit> ./script/check-ensip-sync.sh  # against another commit
#   ENSIP_FILE=path/to/x.md ./script/check-ensip-sync.sh  # against a local draft
#
# Exits non-zero and prints a diff on any difference.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENSIP_REF="${ENSIP_REF:-955e104670b5f019cd3b8a5f4a208142818d68bc}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if [[ -n "${ENSIP_FILE:-}" ]]; then
  cp "$ENSIP_FILE" "$TMP/ensip.md"
  SOURCE="$ENSIP_FILE"
else
  SOURCE="https://raw.githubusercontent.com/ensdomains/ensips/$ENSIP_REF/ensips/x.md"
  curl -sfL "$SOURCE" -o "$TMP/ensip.md"
fi

python3 - "$TMP/ensip.md" "$ROOT/src/interfaces/IStealthResolver.sol" "$SOURCE" <<'PY'
import difflib, re, sys
spec_path, sol_path, source = sys.argv[1:]
pattern = re.compile(r"^interface IStealthResolver \{\n.*?^\}\n", re.S | re.M)
def block(path):
    m = pattern.search(open(path).read())
    if not m:
        sys.exit(f"no IStealthResolver block found in {path}")
    return m.group(0)
spec, sol = block(spec_path), block(sol_path)
if spec == sol:
    print(f"IStealthResolver matches the ENSIP ({source})")
    sys.exit(0)
sys.stdout.writelines(difflib.unified_diff(
    spec.splitlines(keepends=True), sol.splitlines(keepends=True), "ENSIP", "IStealthResolver.sol"))
sys.exit(1)
PY
