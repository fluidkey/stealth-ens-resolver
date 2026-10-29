"""Generates test/utils/CloakedVectors.sol: the known answers in Cloaked's own clkd-stealth test
suite, with the private keys the verifier tests need to rebuild each derivation.

  - genStealthAddress.test.ts: two spending keys and one ephemeral key, with the expected
    addresses. Used as published.
  - e2e/fullFlow.test.ts: for a test wallet and PIN, the stealth address and key at nonces 0-10
    under the Cloaked message and under the Fluidkey one. The test publishes the results, not the
    keys in between, so this script recomputes them as clkd-stealth does (EIP-191 signature,
    keccak256 of r and s, BIP-32 hardened derivation m/5564'/0' then m/0'/0'/0'/nonce'). The
    expected addresses and keys are Cloaked's, so a mistake here fails the Solidity test rather
    than passing unnoticed. The BIP-32 code is first checked against deriveChildViewingNode.test.ts.

  git clone https://github.com/cloakedxyz/clkd-stealth <dir>
  git -C <dir> checkout 9eb359efdd4ea31f5504bf81e57dcfe6f966dc14
  python3 script/vectors/cloaked.py <dir> > test/utils/CloakedVectors.sol && forge fmt

Needs Foundry's `cast` (signing and keccak256); Python standard library otherwise.
"""

import hashlib
import hmac
import re
import subprocess
import sys

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
HARDENED = 0x80000000

CLOAKED_MESSAGE = """Sign this message to generate your Cloaked private payment keys.

WARNING: Only sign this message within a trusted website or platform to avoid loss of funds.

Secret: {secret}"""
FLUIDKEY_MESSAGE = """Sign this message to generate your Fluidkey private payment keys.

WARNING: Only sign this message within a trusted website or platform to avoid loss of funds.

Secret: {secret}"""


def cast(*args):
    return subprocess.run(["cast", *args], check=True, capture_output=True, text=True).stdout.strip()


def keccak(data: bytes) -> bytes:
    return bytes.fromhex(cast("keccak", "0x" + data.hex())[2:])


def ckd_hardened(key: int, chain: bytes, index: int):
    """BIP-32 private child key derivation, hardened."""
    i = hmac.new(chain, b"\x00" + key.to_bytes(32, "big") + (index + HARDENED).to_bytes(4, "big"), hashlib.sha512).digest()
    il = int.from_bytes(i[:32], "big")
    child = (il + key) % N
    assert il < N and child != 0, "invalid child key"
    return child, i[32:]


def derive(seed: bytes, path):
    i = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    key, chain = int.from_bytes(i[:32], "big"), i[32:]
    for index in path:
        key, chain = ckd_hardened(key, chain, index)
    return key, chain


def ephemeral_key(view_node, nonce: int, chain_id: int = 0) -> int:
    """deriveDeterministicEphemeralKey: m/chainId'/0'/parentNonce'/nonce' from the child node."""
    parent, nonce = (nonce >> 28, nonce & 0xFFFFFFF) if nonce > 0xFFFFFFF else (0, nonce)
    key, chain = view_node
    for index in (chain_id, 0, parent, nonce):
        key, chain = ckd_hardened(key, chain, index)
    return key


def read(root, path):
    with open(f"{root}/{path}") as f:
        return f.read()


def hexes(text, pattern):
    return re.findall(pattern + r"\s*'(0x[0-9a-fA-F]+)'", text)


root = sys.argv[1] if len(sys.argv) > 1 else sys.exit("usage: cloaked.py <clkd-stealth checkout>")
commit = subprocess.run(["git", "-C", root, "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
assert CLOAKED_MESSAGE.split("{")[0] in read(root, "src/client/genCloakedMessage.ts"), "Cloaked message changed"

# The BIP-32 code against deriveChildViewingNode.test.ts.
kat = read(root, "test/deriveChildViewingNode.test.ts")
(p_view_kat,) = hexes(kat, r"const privateViewingKey =")[:1]
(chain_kat,) = hexes(kat, r"const expectedChainCode =")
(key_kat,) = hexes(kat, r"const expectedPrivateKey =")
key, chain = derive(bytes.fromhex(p_view_kat[2:]), (5564, 0))
assert (key, chain.hex()) == (int(key_kat, 16), chain_kat[2:]), "BIP-32 derivation differs from Cloaked's"

vectors = []  # (label, spend key, ephemeral key, stealth address, stealth key or 0)

# genStealthAddress.test.ts, first case.
gsa = read(root, "test/genStealthAddress.test.ts").split("  it(")[1]
spends = hexes(gsa, r"privateKeyToAccount\(")
(e,) = hexes(gsa, r"const p_derived =")
expected = re.findall(r"'(0x[0-9a-fA-F]{40})'", gsa)
assert len(spends) == len(expected) == 2
for i, (s, a) in enumerate(zip(spends, expected)):
    vectors.append((f"genStealthAddress {i}", int(s, 16), int(e, 16), a, 0))

# e2e/fullFlow.test.ts: the two cases with expected results.
flow = read(root, "test/e2e/fullFlow.test.ts")
(user_key,) = hexes(flow, r"const userPrivateKey =")
(pin,) = re.findall(r"const userPin = '(\d{4})'", flow)
address = cast("wallet", "address", "--private-key", user_key)
blocks = re.findall(r"const expectedResults = \[(.*?)\n    \];", flow, re.S)
assert len(blocks) == 2
for name, template, block in (("Cloaked", CLOAKED_MESSAGE, blocks[0]), ("Fluidkey", FLUIDKEY_MESSAGE, blocks[1])):
    secret = keccak((address + pin).encode()).hex()
    signature = bytes.fromhex(cast("wallet", "sign", "--private-key", user_key, template.format(secret=secret))[2:])
    p_spend = int.from_bytes(keccak(signature[:32]), "big")  # genKeys: keccak256 of each half
    p_view = keccak(signature[32:64])
    view_node = derive(p_view, (5564, 0))
    addresses = hexes(block, r"stealthAddress:")
    keys = hexes(block, r"stealthPrivateKey:")
    assert len(addresses) == len(keys) == 11
    for nonce, (a, k) in enumerate(zip(addresses, keys)):
        vectors.append((f"fullFlow {name} message, nonce {nonce}", p_spend, ephemeral_key(view_node, nonce), a, int(k, 16)))

lines = "\n".join(
    f'        v[{i}] = Vector("{label}", 0x{s:064x}, 0x{e:064x}, {a}, 0x{k:064x});'
    for i, (label, s, e, a, k) in enumerate(vectors)
)
print(f"""// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

// Generated by script/vectors/cloaked.py from cloakedxyz/clkd-stealth@{commit[:7]}.
// Do not edit: regenerate, then `forge fmt`.

/// @dev The known answers in clkd-stealth's own tests: the stealth address (and, from the full flow,
///      its key) are Cloaked's; the spending and ephemeral keys are given by genStealthAddress.test.ts
///      or recomputed from fullFlow.test.ts's wallet and PIN.
library CloakedVectors {{
    struct Vector {{
        string label;
        uint256 spendKey;
        uint256 ephemeralKey;
        /// @dev As Cloaked's test expects it.
        address stealthAddress;
        /// @dev As Cloaked's test expects it, or 0 where the test gives none.
        uint256 stealthKey;
    }}

    function all() internal pure returns (Vector[] memory v) {{
        v = new Vector[]({len(vectors)});
{lines}
    }}
}}""")
