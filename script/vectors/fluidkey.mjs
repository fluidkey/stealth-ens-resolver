// Generates test/utils/FluidkeyVectors.sol: FK1 derivations computed by Fluidkey's
// stealth-account-kit (generateEphemeralPrivateKey, generateStealthAddresses,
// predictStealthSafeAddressWithBytecode), for each parity of the spending key and the shared
// secret point and for three Safe setups: auto-earn off, the production auto-earn v1.1 configHash
// and another configHash. The auto-earn setup data is built from the template and checked against
// the v1.1 bytes the kit publishes (initdata/stealth-account-initdata.md); every owner key is
// rederived from the curve operations.
//
//   npm install --prefix <dir> --ignore-scripts @fluidkey/stealth-account-kit@1.1.1
//   node script/vectors/fluidkey.mjs <dir> > test/utils/FluidkeyVectors.sol && forge fmt
//
// Deterministic: keys are hashes of fixed labels, so the output only changes with the kit.

import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";

const dir = process.argv[2];
if (!dir) throw new Error("usage: node script/vectors/fluidkey.mjs <dir with the kit installed>");
const require = createRequire(join(dir, "package.json"));
const kitPath = require.resolve("@fluidkey/stealth-account-kit");
const kit = require("@fluidkey/stealth-account-kit");
const secp = require("@noble/secp256k1");
const { keccak256, toHex, encodePacked, encodeFunctionData, encodeAbiParameters, getAddress } =
  require("viem");
const version = (p) =>
  JSON.parse(readFileSync(join(dir, "node_modules", p, "package.json"))).version;

const assert = (ok, msg) => {
  if (!ok) throw new Error(msg);
};
const n = secp.CURVE.n;
const key = (label, i) =>
  toHex((BigInt(keccak256(toHex(`fluidkey-vector-${label}-${i}`))) % (n - 1n)) + 1n, { size: 32 });
const hex = (b) => Buffer.from(b).toString("hex");

const MULTI_SEND = "0xA238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761";
const MODULE_SETUP = "0x2dd68b007B46fBe91B9A7c3EDa5A7a1063cB5b47";
const EARN_MODULE = "0x3BDb857AFe9b51d8916D80240d2ADe40D4d3f2f9";

// The kit's published v1.1 setup data and its configHash (the last onInstall word).
const initdataDoc = readFileSync(join(kitPath, "../../initdata/stealth-account-initdata.md"), "utf8");
const published = [...initdataDoc.matchAll(/\/\/ data\n(0x[0-9a-f]+)/g)].map((m) => m[1]);
const PROD_SETUP_DATA = published[published.length - 1];
const PROD_CONFIG_HASH = BigInt(`0x${PROD_SETUP_DATA.slice(-92, -28)}`);

const abi = (name, inputs) => [{ type: "function", name, inputs, outputs: [] }];
const setupData = (configHash) => {
  const enable = encodeFunctionData({
    abi: abi("enableModules", [{ type: "address[]" }]),
    args: [[EARN_MODULE]],
  });
  const install = encodeFunctionData({
    abi: abi("onInstall", [{ type: "bytes" }]),
    args: [encodeAbiParameters([{ type: "uint256" }], [configHash])],
  });
  const len = (h) => BigInt((h.length - 2) / 2);
  const txs = encodePacked(
    ["uint8", "address", "uint256", "uint256", "bytes", "uint8", "address", "uint256", "uint256", "bytes"],
    [1, MODULE_SETUP, 0n, len(enable), enable, 0, EARN_MODULE, 0n, len(install), install],
  );
  return encodeFunctionData({ abi: abi("multiSend", [{ type: "bytes" }]), args: [txs] });
};
assert(setupData(PROD_CONFIG_HASH) === PROD_SETUP_DATA, "template differs from the kit's v1.1 setup data");

const safeProxyBytecode = readFileSync(join(kitPath, "../example/example.js"), "utf8").match(
  /0x608060405234801561001057600080fd5b50604051[0-9a-f]+/,
)[0];
const configs = [0n, PROD_CONFIG_HASH, BigInt(keccak256(toHex("fluidkey-vector-config")))];
const viewingNode = kit.extractViewingPrivateKeyNode(key("viewing", 0), 0);

const vectors = new Array(12);
for (let i = 0, found = 0; found < 12; ++i) {
  const spend = secp.getPublicKey(key("spend", i).slice(2), true);
  const { ephemeralPrivateKey: e } = kit.generateEphemeralPrivateKey({
    viewingPrivateKeyNode: viewingNode,
    nonce: BigInt(i),
    chainId: 0,
  });
  const shared = secp.getSharedSecret(e.slice(2), hex(spend), false); // 0x04 || x || y
  const slot = (i % 3) * 4 + (spend[0] - 2) * 2 + (shared[64] & 1);
  if (vectors[slot]) continue;
  const configHash = configs[i % 3];

  const { stealthAddresses } = kit.generateStealthAddresses({
    spendingPublicKeys: [`0x${hex(spend)}`],
    ephemeralPrivateKey: e,
  });
  const owner = getAddress(stealthAddresses[0]);
  // Rederived: owner = address(keccak256(S.x || S.y) · P_spend).
  const h = BigInt(keccak256(shared.slice(1)));
  const point = secp.Point.fromHex(hex(spend)).multiply(h);
  assert(getAddress(`0x${keccak256(point.toRawBytes(false).slice(1)).slice(-40)}`) === owner, "owner differs");

  const { stealthSafeAddress } = kit.predictStealthSafeAddressWithBytecode({
    safeProxyBytecode,
    threshold: 1,
    stealthAddresses: [owner],
    useDefaultAddress: true,
    safeVersion: "1.3.0",
    initializerExtraFields: configHash === 0n ? undefined : { to: MULTI_SEND, data: setupData(configHash) },
  });

  vectors[slot] = {
    meta: `${hex(spend)}${configHash.toString(16).padStart(64, "0")}`,
    vd: `${e.slice(2)}${hex(shared.slice(1))}`,
    owner,
    safe: getAddress(stealthSafeAddress),
  };
  ++found;
}

process.stdout.write(`// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

// Generated by script/vectors/fluidkey.mjs from @fluidkey/stealth-account-kit@${version("@fluidkey/stealth-account-kit")}
// (@noble/secp256k1@${version("@noble/secp256k1")}). Do not edit: regenerate, then \`forge fmt\`.

/// @dev FK1 derivations by Fluidkey's stealth-account-kit. Vector i has Safe setup i / 4 (auto-earn
///      off, the production auto-earn v1.1 configHash, another configHash), spending key parity
///      (i >> 1) & 1 and shared secret point parity i & 1.
library FluidkeyVectors {
    struct Vector {
        /// @dev Compressed spending key || configHash (65 bytes).
        bytes metaAddress;
        /// @dev Ephemeral private key || shared secret point x || y (96 bytes).
        bytes verificationData;
        /// @dev The stealth Safe's owner, from generateStealthAddresses.
        address owner;
        /// @dev The stealth Safe, from predictStealthSafeAddressWithBytecode.
        address stealthAddress;
    }

    /// @dev The configHash and Safe setup data of auto-earn v1.1, as the kit publishes them.
    uint256 internal constant PROD_CONFIG_HASH = 0x${PROD_CONFIG_HASH.toString(16).padStart(64, "0")};
    bytes internal constant PROD_SETUP_DATA = hex"${PROD_SETUP_DATA.slice(2)}";

    function all() internal pure returns (Vector[] memory v) {
        v = new Vector[](12);
${vectors.map((x, i) => `        v[${i}] = Vector(hex"${x.meta}", hex"${x.vd}", ${x.owner}, ${x.safe});`).join("\n")}
    }
}
`);
