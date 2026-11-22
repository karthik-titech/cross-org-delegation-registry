// Frozen conformance rows N1 to N11 for the Node.js verifier of
// draft-rampalli-pedigree-01. Do not edit.
//
// Every input used here (case files, fixtures, keys, rebuilt tokens, curve
// points) is prepared in this file with node:crypto, node:fs and JSON. The
// modules under test are called only at the point where a row asserts.
// The helpers below (sorted-member serializer, curve arithmetic, token
// signing) are test-side only and are deliberately independent of the
// modules under test.
//
// All keys are TEST ONLY. Each Ed25519 seed is published in the case files
// and equals SHA-256("pedigree-01 test key " + decimal index).

import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { decodeB64url, B64Error } from "../lib/b64url.mjs";
import { parseIJSON, IJSONError } from "../lib/ijson.mjs";
import { canonicalize } from "../lib/jcs.mjs";
import { okpThumbprint } from "../lib/thumbprint.mjs";
import { checkPublicKey, verifyEd25519 } from "../lib/ed25519.mjs";
import { verify } from "../lib/verify.mjs";

console.log(
  `runtime: node ${process.version} openssl ${process.versions.openssl}`,
);

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..", "..", "..");
const VECTOR_DIR = path.join(ROOT, "vectors", "pedigree-01");
const FIXTURES_PATH = path.join(
  ROOT, "reference", "go", "pedigree", "testdata", "fixtures.json",
);
const CLI = path.join(ROOT, "reference", "node", "pedigree-verify.mjs");

// ---------------------------------------------------------------------------
// Test-side helpers (never the modules under test)
// ---------------------------------------------------------------------------

const sha256 = (b) => crypto.createHash("sha256").update(b).digest();
const toB64u = (b) => Buffer.from(b).toString("base64url");
const fromB64u = (s) => Buffer.from(s, "base64url");
const hex = (b) => Buffer.from(b).toString("hex");
const readJSON = (p) => JSON.parse(fs.readFileSync(p, "utf8"));

/**
 * Sorted-member serializer for the objects this file rebuilds. Those
 * objects hold only ASCII member names, strings, safe integers, booleans,
 * arrays and objects, for which JSON.stringify of each primitive plus a
 * code-unit sort of member names gives the canonical form. The helper is
 * checked against the published token bytes in loadBase().
 */
function sortedJSON(v) {
  if (Array.isArray(v)) return "[" + v.map(sortedJSON).join(",") + "]";
  if (v !== null && typeof v === "object") {
    const names = Object.keys(v).sort();
    return "{" +
      names.map((k) => JSON.stringify(k) + ":" + sortedJSON(v[k])).join(",") +
      "}";
  }
  return JSON.stringify(v);
}

/** Private key object from a 32-byte seed (RFC 8410 PKCS#8 wrapping). */
function privateFromSeed(seed) {
  const der = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    seed,
  ]);
  return crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

/** Test keys from the published seeds of a case file. */
function loadKeys(caseObj) {
  return caseObj.keys.map((k) => {
    assert.equal(k.label, "TEST ONLY");
    const seed = Buffer.from(k.seed_hex, "hex");
    assert.equal(
      hex(sha256(Buffer.from("pedigree-01 test key " + k.index, "utf8"))),
      k.seed_hex,
      "setup: seed equals the published derivation",
    );
    const priv = privateFromSeed(seed);
    const x = crypto.createPublicKey(priv).export({ format: "jwk" }).x;
    return { index: k.index, seed, priv, x, raw: fromB64u(x) };
  });
}

function signingInputOf(compact) {
  return compact.slice(0, compact.lastIndexOf("."));
}

function parseCompact(compact) {
  const [h, p] = compact.split(".");
  return {
    header: JSON.parse(fromB64u(h).toString("utf8")),
    payload: JSON.parse(fromB64u(p).toString("utf8")),
  };
}

function signCompact(header, payload, priv) {
  const input = toB64u(Buffer.from(sortedJSON(header), "utf8")) + "." +
    toB64u(Buffer.from(sortedJSON(payload), "utf8"));
  const sig = crypto.sign(null, Buffer.from(input, "ascii"), priv);
  return input + "." + toB64u(sig);
}

/** The valid-3-hop case, the fixtures and the test keys, with self checks. */
function loadBase() {
  const caseObj = readJSON(path.join(VECTOR_DIR, "valid-3-hop.json"));
  const fixtures = readJSON(FIXTURES_PATH);
  const keys = loadKeys(caseObj);
  const pres = caseObj.presentations[0];
  const byX = new Map(keys.map((k) => [k.x, k]));
  const holderX = toB64u(Buffer.from(caseObj.wpt[0].holder_key, "base64"));
  const holder = byX.get(holderX);
  assert.ok(holder, "setup: holder key is a published test key");
  // The helper serializer and signer reproduce the published bytes.
  for (const tok of [...pres.chain, pres.invocation]) {
    const [h, p] = tok.split(".");
    const parsed = parseCompact(tok);
    assert.equal(sortedJSON(parsed.header), fromB64u(h).toString("utf8"));
    assert.equal(sortedJSON(parsed.payload), fromB64u(p).toString("utf8"));
  }
  const t1 = parseCompact(pres.chain[1]);
  assert.equal(
    signCompact(t1.header, t1.payload, byX.get(t1.header.jwk.x).priv),
    pres.chain[1],
    "setup: re-signing the unchanged T_1 reproduces the published token",
  );
  return { caseObj, fixtures, keys, byX, holder, pres };
}

/** Trusted inputs for one presentation of a case (zero-based index). */
function trustedFor(caseObj, fixtures, index) {
  const wpt = caseObj.wpt.find((w) => w.presentation_index === index + 1);
  assert.ok(wpt, "setup: one WPT assumption per presentation");
  return { wpt, consent: caseObj.consent, policies: fixtures };
}

function freshReplay(available = true) {
  return { available, seen: new Set() };
}

/** Verifier configuration for a case. */
function configFor(caseObj, fixtures, replay, overrides = {}) {
  const ceilingBytes = Buffer.from(sortedJSON(fixtures.ceiling), "utf8");
  assert.equal(
    "sha256:" + hex(sha256(ceilingBytes)),
    fixtures.ceiling_ref,
    "setup: ceiling bytes match ceiling_ref",
  );
  return {
    trustAnchors: caseObj.trust_anchors,
    verifierIds: caseObj.verifier_ids,
    ceilings: { [fixtures.ceiling_ref]: new Uint8Array(ceilingBytes) },
    maxTokens: 8,
    maxBytes: 262144,
    maxInvocationLifetimeSeconds: 60,
    replay,
    ...overrides,
  };
}

function requestOf(pres) {
  return { chain: pres.chain, invocation: pres.invocation, args: pres.args };
}

/** Run verify() on a presentation of the base case with fresh replay state. */
function runBase(base, presentation, overrides = {}) {
  const result = verify(
    presentation,
    trustedFor(base.caseObj, base.fixtures, 0),
    configFor(base.caseObj, base.fixtures, freshReplay(), overrides),
    new Date(base.caseObj.at),
  );
  return result === null || typeof result !== "object"
    ? result
    : result.outcome;
}

/**
 * Rebuild the valid-3-hop presentation after a change to token `from`.
 * mutate(tokens) edits the parsed tokens in place. Token `from` and every
 * descendant is re-signed by its signer (the key in its header jwk), each
 * descendant gets a new par_hash, the invocation gets a new tok and is
 * re-signed with the holder key.
 */
function rebuild(base, from, mutate) {
  assert.ok(from >= 1, "setup: rebuild starts at a non-root token");
  const chain = base.pres.chain.slice();
  const tokens = chain.map(parseCompact);
  mutate(tokens);
  for (let i = from; i < tokens.length; i++) {
    const { header, payload } = tokens[i];
    if (i > from) {
      payload.par_hash = toB64u(sha256(signingInputOf(chain[i - 1])));
    }
    const signer = base.byX.get(header.jwk.x);
    assert.ok(signer, "setup: signer is a published test key");
    chain[i] = signCompact(header, payload, signer.priv);
  }
  const inv = parseCompact(base.pres.invocation);
  inv.payload.tok = toB64u(sha256(signingInputOf(chain[chain.length - 1])));
  const invocation = signCompact(inv.header, inv.payload, base.holder.priv);
  return { chain, invocation, args: base.pres.args };
}

// --- edwards25519 arithmetic, test side only (RFC 8032 Section 5.1) --------

const P = 2n ** 255n - 19n;
const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const fe = (a) => ((a % P) + P) % P;
function fpow(b, e) {
  let r = 1n;
  b = fe(b);
  while (e > 0n) {
    if (e & 1n) r = (r * b) % P;
    b = (b * b) % P;
    e >>= 1n;
  }
  return r;
}
const finv = (a) => fpow(a, P - 2n);
const D = fe(-121665n * finv(121666n));
const SQRT_M1 = fpow(2n, (P - 1n) / 4n);
const IDENTITY = { x: 0n, y: 1n };

/** x for a given y and sign bit, or null when no point exists. */
function recoverX(y, sign) {
  const x2 = fe((y * y - 1n) * finv(D * y * y + 1n));
  if (x2 === 0n) return sign ? null : 0n;
  let x = fpow(x2, (P + 3n) / 8n);
  if (fe(x * x) !== x2) x = fe(x * SQRT_M1);
  if (fe(x * x) !== x2) return null;
  if (Number(x & 1n) !== sign) x = P - x;
  return x;
}
function padd(a, b) {
  const t = fe(D * a.x * b.x * a.y * b.y);
  return {
    x: fe((a.x * b.y + b.x * a.y) * finv(1n + t)),
    y: fe((a.y * b.y + a.x * b.x) * finv(1n - t)),
  };
}
function pmul(k, pt) {
  let r = IDENTITY;
  let q = pt;
  while (k > 0n) {
    if (k & 1n) r = padd(r, q);
    q = padd(q, q);
    k >>= 1n;
  }
  return r;
}
const isIdentity = (pt) => pt.x === 0n && pt.y === 1n;
function le32(n) {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}
function encodePoint(pt) {
  const out = le32(pt.y);
  out[31] |= Number(pt.x & 1n) << 7;
  return out;
}

/** Smallest y >= 2 that is canonical and has no curve point. */
function undecodableY() {
  for (let y = 2n; ; y++) {
    if (recoverX(y, 0) === null && recoverX(y, 1) === null) return y;
  }
}

/** A point of order exactly 8, found by clearing the prime-order part. */
function orderEightPoint() {
  for (let y = 2n; ; y++) {
    const x = recoverX(y, 0);
    if (x === null) continue;
    const q = pmul(L, { x, y });
    const q4 = pmul(4n, q);
    if (isIdentity(q4)) continue;
    assert.ok(isIdentity(padd(q4, q4)), "setup: 8A is the identity");
    return q;
  }
}

// --- CLI helpers ------------------------------------------------------------

function runCli(args) {
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8" });
  return { status: r.status, stdout: r.stdout || "", stderr: r.stderr || "" };
}
function resultLines(stdout) {
  return stdout.split("\n").filter((l) => l.trim() !== "")
    .map((l) => JSON.parse(l));
}
function makeTemp(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pedigree-node-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}
function copyVectors(t) {
  const dir = makeTemp(t);
  for (const name of fs.readdirSync(VECTOR_DIR)) {
    fs.copyFileSync(path.join(VECTOR_DIR, name), path.join(dir, name));
  }
  return dir;
}
function expectedLine(row, status = "PASS") {
  return {
    id: row.id,
    presentation: row.presentation,
    expected: row.outcome,
    got: row.outcome,
    trusted_inputs_used: row.trusted_inputs_used,
    status,
  };
}

// ---------------------------------------------------------------------------
// N1: JCS output
// ---------------------------------------------------------------------------

test("N1", () => {
  const numbers = [
    [0, "0"],
    [-0, "0"],
    [1e-7, "1e-7"],
    [0.000001, "0.000001"],
    [1e21, "1e+21"],
    [5e-324, "5e-324"],
    [9007199254740991, "9007199254740991"],
  ];
  for (const [value, want] of numbers) {
    assert.equal(canonicalize(value), want,
      `number ${Object.is(value, -0) ? "-0" : String(value)}`);
  }

  // Strings with escapes: quote, backslash, solidus, the five short
  // escapes, two other controls, DEL, and three non-ASCII characters.
  const s = "\"\\/\b\f\n\r\t\u0000\u001f\u007fé€\u{1F600}";
  const wantS = String.raw`"\"\\/\b\f\n\r\t\u0000\u001f` +
    "\u007fé€\u{1F600}" + "\"";
  assert.equal(canonicalize(s), wantS, "string with escapes");
  assert.equal(canonicalize(""), "\"\"", "empty string");

  // Member order is by UTF-16 code unit: "10" before "2".
  const obj = { b: 1, "10": 2, a: 3, "\u{1F600}": 4, "2": 5 };
  assert.equal(
    canonicalize(obj),
    "{\"10\":2,\"2\":5,\"a\":3,\"b\":1,\"\u{1F600}\":4}",
    "object member order",
  );

  // Nested: U+1F600 (code units D83D DE00) sorts before U+FFFD.
  const nested = {
    z: { "�": 1, "\u{1F600}": 2, "é": [true, null, { k: "v" }] },
    a: [],
  };
  assert.equal(
    canonicalize(nested),
    "{\"a\":[],\"z\":{\"é\":[true,null,{\"k\":\"v\"}]," +
      "\"\u{1F600}\":2,\"�\":1}}",
    "nested object",
  );
});

// ---------------------------------------------------------------------------
// N2: I-JSON parsing
// ---------------------------------------------------------------------------

test("N2", () => {
  /** The IJSONError reason for an input, or a description of what happened. */
  function reasonOf(bytes) {
    let value;
    try {
      value = parseIJSON(bytes);
    } catch (e) {
      if (e instanceof IJSONError) return e.reason;
      return "threw " + (e && e.name) + ", not IJSONError";
    }
    return "no error, returned " + JSON.stringify(value);
  }
  const ascii = (str) => new Uint8Array(Buffer.from(str, "latin1"));

  assert.equal(reasonOf(ascii(String.raw`{"a":1,"a":2}`)), "duplicate",
    "duplicate member");
  assert.equal(reasonOf(ascii(String.raw`{"a":1,"a":2}`)), "duplicate",
    "escape-equivalent duplicate member");
  assert.equal(reasonOf(ascii(String.raw`{"s":"\ud800"}`)), "surrogate",
    "lone surrogate escape");
  assert.equal(
    reasonOf(Uint8Array.of(0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d)),
    "utf8",
    "invalid UTF-8 byte inside a string",
  );
  assert.equal(reasonOf(ascii(String.raw`{"a":1}{"b":2}`)), "trailing",
    "trailing content");
  assert.equal(reasonOf(ascii(String.raw`{"n":9007199254740992}`)),
    "int_range", "integer 2^53");
  assert.equal(reasonOf(ascii(String.raw`{"n":9.007199254740992e15}`)),
    "int_range", "integer 2^53 in exponent spelling");

  const valid = Buffer.from(
    "{\"a\":[1,2.5,\"xé\"],\"b\":{\"c\":null,\"d\":true}," +
      "\"n\":9007199254740991}",
    "utf8",
  );
  assert.deepStrictEqual(
    parseIJSON(new Uint8Array(valid)),
    { a: [1, 2.5, "xé"], b: { c: null, d: true }, n: 9007199254740991 },
    "valid canonical object",
  );
});

// ---------------------------------------------------------------------------
// N3: strict base64url
// ---------------------------------------------------------------------------

test("N3", () => {
  // Bytes fb ff 00 fb ff are the bit groups
  // 111110 111111 111100 000000 111110 111111 1111(00): "-_8A-_8".
  const want = Uint8Array.of(0xfb, 0xff, 0x00, 0xfb, 0xff);
  const good = "-_8A-_8";
  const got = decodeB64url(good);
  assert.ok(got instanceof Uint8Array,
    `valid string returns a Uint8Array, got ${typeof got} ${String(got)}`);
  assert.equal(hex(got), hex(want), "valid string gives exact bytes");

  const refused = [
    ["padding", "-_8A-_8="],
    ["plus in place of minus", "+_8A-_8"],
    ["embedded whitespace", "-_8A -_8"],
    // Last group 111101: a permissive decoder drops the low bits and
    // returns the same five bytes.
    ["non-zero trailing bits", "-_8A-_9"],
  ];
  for (const [label, input] of refused) {
    assert.throws(() => decodeB64url(input), B64Error, label);
  }
});

// ---------------------------------------------------------------------------
// N4: RFC 7638 thumbprint of key 1
// ---------------------------------------------------------------------------

test("N4", () => {
  // Both literals were derived with the openssl command line from the
  // published seed of key 1 and are frozen here.
  assert.equal(
    okpThumbprint("objtVgOoVyOQvCjA245nWeTayaEKkNx6qU_i8Lm_THA"),
    "cf8YxbFdYDztN3LloLpmXSxxJrk50bL4zszPsKBaWnw",
  );
});

// ---------------------------------------------------------------------------
// N5: Ed25519 pre-checks
// ---------------------------------------------------------------------------

test("N5", (t) => {
  const base = loadBase();
  const key1 = base.keys.find((k) => k.index === 1);
  const msg = new Uint8Array(
    Buffer.from("pedigree-01 frozen conformance message", "utf8"),
  );
  const validSig = new Uint8Array(crypto.sign(null, msg, key1.priv));
  assert.ok(
    crypto.verify(null, msg, crypto.createPublicKey(key1.priv), validSig),
    "setup: the control signature verifies with node:crypto",
  );
  const validR = validSig.slice(0, 32);
  const join = (r, sVal) => {
    const out = new Uint8Array(64);
    out.set(r, 0);
    out.set(le32(sVal), 32);
    return out;
  };

  const identityKey = encodePoint(IDENTITY);
  const neutralSig = join(identityKey, 0n);
  // Non-canonical y = p + k for the smallest k >= 2 whose reduced value
  // is a curve point: not a small-order encoding, so only the range check
  // on y can refuse it before the backend.
  let k = 2n;
  while (recoverX(k, 0) === null) k++;
  assert.ok(k < 19n, "setup: p + k fits in 255 bits");
  assert.ok(!isIdentity(pmul(8n, { x: recoverX(k, 0), y: k })),
    "setup: the reduced point is not small order");
  const nonCanonicalKey = le32(P + k);
  const badY = undecodableY();
  const undecodableKey = le32(badY);
  const undecodableRSig = join(le32(badY), 1n);
  const sEqualsL = join(validR, L);
  const sBelowL = join(validR, L - 1n);
  const order8 = orderEightPoint();
  const order8Key = encodePoint(order8);
  assert.ok(isIdentity(pmul(8n, order8)), "setup: 8A is the identity");
  assert.ok(!isIdentity(pmul(4n, order8)), "setup: 4A is not the identity");
  assert.ok(order8.y < P && recoverX(order8.y, Number(order8.x & 1n)) !== null,
    "setup: the order-8 encoding is canonical and decodes");

  // Backend observation, recorded and not asserted.
  let observed;
  try {
    const ko = crypto.createPublicKey({
      key: { kty: "OKP", crv: "Ed25519", x: toB64u(identityKey) },
      format: "jwk",
    });
    observed = String(crypto.verify(null, msg, ko, neutralSig));
  } catch (e) {
    observed = "threw " + e.message;
  }
  t.diagnostic(
    `derived inputs: non-canonical key ${hex(nonCanonicalKey)} (y = p + ${k}), ` +
      `undecodable y = ${badY}, order-8 key ${hex(order8Key)}`,
  );
  t.diagnostic(
    "observation (not asserted): plain crypto.verify on the identity key " +
      "with the neutral-element signature gives " + observed,
  );

  // 1. Identity-point key with the neutral-element signature.
  const r1 = verifyEd25519(identityKey, msg, neutralSig);
  assert.equal(r1.ok, false, "identity key with neutral signature refused");
  assert.equal(checkPublicKey(identityKey).ok, false, "identity key refused");

  // 2. Non-canonical y (y >= p).
  const r2 = verifyEd25519(nonCanonicalKey, msg, validSig);
  assert.equal(r2.ok, false, "non-canonical y refused");
  assert.equal(r2.backendCalled, false, "non-canonical y: backend not called");
  assert.equal(checkPublicKey(nonCanonicalKey).ok, false,
    "non-canonical y refused by checkPublicKey");

  // 3. Canonical y with no curve point.
  const r3 = verifyEd25519(undecodableKey, msg, validSig);
  assert.equal(r3.ok, false, "undecodable y refused");
  assert.equal(r3.backendCalled, false, "undecodable y: backend not called");
  assert.equal(checkPublicKey(undecodableKey).ok, false,
    "undecodable y refused by checkPublicKey");

  // 4. Signature whose R does not decode.
  const r4 = verifyEd25519(key1.raw, msg, undecodableRSig);
  assert.equal(r4.ok, false, "undecodable R refused");
  assert.equal(r4.backendCalled, false, "undecodable R: backend not called");

  // 5. S = L.
  const r5 = verifyEd25519(key1.raw, msg, sEqualsL);
  assert.equal(r5.ok, false, "S = L refused");

  // Order-8 key with a structurally valid 64-byte signature.
  const r8 = verifyEd25519(order8Key, msg, validSig);
  assert.equal(r8.ok, false, "order-8 key refused");
  assert.equal(r8.backendCalled, false, "order-8 key: backend not called");
  assert.equal(checkPublicKey(order8Key).ok, false,
    "order-8 key refused by checkPublicKey");

  // 6. S = L - 1: in range, refused because the signature is invalid.
  const r6 = verifyEd25519(key1.raw, msg, sBelowL);
  assert.equal(r6.ok, false, "S = L - 1 with an invalid signature refused");
  assert.notEqual(r5.reason, r6.reason,
    "S = L reason differs from S = L - 1 reason");

  // 7. Valid signature from key 1.
  assert.equal(checkPublicKey(key1.raw).ok, true, "key 1 accepted");
  const r7 = verifyEd25519(key1.raw, msg, validSig);
  assert.equal(r7.ok, true, "valid signature accepted");
});

// ---------------------------------------------------------------------------
// N6: all 28 presentations
// ---------------------------------------------------------------------------

test("N6", () => {
  const expected = readJSON(path.join(VECTOR_DIR, "expected.json")).cases;
  const fixtures = readJSON(FIXTURES_PATH);
  assert.equal(expected.length, 28, "setup: 28 expected rows");

  const cases = new Map();
  const want = [];
  const got = [];
  for (const row of expected) {
    if (!cases.has(row.id)) {
      const caseObj = readJSON(path.join(VECTOR_DIR, row.id + ".json"));
      cases.set(row.id, {
        caseObj,
        replay: freshReplay(caseObj.replay_available),
      });
    }
    const { caseObj, replay } = cases.get(row.id);
    const index = row.presentation - 1;
    const result = verify(
      requestOf(caseObj.presentations[index]),
      trustedFor(caseObj, fixtures, index),
      configFor(caseObj, fixtures, replay),
      new Date(caseObj.at),
    );
    const label = `${row.id}#${row.presentation}`;
    want.push({
      case: label,
      outcome: row.outcome,
      trustedInputsUsed: row.trusted_inputs_used,
    });
    got.push({
      case: label,
      outcome: result && result.outcome,
      trustedInputsUsed: result && result.trustedInputsUsed,
    });
  }
  assert.deepStrictEqual(got, want);
});

// ---------------------------------------------------------------------------
// N7: CLI refuses a case file whose bytes do not match the manifest
// ---------------------------------------------------------------------------

test("N7", (t) => {
  const control = runCli(["--dir", copyVectors(t)]);
  assert.equal(control.status, 0, "unchanged copy: exit code");
  assert.equal(resultLines(control.stdout).length, 28, "unchanged copy: lines");

  const tampered = copyVectors(t);
  const id = "parent-swap";
  const file = path.join(tampered, id + ".json");
  const before = fs.readFileSync(file);
  const after = Buffer.from(JSON.stringify(JSON.parse(before.toString("utf8"))));
  assert.ok(!before.equals(after), "setup: only whitespace changed the bytes");
  fs.writeFileSync(file, after);

  const r = runCli(["--dir", tampered]);
  assert.equal(r.status, 1, "tampered copy: exit code");
  assert.ok(r.stderr.includes(id), "stderr names the case");
  assert.ok(r.stderr.includes("digest"), "stderr contains the word digest");
  const lines = resultLines(r.stdout);
  assert.equal(lines.filter((l) => l.id === id).length, 0,
    "no result line for the tampered case");
});

// ---------------------------------------------------------------------------
// N8: CLI output, FAIL paths and exit codes
// ---------------------------------------------------------------------------

test("N8", (t) => {
  const expected = readJSON(path.join(VECTOR_DIR, "expected.json")).cases;

  // Published vectors.
  const pub = runCli(["--dir", VECTOR_DIR]);
  assert.equal(pub.status, 0, "published vectors: exit code");
  assert.deepStrictEqual(
    resultLines(pub.stdout),
    expected.map((row) => expectedLine(row)),
    "published vectors: 28 lines in expected.json order",
  );

  const targetId = "local-expired";
  const targetIndex = expected.findIndex((row) => row.id === targetId);
  assert.ok(targetIndex >= 0, "setup: target row exists");

  // One expected.json row changed, digests valid.
  const dirA = copyVectors(t);
  const expA = readJSON(path.join(dirA, "expected.json"));
  assert.notEqual(expA.cases[targetIndex].outcome, "permit");
  expA.cases[targetIndex].outcome = "permit";
  fs.writeFileSync(path.join(dirA, "expected.json"),
    JSON.stringify(expA, null, 2) + "\n");
  const a = runCli(["--dir", dirA]);
  assert.equal(a.status, 1, "changed expected row: exit code");
  const lineA = resultLines(a.stdout)[targetIndex];
  assert.equal(lineA.id, targetId, "changed expected row: line position");
  assert.equal(lineA.status, "FAIL", "changed expected row: status");

  // One embedded recorded outcome changed, manifest digest refreshed.
  const dirB = copyVectors(t);
  const caseFile = path.join(dirB, targetId + ".json");
  const caseObj = readJSON(caseFile);
  assert.notEqual(caseObj.presentations[0].outcome, "permit");
  caseObj.presentations[0].outcome = "permit";
  const caseBytes = Buffer.from(JSON.stringify(caseObj, null, 2) + "\n");
  fs.writeFileSync(caseFile, caseBytes);
  const manifest = readJSON(path.join(dirB, "manifest.json"));
  const entry = manifest.cases.find((c) => c.id === targetId);
  assert.ok(entry, "setup: manifest entry exists");
  entry.digest = "sha256:" + hex(sha256(caseBytes));
  fs.writeFileSync(path.join(dirB, "manifest.json"),
    JSON.stringify(manifest, null, 2) + "\n");
  const b = runCli(["--dir", dirB]);
  assert.equal(b.status, 1, "changed embedded result: exit code");
  const lineB = resultLines(b.stdout)[targetIndex];
  assert.equal(lineB.id, targetId, "changed embedded result: line position");
  assert.equal(lineB.status, "FAIL", "changed embedded result: status");

  // Missing directory.
  const missing = path.join(makeTemp(t), "no-such-directory");
  assert.equal(runCli(["--dir", missing]).status, 2, "missing dir: exit code");

  // Fixtures whose ceiling no longer matches ceiling_ref.
  const fx = readJSON(FIXTURES_PATH);
  fx.ceiling = fx.ceiling.slice(0, -1);
  const fxPath = path.join(makeTemp(t), "fixtures.json");
  fs.writeFileSync(fxPath, JSON.stringify(fx, null, 2) + "\n");
  assert.equal(
    runCli(["--dir", VECTOR_DIR, "--fixtures", fxPath]).status,
    2,
    "altered ceiling: exit code",
  );
});

// ---------------------------------------------------------------------------
// N9: chain limits
// ---------------------------------------------------------------------------

test("N9", () => {
  const base = loadBase();
  const request = requestOf(base.pres);
  assert.equal(request.chain.length, 3, "setup: three chain tokens");
  const B = request.chain.reduce((n, tok) => n + Buffer.byteLength(tok), 0);
  assert.equal(B, 3471, "setup: published chain byte total");

  const run = (maxTokens, maxBytes) =>
    runBase(base, request, { maxTokens, maxBytes });
  assert.equal(run(3, 10 ** 9), "permit", "maxTokens 3");
  assert.equal(run(2, 10 ** 9), "malformed", "maxTokens 2");
  assert.equal(run(1000, B), "permit", "maxBytes B");
  assert.equal(run(1000, B - 1), "malformed", "maxBytes B - 1");
});

// ---------------------------------------------------------------------------
// N10: a mandate that is not the fixture mandate reaches the decision step
// ---------------------------------------------------------------------------

test("N10", () => {
  const base = loadBase();
  const modified = rebuild(base, 2, (tokens) => {
    tokens[2].payload.mandate = {
      format: "cedar",
      policy_set: [base.fixtures.mandate[0]],
    };
  });
  assert.deepStrictEqual(modified.args, { max_records: 500 }, "setup: args");
  assert.equal(parseCompact(modified.invocation).payload.action, "read",
    "setup: action");
  assert.deepStrictEqual(
    base.caseObj.wpt[0].covers,
    ["Pedigree", "Pedigree-Invocation"],
    "setup: WPT coverage",
  );

  assert.equal(runBase(base, modified), "unsupported_fixture_policy",
    "leaf mandate narrowed to one fixture policy");
  assert.equal(runBase(base, requestOf(base.pres)), "permit", "control");
});

// ---------------------------------------------------------------------------
// N11: par_hash spelling and header jwk members
// ---------------------------------------------------------------------------

test("N11", () => {
  const base = loadBase();
  const t1 = parseCompact(base.pres.chain[1]);
  const parentDigest = sha256(signingInputOf(base.pres.chain[0]));
  assert.equal(t1.payload.par_hash, toB64u(parentDigest),
    "setup: published par_hash is the parent digest");
  const signer = base.byX.get(t1.header.jwk.x);

  const hexForm = rebuild(base, 1, (tokens) => {
    tokens[1].payload.par_hash = hex(parentDigest);
  });
  assert.match(parseCompact(hexForm.chain[1]).payload.par_hash,
    /^[0-9a-f]{64}$/, "setup: hex par_hash");

  const withD = rebuild(base, 1, (tokens) => {
    tokens[1].header.jwk.d = toB64u(signer.seed);
  });
  const withKid = rebuild(base, 1, (tokens) => {
    tokens[1].header.jwk.kid = "agent-1";
  });

  assert.equal(runBase(base, hexForm), "malformed",
    "(a) T_1 par_hash in lowercase hex");
  assert.equal(runBase(base, withD), "malformed",
    "(b) T_1 header jwk with a d member");
  assert.equal(runBase(base, withKid), "permit",
    "(c) T_1 header jwk with kid");
});
