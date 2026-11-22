import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import test from "node:test";
import { B64Error, decodeB64url, decodeStdB64, encodeB64url } from "../lib/b64url.mjs";
import { checkPublicKey, verifyEd25519 } from "../lib/ed25519.mjs";
import { IJSONError, parseIJSON } from "../lib/ijson.mjs";
import { canonicalize } from "../lib/jcs.mjs";

test("B:encoding distinguishes base64 alphabets and padding", () => {
  const bytes = Buffer.from([251, 255]);
  assert.deepEqual(decodeStdB64("+/8="), bytes);
  assert.deepEqual(decodeB64url("-_8"), bytes);
  assert.equal(encodeB64url(bytes), "-_8");
  for (const spelling of ["-_8=", "+/8", "+/9=", "+/8==", "+/8=\n", "A==="]) {
    assert.throws(() => decodeStdB64(spelling), B64Error);
  }
  for (const spelling of ["A", "-_8\n", "-_9", "+/8"]) {
    assert.throws(() => decodeB64url(spelling), B64Error);
  }
});

test("B:encoding checks I-JSON names, Unicode and exact decimal magnitudes", () => {
  const parse = (s) => parseIJSON(Buffer.from(s));
  const refused = [
    ['{"a":1,"\\u0061":2}', "duplicate"],
    ['{"a":[{"a":1,"a":2}]}', "duplicate"],
    ['"\\ud800"', "surrogate"],
    ['{"\\udfff":1}', "surrogate"],
    ['{"s":"\\uffff"}', "syntax"],
    ['{"\\ud83f\\udffe":true}', "syntax"],
    ["9007199254740992.0", "int_range"],
    ["-9007199254740992000e-3", "int_range"],
    ["9.007199254740992e15", "int_range"],
    ["1e999", "int_range"],
    ["[1,]", "syntax"],
    ['{"a":0,}', "syntax"],
    ["true false", "trailing"],
  ];
  for (const [source, reason] of refused) {
    assert.throws(() => parse(source), (e) => e instanceof IJSONError && e.reason === reason, source);
  }
  assert.throws(() => parseIJSON(Buffer.from([0xed, 0xa0, 0x80])), { reason: "utf8" });
  assert.equal(parse("900719925474099100e-2"), 9007199254740991);
  assert.equal(parse("9007199254740991.9"), 9007199254740992);
  assert.equal(parse('"\\ud83d\\ude00"'), "😀");
  const parsed = parse('{"__proto__":{"marker":true}}');
  assert.equal(Object.getPrototypeOf(parsed), Object.prototype);
  assert.equal(Object.hasOwn(parsed, "__proto__"), true);
  assert.equal(parsed.marker, undefined);
});

test("B:encoding emits JCS with code-unit order and rejects non-JSON values", () => {
  assert.equal(canonicalize({ 2: 1, 10: -0, "�": 2, "😀": [5e-324] }),
    '{"10":0,"2":1,"😀":[5e-324],"�":2}');
  for (const value of [NaN, Infinity, -Infinity, "\ud800", { "\udfff": true }]) {
    assert.throws(() => canonicalize(value), TypeError);
  }
  const nested = "[".repeat(10000) + "0" + "]".repeat(10000);
  assert.equal(canonicalize(parseIJSON(Buffer.from(nested))), nested);
});

const p = (1n << 255n) - 19n;
const l = (1n << 252n) + 27742317777372353535851937790883648493n;

function le32(number) {
  const bytes = Buffer.alloc(32);
  for (let offset = 0; offset < bytes.length; offset++) {
    bytes[offset] = Number(number & 255n);
    number >>= 8n;
  }
  return bytes;
}

test("B:encoding enforces Ed25519 key length, canonical y, square root, sign and order", () => {
  const cases = [
    [Buffer.alloc(31), "key_length"],
    [Buffer.alloc(33), "key_length"],
    [le32(p), "noncanonical_y"],
    [le32(2n), "no_point"],
    [le32((1n << 255n) | 1n), "zero_x_sign"],
    [le32(1n), "small_order"],
    [le32(p - 1n), "small_order"],
    [le32(0n), "small_order"],
    [le32(1n << 255n), "small_order"],
  ];
  for (const [raw, reason] of cases) {
    assert.deepEqual(checkPublicKey(raw), { ok: false, reason });
    assert.deepEqual(verifyEd25519(raw, Buffer.alloc(0), Buffer.alloc(64)),
      { ok: false, reason, backendCalled: false });
  }
});

test("B:encoding enforces Ed25519 signature length, R encoding and S range", () => {
  // Synthetic seed for this test only.
  const key = createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.alloc(32, 42)]),
    format: "der",
    type: "pkcs8",
  });
  const raw = Buffer.from(createPublicKey(key).export({ format: "jwk" }).x, "base64url");
  const msg = Buffer.from("Ed25519 pre-check test");
  const valid = sign(null, msg, key);
  const r = valid.subarray(0, 32);
  const cases = [
    [valid.subarray(0, 63), "signature_length"],
    [Buffer.concat([valid, Buffer.of(0)]), "signature_length"],
    [Buffer.concat([le32(p), le32(0n)]), "r_noncanonical_y"],
    [Buffer.concat([le32(2n), le32(0n)]), "r_no_point"],
    [Buffer.concat([le32((1n << 255n) | 1n), le32(0n)]), "r_zero_x_sign"],
    [Buffer.concat([r, le32(l)]), "s_range"],
  ];
  for (const [signature, reason] of cases) {
    assert.deepEqual(verifyEd25519(raw, msg, signature), { ok: false, reason, backendCalled: false });
  }
  assert.equal(verifyEd25519(raw, msg, Buffer.concat([le32(1n), le32(0n)])).backendCalled, true);
  assert.deepEqual(verifyEd25519(raw, msg, Buffer.concat([r, le32(l - 1n)])),
    { ok: false, reason: "signature_invalid", backendCalled: true });
  assert.deepEqual(verifyEd25519(raw, msg, valid), { ok: true, backendCalled: true });
  assert.deepEqual(verifyEd25519(raw, Buffer.from("changed"), valid),
    { ok: false, reason: "signature_invalid", backendCalled: true });
});
