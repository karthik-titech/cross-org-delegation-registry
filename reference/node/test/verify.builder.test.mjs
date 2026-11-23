import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { spawnSync } from "node:child_process";
import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import process from "node:process";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { runInNewContext } from "node:vm";
import { FixtureError, loadFixtures } from "../lib/fixtures.mjs";
import { verify } from "../lib/verify.mjs";

const fixturesBytes = readFileSync(new URL("../../go/pedigree/testdata/fixtures.json", import.meta.url));
const fixtures = JSON.parse(fixturesBytes);
const digest = (value) => createHash("sha256").update(value);
const b64 = (value) => Buffer.from(value).toString("base64url");

// This serializer is used only with the simple JSON values below.
function sortedJson(value) {
  if (Array.isArray(value)) return "[" + value.map(sortedJson).join(",") + "]";
  if (value && typeof value === "object") {
    const pairs = Object.keys(value).sort().map((key) => JSON.stringify(key) + ":" + sortedJson(value[key]));
    return "{" + pairs.join(",") + "}";
  }
  return JSON.stringify(value);
}

function privateKeyFromSeed(seed) {
  return createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]),
    format: "der",
    type: "pkcs8",
  });
}

function testKey(byte) {
  const privateKey = privateKeyFromSeed(Buffer.alloc(32, byte));
  const { x } = createPublicKey(privateKey).export({ format: "jwk" });
  const jwk = { crv: "Ed25519", kty: "OKP", x };
  return {
    privateKey,
    jwk,
    standard: Buffer.from(x, "base64url").toString("base64"),
    jkt: digest(JSON.stringify(jwk)).digest("base64url"),
  };
}

function compact(header, payload, key) {
  const input = b64(sortedJson(header)) + "." + b64(sortedJson(payload));
  return input + "." + b64(sign(null, Buffer.from(input, "ascii"), key.privateKey));
}

function signingDigest(jws) {
  return digest(jws.slice(0, jws.lastIndexOf("."))).digest("base64url");
}

// All three synthetic signing keys are for tests only.
const [anchor, agent, holder] = [21, 22, 23].map(testKey);
const at = new Date("2026-10-18T08:00:15Z");
const iat = at.getTime() / 1000 - 15;
const verifier = "https://records.example.net";
const resource = fixtures.resource;
const allLabels = [
  "policy_fixture",
  "consent_fixture",
  "wpt_assumed:fresh,covers=Pedigree+Pedigree-Invocation",
];

function setup({ changeRoot, changeChild, changeInvocation, changeArguments, changeInputs } = {}) {
  const grant = { resource, scopes: ["read", "export"] };
  const root = {
    iss: "issuer", sub: "principal", client_id: "first", aud: "another-verifier", jti: "root",
    iat, exp: iat + 120, cnf: { jkt: agent.jkt }, del_depth: 0, parent_chain: [],
    grants: [structuredClone(grant)], consent_chain: ["consent"], ceiling_ref: fixtures.ceiling_ref,
  };
  const rootHeader = { typ: "pedigree+jwt", alg: "Ed25519" };
  changeRoot?.(root, rootHeader);
  const rootToken = compact(rootHeader, root, anchor);
  const child = {
    ...structuredClone(root), iss: "first", client_id: "last", aud: [verifier], jti: "child",
    cnf: { jkt: holder.jkt }, del_depth: 1, parent_chain: [root.jti],
    par_hash: signingDigest(rootToken),
    mandate: { format: "cedar", policy_set: [...fixtures.mandate] },
  };
  const childHeader = { typ: "pedigree+jwt", alg: "Ed25519", jwk: { ...agent.jwk } };
  changeChild?.(child, childHeader);
  const childToken = compact(childHeader, child, agent);
  const args = { max_records: 500 };
  const invocation = {
    iss: "last", aud: verifier, jti: "invocation", iat, exp: iat + 60, action: "read", resource,
    tok: signingDigest(childToken), args: { sha256: digest(sortedJson(args)).digest("base64url") },
  };
  const invocationHeader = { typ: "pedigree-inv+jwt", alg: "Ed25519" };
  changeInvocation?.(invocation, invocationHeader);
  changeArguments?.(args);

  const config = {
    trustAnchors: { issuer: anchor.standard },
    verifierIds: [verifier],
    ceilings: { [fixtures.ceiling_ref]: Buffer.from(sortedJson(fixtures.ceiling)) },
    maxTokens: 8,
    maxBytes: 262144,
    maxInvocationLifetimeSeconds: 60,
    replay: { available: true, seen: new Set() },
  };
  const trusted = {
    wpt: { presentation_index: 1, holder_key: holder.standard, fresh: true, covers: ["Pedigree", "Pedigree-Invocation"] },
    consent: [{ trust_anchor_kid: "issuer", consent_id: "consent", valid_at: at.toISOString(), active: true }],
    policies: structuredClone(fixtures),
  };
  const presentation = { chain: [rootToken, childToken], invocation: compact(invocationHeader, invocation, holder), args };
  changeInputs?.(presentation, trusted, config);
  return { run: (instant = at) => verify(presentation, trusted, config, instant), presentation, trusted, config };
}

function check(outcome, labels, options) {
  assert.deepEqual(setup(options).run(), { outcome, trustedInputsUsed: labels });
}

test("B:verify loads fixtures only with a matching canonical ceiling", () => {
  assert.deepEqual(loadFixtures(fixturesBytes), fixtures);
  assert.throws(() => loadFixtures(Buffer.from("{")), FixtureError);
  assert.throws(() => loadFixtures(Buffer.from('{"ceiling":[]}')), FixtureError);
  assert.throws(() => loadFixtures(Buffer.from(JSON.stringify({ ...fixtures, ceiling: fixtures.ceiling.toReversed() }))),
    { name: "FixtureError", message: "Fixture ceiling digest mismatch" });
});

test("B:verify fixture loading rejects contradictory decisions with JCS-equivalent arguments", () => {
  const policies = structuredClone(fixtures);
  const row = policies.decisions.find((entry) => entry.policy_id === "mandate" && entry.action === "read");
  row.args = { max_records: 500, extra: true };
  const duplicate = { ...row, args: { extra: true, max_records: 500 } };
  policies.decisions.push(duplicate);
  assert.deepEqual(loadFixtures(Buffer.from(JSON.stringify(policies))), policies);
  duplicate.decision = row.decision === "permit" ? "deny" : "permit";
  assert.throws(() => loadFixtures(Buffer.from(JSON.stringify(policies))), FixtureError);
});

test("B:verify step 11 rejects contradictory decisions in directly supplied fixtures", () => {
  const changeInputs = (_p, t) => {
    const row = t.policies.decisions.find((entry) => entry.policy_id === "mandate" && entry.action === "read");
    t.policies.decisions.push({ ...row, decision: "deny" });
  };
  const changeChild = (p) => { delete p.mandate; };
  const consentAndWpt = allLabels.slice(1);
  check("unsupported_fixture_policy", allLabels, { changeInputs });
  check("unsupported_fixture_policy", [...consentAndWpt, "policy_fixture"], { changeChild, changeInputs });
  check("scope_not_granted", consentAndWpt, {
    changeChild,
    changeInvocation: (p) => { p.action = "delete"; },
    changeInputs,
  });
});

test("B:verify rejects missing and NaN limits before processing", () => {
  for (const limit of ["maxTokens", "maxBytes", "maxInvocationLifetimeSeconds"]) {
    const { run, config } = setup({ changeInputs: (p) => { p.chain = []; } });
    delete config[limit];
    assert.throws(run, TypeError, limit + " missing");
    config[limit] = NaN;
    assert.throws(run, TypeError, limit + " NaN");
  }
});

test("B:verify wraps a throwing maxBytes getter in TypeError", () => {
  const { run, config } = setup();
  const cause = new RangeError("Cannot read maxBytes");
  Object.defineProperty(config, "maxBytes", {
    get() { throw cause; },
  });
  assert.throws(run, (error) => error instanceof TypeError && error.cause === cause);
});

test("B:verify reads each limit once before processing the presentation", () => {
  const { run, config, presentation } = setup();
  const limits = ["maxTokens", "maxBytes", "maxInvocationLifetimeSeconds"];
  const reads = [];
  for (const name of limits) {
    const value = config[name];
    Object.defineProperty(config, name, {
      get() { reads.push(name); return value; },
    });
  }
  const chain = presentation.chain;
  Object.defineProperty(presentation, "chain", {
    get() { reads.push("chain"); return chain; },
  });
  assert.deepEqual(run(), { outcome: "permit", trustedInputsUsed: allLabels });
  assert.deepEqual(reads, [...limits, "chain"]);
});

test("B:verify step 1 checks every token and both JCS segments before signatures", () => {
  check("malformed", [], { changeRoot: (p) => { p.grants[0].resource = "local"; } });
  check("malformed", [], { changeChild: (p) => { p.grants.push(p.grants[0]); } });
  check("malformed", [], { changeChild: (p) => { p.act = { sub: "unrelated" }; } });
  check("malformed", [], { changeChild: (_p, h) => { h.crit = ["extension"]; } });
  check("malformed", [], { changeChild: (_p, h) => { h.jwk.oth = []; } });
  check("malformed", [], { changeInputs: (_p, _t, c) => { c.maxTokens = 1; } });
  for (const index of [0, 1]) {
    check("non_canonical", [], {
      changeRoot: (_p, h) => { h.alg = "EdDSA"; },
      changeInputs: (p) => {
        const segments = p.chain[1].split(".");
        segments[index] = b64(Buffer.from(segments[index], "base64url").toString() + " ");
        p.chain[1] = segments.join(".");
      },
    });
  }
});

test("B:verify rejects a fragment in a grant resource URI", () => {
  check("malformed", [], {
    changeRoot: (p) => { p.grants[0].resource = "https://records.example.net/data#frag"; },
  });
});

test("B:verify rejects a fragment in an invocation resource URI", () => {
  check("invocation_invalid", allLabels, {
    changeInvocation: (p) => { p.resource = "https://records.example.net/data#frag"; },
  });
});

test("B:verify step 1 checks private and registered public T_1 JWK members", () => {
  const vector = JSON.parse(readFileSync(new URL("../../../vectors/pedigree-01/valid-3-hop.json", import.meta.url)));
  const { chain, invocation, args } = vector.presentations[0];
  const wpt = vector.wpt[0];
  const keyByX = new Map(vector.keys.map(({ label, seed_hex }) => {
    assert.equal(label, "TEST ONLY");
    const privateKey = privateKeyFromSeed(Buffer.from(seed_hex, "hex"));
    const { x, d } = privateKey.export({ format: "jwk" });
    return [x, { privateKey, d }];
  }));
  const holderKey = keyByX.get(b64(Buffer.from(wpt.holder_key, "base64")));
  const parse = (token) => token.split(".").slice(0, 2)
    .map((part) => JSON.parse(Buffer.from(part, "base64url")));
  const [childHeader] = parse(chain[1]);
  const symmetricKey = b64(Buffer.alloc(32));
  const extension = { extra: "ignored" };
  const cases = [
    ["k alone", { k: symmetricKey }, "malformed"],
    ["k beside an unknown member", { k: symmetricKey, ...extension }, "malformed"],
    ["k with a null value", { k: null }, "malformed"],
    ["d alone", { d: keyByX.get(childHeader.jwk.x).d }, "malformed"],
    ["unknown member alone", extension, "permit"],
    ["unknown numeric member", { extra: 10 }, "permit"],
    ["numeric kid", { kid: 1 }, "malformed"],
    ["null alg", { alg: null }, "malformed"],
    ["object use", { use: {} }, "malformed"],
    ["boolean x5u", { x5u: true }, "malformed"],
    ["string key_ops", { key_ops: "sign" }, "malformed"],
    ["mixed-type key_ops", { key_ops: ["sign", 1] }, "malformed"],
    ["numeric x5c element", { x5c: [1] }, "malformed"],
    ["numeric x5t", { x5t: 1 }, "malformed"],
    ["numeric x5t#S256", { "x5t#S256": 1 }, "malformed"],
    ["string kid", { kid: "" }, "permit"],
    ["string alg differing from the header", { alg: "RS256" }, "permit"],
    ["string use", { use: "sig" }, "permit"],
    ["string x5u", { x5u: "https://example.test/cert.pem" }, "permit"],
    ["string elements in key_ops", { key_ops: ["sign"] }, "permit"],
    ["empty x5c", { x5c: [] }, "permit"],
    ["string elements in x5c", { x5c: ["certificate"] }, "permit"],
    ["string x5t", { x5t: "thumbprint" }, "permit"],
    ["string x5t#S256", { "x5t#S256": "thumbprint" }, "permit"],
  ];

  for (const [name, members, outcome] of cases) {
    const rebuilt = [chain[0]];
    for (let i = 1; i < chain.length; i++) {
      const [header, payload] = parse(chain[i]);
      if (i === 1) Object.assign(header.jwk, members);
      payload.par_hash = signingDigest(rebuilt[i - 1]);
      rebuilt.push(compact(header, payload, keyByX.get(header.jwk.x)));
    }
    const [header, payload] = parse(invocation);
    payload.tok = signingDigest(rebuilt.at(-1));
    const result = verify(
      { chain: rebuilt, invocation: compact(header, payload, holderKey), args },
      { wpt, consent: vector.consent, policies: fixtures },
      {
        trustAnchors: vector.trust_anchors,
        verifierIds: vector.verifier_ids,
        ceilings: { [fixtures.ceiling_ref]: Buffer.from(sortedJson(fixtures.ceiling)) },
        maxTokens: 8,
        maxBytes: 262144,
        maxInvocationLifetimeSeconds: 60,
        replay: { available: vector.replay_available, seen: new Set() },
      },
      new Date(vector.at),
    );
    assert.deepEqual(result, { outcome, trustedInputsUsed: outcome === "permit" ? allLabels : [] }, name);
  }
});

test("B:verify step 2 selects the configured issuer and enforces algorithm and parent key", () => {
  check("permit", allLabels, {
    changeRoot: (_p, h) => { h.kid = "issuer-key-hint"; },
    changeChild: (_p, h) => { h.jwk = { ...h.jwk, alg: "ignored", extra: 10 }; },
  });
  check("signature_invalid", [], { changeRoot: (_p, h) => { h.alg = "EdDSA"; } });
  check("signature_invalid", [], { changeRoot: (p) => { p.cnf.jkt = holder.jkt; } });
  check("signature_invalid", [], { changeChild: (p) => { p.iss = "elsewhere"; } });
  check("signature_invalid", [], { changeInputs: (_p, _t, c) => { c.trustAnchors = { issuer: "+/8" }; } });
});

test("B:verify steps 3 and 4 distinguish digest, linkage, principal and consent failures", () => {
  check("par_hash_mismatch", [], { changeChild: (p) => { p.par_hash = b64(Buffer.alloc(32)); } });
  check("linkage_invalid", [], { changeRoot: (p) => { p.del_depth = 1; } });
  check("linkage_invalid", [], { changeChild: (p) => { p.parent_chain = ["different-root"]; } });
  check("principal_altered", [], { changeChild: (p) => { p.sub = "other"; } });
  check("consent_altered", [], { changeChild: (p) => { p.consent_chain = ["other"]; } });
});

test("B:verify step 5 checks fixture policy effects, grants and retained forbids", () => {
  check("unsupported_fixture_policy", allLabels.slice(0, 1), {
    changeChild: (p) => { p.mandate.policy_set = ["unknown policy"]; },
  });
  check("unsupported_fixture_policy", allLabels.slice(0, 1), {
    changeInputs: (_p, t) => { t.policies.effects[fixtures.mandate[0]] = "unknown"; },
  });
  check("scope_widened", allLabels.slice(0, 1), {
    changeChild: (p) => { p.grants[0].scopes.push("delete"); },
  });
  check("mandate_not_narrower", allLabels.slice(0, 1), {
    changeRoot: (p) => { p.mandate = { format: "cedar", policy_set: [...fixtures.ceiling] }; },
    changeChild: (p) => { p.narrowing_proof = { format: "unsupported", hash: fixtures.ceiling_ref }; },
  });
});

test("B:verify steps 6 and 7 enforce time bounds and every ceiling reference", () => {
  check("expired", allLabels.slice(0, 1), { changeChild: (p) => { p.iat -= 1; } });
  check("expired", allLabels.slice(0, 1), { changeChild: (p) => { p.nbf = iat + 16; } });
  check("expired", allLabels.slice(0, 1), { changeChild: (p) => { p.exp = iat + 15; } });
  check("expired", allLabels.slice(0, 1), { changeChild: (p) => { p.exp += 1; } });
  check("ceiling_unknown", allLabels.slice(0, 1), {
    changeRoot: (p) => { p.ceiling_ref = "sha256:" + "0".repeat(64); },
    changeChild: (p) => { p.ceiling_ref = fixtures.ceiling_ref; },
  });
});

test("B:verify treats fractional milliseconds from a Date-like instant as an invalid Date", () => {
  const { run } = setup();
  const invalid = run(new Date(NaN));
  assert.deepEqual(invalid, { outcome: "expired", trustedInputsUsed: allLabels.slice(0, 1) });
  assert.deepEqual(run({ getTime: () => 1.5 }), invalid);
});

const numericDateBoundary = 1700000000;
const beforeBoundary = "2023-11-14T22:13:19.9999999Z";
const afterBoundary = "2023-11-14T22:13:20.0000001Z";

for (const [claim, before, after] of [
  ["iat", "expired", "permit"],
  ["nbf", "expired", "permit"],
  ["exp", "permit", "expired"],
]) {
  test("B:verify compares token " + claim + " at 100 nanoseconds on either side", () => {
    for (const [instant, outcome] of [[beforeBoundary, before], [afterBoundary, after]]) {
      const { run } = setup({
        changeRoot: (p) => {
          p.iat = numericDateBoundary - 15;
          p.exp = numericDateBoundary + 60;
          p[claim] = numericDateBoundary;
        },
        changeInvocation: (p) => {
          p.iat = numericDateBoundary - 15;
          p.exp = claim === "exp" ? numericDateBoundary : numericDateBoundary + 30;
        },
        changeInputs: (_p, t) => { t.consent[0].valid_at = instant; },
      });
      const trustedInputsUsed = outcome === "permit" ? allLabels : allLabels.slice(0, 1);
      assert.deepEqual(run(instant), { outcome, trustedInputsUsed }, instant);
    }
  });
}

test("B:verify compares the invocation window at 100 nanoseconds on either side", () => {
  for (const [claim, before, after] of [
    ["iat", "invocation_invalid", "permit"],
    ["exp", "permit", "invocation_invalid"],
  ]) {
    for (const [instant, outcome] of [[beforeBoundary, before], [afterBoundary, after]]) {
      const { run } = setup({
        changeRoot: (p) => { p.iat = numericDateBoundary - 15; p.exp = numericDateBoundary + 60; },
        changeInvocation: (p) => {
          p.iat = numericDateBoundary - 15;
          p.exp = numericDateBoundary + 30;
          p[claim] = numericDateBoundary;
        },
        changeInputs: (_p, t) => { t.consent[0].valid_at = instant; },
      });
      assert.deepEqual(run(instant), { outcome, trustedInputsUsed: allLabels }, claim + " at " + instant);
    }
  }
});

test("B:verify truncates subnanosecond digits when comparing a fractional NumericDate", () => {
  for (const [fraction, outcome] of [["0009765629", "expired"], ["0009765630", "permit"]]) {
    const instant = "2023-11-14T22:13:20." + fraction + "Z";
    const { run } = setup({
      changeRoot: (p) => {
        p.iat = numericDateBoundary + 1 / 1024;
        p.exp = numericDateBoundary + 60;
      },
      changeInvocation: (p) => {
        p.iat = numericDateBoundary - 15;
        p.exp = numericDateBoundary + 30;
      },
      changeInputs: (_p, t) => { t.consent[0].valid_at = instant; },
    });
    const trustedInputsUsed = outcome === "permit" ? allLabels : allLabels.slice(0, 1);
    assert.deepEqual(run(instant), { outcome, trustedInputsUsed }, instant);
  }
});

test("B:verify rejects a ceiling map entry whose bytes do not hash to its key", () => {
  check("unsupported_fixture_policy", allLabels.slice(0, 1), {
    changeInputs: (_p, _t, c) => { c.ceilings["sha256:" + "0".repeat(64)] = Buffer.from("[]"); },
  });
});

test("B:verify rejects a leaf ceiling that differs from the fixture ceiling", () => {
  const bytes = Buffer.from(sortedJson(fixtures.ceiling) + " ");
  const ref = "sha256:" + digest(bytes).digest("hex");
  check("unsupported_fixture_policy", allLabels, {
    changeChild: (p) => { p.ceiling_ref = ref; },
    changeInputs: (_p, t, c) => {
      c.ceilings[ref] = bytes;
      const row = t.policies.decisions.find((entry) => entry.policy_id === fixtures.ceiling_ref && entry.action === "read");
      t.policies.decisions.push({ ...row, policy_id: ref });
    },
  });
});

test("B:verify steps 8 and 9 order status, exact consent answers and leaf audience", () => {
  check("status_unknown", allLabels.slice(0, 1), {
    changeRoot: (p) => { p.status = { status_list: { idx: 0, uri: "https://status.example/list" } }; },
    changeInputs: (_p, t) => { t.consent[0].active = false; },
  });
  check("status_unknown", allLabels.slice(0, 2), {
    changeInputs: (_p, t) => { t.consent[0].trust_anchor_kid = "other"; },
  });
  check("status_unknown", allLabels.slice(0, 2), {
    changeInputs: (_p, t) => { t.consent[0].valid_at = new Date(at.getTime() - 1).toISOString(); },
  });
  check("revoked", allLabels.slice(0, 2), { changeInputs: (_p, t) => { t.consent[0].active = false; } });
  check("audience_mismatch", allLabels.slice(0, 2), { changeChild: (p) => { p.aud = "other"; } });
});

test("B:verify a matching revoked consent answer overrides an active answer in either order", () => {
  for (const fraction of [".0000", ".000000000"]) {
    for (const reverse of [false, true]) {
      check("revoked", allLabels.slice(0, 2), {
        changeInputs: (_p, t) => {
          const valid_at = "2026-10-18T08:00:15Z";
          t.consent[0].valid_at = valid_at;
          t.consent.push({ ...t.consent[0], valid_at: valid_at.replace("Z", fraction + "Z"), active: false });
          if (reverse) t.consent.reverse();
        },
      });
    }
  }
});

test("B:verify accepts consent answers parsed in another realm", () => {
  for (const active of [true, false]) {
    const changeInputs = (_p, t) => { t.consent[0].active = active; };
    const sameRealm = setup({ changeInputs });
    const otherRealm = setup({ changeInputs });
    const json = JSON.stringify(sameRealm.trusted.consent);
    otherRealm.trusted.consent = runInNewContext("JSON.parse(json)", { json });
    assert.deepEqual(otherRealm.run(), sameRealm.run());
  }
});

for (const [kind, entry] of [["null", null], ["string", "consent"], ["array", []]]) {
  test("B:verify refuses consent entries of type " + kind + " even alongside an active match", () => {
    check("status_unknown", allLabels.slice(0, 2), {
      changeInputs: (_p, t) => { t.consent.push(entry); },
    });
  });
}

test("B:verify requires a boolean active value on every matching consent answer", () => {
  for (const value of [0, "false", null, undefined]) {
    check("status_unknown", allLabels.slice(0, 2), {
      changeInputs: (_p, t) => {
        const match = { ...t.consent[0], active: value };
        if (value === undefined) delete match.active;
        t.consent.push(match);
      },
    });
  }
});

test("B:verify maps throwing caller getters to the check that reads them", () => {
  const failRead = (target, key) => {
    Object.defineProperty(target, key, {
      get() { throw new Error("Cannot read " + key); },
    });
  };
  check("malformed", [], { changeInputs: (p) => failRead(p, "chain") });
  check("unsupported_fixture_policy", allLabels.slice(0, 1), {
    changeInputs: (_p, t) => failRead(t, "policies"),
  });
  check("status_unknown", allLabels.slice(0, 2), {
    changeInputs: (_p, t) => failRead(t, "consent"),
  });
  check("holder_binding_failed", allLabels.slice(0, 2), {
    changeInputs: (_p, t) => failRead(t, "wpt"),
  });
  check("invocation_invalid", allLabels, { changeInputs: (p) => failRead(p, "invocation") });
  check("unsupported_fixture_policy", [...allLabels.slice(1), "policy_fixture"], {
    changeChild: (p) => { delete p.mandate; },
    changeInputs: (_p, t) => failRead(t, "policies"),
  });
});

test("B:verify a sub-millisecond consent instant never matches a whole second", () => {
  check("status_unknown", allLabels.slice(0, 2), {
    changeInputs: (_p, t) => { t.consent[0].valid_at = "2026-10-18T08:00:15.0009Z"; },
  });
  check("permit", allLabels, {
    changeInputs: (_p, t) => {
      t.consent[0].valid_at = "2026-10-17T23:30:15.000000000-08:30";
      t.consent.unshift({ ...t.consent[0], valid_at: "2026-10-18T08:00:15.0009Z", active: false });
    },
  });
});

test("B:verify an invalid timestamp for a matching consent ID yields status_unknown in either order", () => {
  for (const reverse of [false, true]) {
    check("status_unknown", allLabels.slice(0, 2), {
      changeInputs: (_p, t) => {
        t.consent.push({ ...t.consent[0], active: false });
        t.consent.push({ ...t.consent[0], valid_at: "2026-02-30T08:00:15Z" });
        if (reverse) t.consent.reverse();
      },
    });
  }
});

test("B:verify step 10 labels WPT only when fresh is exactly true", () => {
  const earlierLabels = allLabels.slice(0, 2);
  for (const fresh of [false, "true", 1]) {
    check("holder_binding_failed", earlierLabels, {
      changeInputs: (_p, t) => { t.wpt.fresh = fresh; },
    });
  }
  check("holder_binding_failed", earlierLabels, { changeInputs: (_p, t) => { delete t.wpt.fresh; } });
  check("holder_binding_failed", earlierLabels, { changeInputs: (_p, t) => { delete t.wpt; } });
  check("permit", allLabels);
});

test("B:verify step 10 checks WPT coverage before invocation", () => {
  const pedigreeOnly = [...allLabels.slice(0, 2), "wpt_assumed:fresh,covers=Pedigree"];
  check("holder_binding_failed", pedigreeOnly, { changeInputs: (_p, t) => { t.wpt.covers.pop(); } });
  check("invocation_invalid", pedigreeOnly, {
    changeInputs: (p, t) => { t.wpt.covers.pop(); p.invocation = ""; },
  });
});

test("B:verify step 10 labels only the assumed WPT coverage in field order", () => {
  const cases = [
    [[], "holder_binding_failed", ""],
    [["Pedigree-Invocation"], "holder_binding_failed", "Pedigree-Invocation"],
    [["Pedigree-Invocation", "Pedigree", "Pedigree", "other"], "permit", "Pedigree+Pedigree-Invocation"],
    [["Pedigree"], "holder_binding_failed", "Pedigree"],
  ];
  for (const [covers, outcome, labelCoverage] of cases) {
    check(outcome, [...allLabels.slice(0, 2), "wpt_assumed:fresh,covers=" + labelCoverage], {
      changeInputs: (_p, t) => { t.wpt.covers = covers; },
    });
  }
});

test("B:verify step 10 checks invocation format, signature, binding and lifetime before replay", () => {
  const noReplay = (_p, _t, c) => { c.replay.available = false; };
  check("invocation_invalid", allLabels, {
    changeInvocation: (_p, h) => { h.jwk = holder.jwk; }, changeInputs: noReplay,
  });
  check("invocation_invalid", allLabels, {
    changeInputs: (p, t, c) => { p.invocation = p.invocation.replace(/\.[^.]+$/, ".AA"); noReplay(p, t, c); },
  });
  check("invocation_invalid", allLabels, {
    changeInvocation: (p) => { p.tok = b64(Buffer.alloc(32)); }, changeInputs: noReplay,
  });
  check("invocation_invalid", allLabels, { changeInvocation: (p) => { p.aud = "other"; } });
  check("invocation_invalid", allLabels, { changeInvocation: (p) => { p.exp += 1; }, changeInputs: noReplay });
  check("replay_unknown", allLabels, { changeInputs: noReplay });
  check("replay_unknown", allLabels, { changeInputs: noReplay, changeArguments: (args) => { args.max_records = 1; } });
});

test("B:verify step 10 records the invocation before arguments binding for its audience", () => {
  const { run, presentation, config } = setup();
  presentation.args.max_records = 1;
  assert.deepEqual(run(), { outcome: "invocation_invalid", trustedInputsUsed: allLabels });
  presentation.args.max_records = 500;
  assert.deepEqual(run(), { outcome: "invocation_replayed", trustedInputsUsed: allLabels });

  const fixture = setup({
    changeChild: (p) => { p.aud.push("other"); },
    changeInvocation: (p) => { p.aud = "other"; },
    changeInputs: (_p, _t, c) => { c.verifierIds.push("other"); c.replay = config.replay; },
  });
  assert.equal(fixture.run().outcome, "permit");
});

for (const method of ["add", "has"]) {
  test("B:verify reports replay_unknown without recording when seen." + method + " throws", () => {
    const { run, config } = setup();
    const seen = config.replay.seen;
    seen.add("existing");
    seen[method] = (key) => {
      Set.prototype.add.call(seen, key);
      throw new Error("Replay state failure");
    };
    assert.deepEqual(run(), { outcome: "replay_unknown", trustedInputsUsed: allLabels });
    assert.deepEqual([...seen], ["existing"]);
  });
}

test("B:verify reports replay_unknown for unusable replay sets", () => {
  class ReplaySet extends Set {}
  const subclass = new ReplaySet();
  const ownAdd = Object.assign(new Set(), { add: Set.prototype.add });
  const proxyTarget = new Set();
  const proxy = new Proxy(proxyTarget, {});
  const plain = {};
  for (const [seen, backingSet] of [
    [subclass, subclass], [ownAdd, ownAdd], [proxy, proxyTarget], [plain, null], [null, null],
  ]) {
    check("replay_unknown", allLabels, { changeInputs: (_p, _t, c) => { c.replay.seen = seen; } });
    if (backingSet) assert.equal(backingSet.size, 0);
  }
  assert.deepEqual(plain, {});

  const { run, config } = setup();
  assert.deepEqual(run(), { outcome: "permit", trustedInputsUsed: allLabels });
  assert.equal(config.replay.seen.size, 1);
});

test("B:verify refuses a hostile replay recorder before it can erase another invocation", () => {
  const first = setup();
  const seen = first.config.replay.seen;
  assert.deepEqual(first.run(), { outcome: "permit", trustedInputsUsed: allLabels });
  const second = setup({
    changeInvocation: (p) => { p.jti = "second-invocation"; },
    changeInputs: (_p, _t, c) => { c.replay.seen = seen; },
  });
  seen.add = () => {
    seen.clear();
    throw new Error("Replay state failure");
  };
  assert.deepEqual(second.run(), { outcome: "replay_unknown", trustedInputsUsed: allLabels });
  delete seen.add;
  assert.deepEqual(first.run(), { outcome: "invocation_replayed", trustedInputsUsed: allLabels });
  assert.equal(seen.size, 1);
});

test("B:verify retains a replay record after a step 11 denial", () => {
  const { run } = setup({ changeInvocation: (p) => { p.action = "delete"; } });
  assert.deepEqual(run(), { outcome: "scope_not_granted", trustedInputsUsed: allLabels });
  assert.deepEqual(run(), { outcome: "invocation_replayed", trustedInputsUsed: allLabels });
});

test("B:verify binds 1e21 in request arguments using JCS and enforces integer range in JOSE", () => {
  check("permit", allLabels, {
    changeInvocation: (p) => { p.args.sha256 = digest('{"max_records":1e+21}').digest("base64url"); },
    changeArguments: (args) => { args.max_records = 1e21; },
    changeInputs: (_p, t) => {
      for (const row of t.policies.decisions) {
        if (row.action === "read") row.args.max_records = 1e21;
      }
    },
  });
  check("malformed", [], { changeChild: (_p, h) => { h.jwk.extra = 1e21; } });
});

test("B:verify CLI reports large arguments, missing presentations and exact RFC 3339 case times", (t) => {
  const dir = mkdtempSync(fileURLToPath(new URL("../.builder-vectors-", import.meta.url)));
  t.after(() => rmSync(dir, { recursive: true }));
  const largeInteger = 9007199254740994;
  const { presentation, trusted, config } = setup({
    changeInvocation: (p) => {
      p.args.sha256 = digest('{"max_records":9007199254740994}').digest("base64url");
    },
    changeArguments: (args) => { args.max_records = largeInteger; },
    changeInputs: (_p, t) => {
      for (const row of t.policies.decisions) {
        if (row.action === "read") row.args.max_records = largeInteger;
      }
    },
  });
  const id = "large-argument";
  const file = id + ".json";
  const recorded = { outcome: "permit", trusted_inputs_used: allLabels };
  const caseData = {
    id,
    at: at.toISOString(),
    trust_anchors: config.trustAnchors,
    verifier_ids: config.verifierIds,
    replay_available: true,
    consent: trusted.consent,
    wpt: [trusted.wpt],
    presentations: [{ ...presentation, ...recorded }],
  };
  const writeJson = (name, value) => writeFileSync(join(dir, name), JSON.stringify(value));
  const writeCase = () => {
    const caseJson = JSON.stringify(caseData);
    writeFileSync(join(dir, file), caseJson);
    writeJson("manifest.json", {
      largeInteger,
      cases: [{ id, file, digest: "sha256:" + digest(caseJson).digest("hex") }],
    });
  };
  writeCase();
  const row = { id, presentation: 1, ...recorded };
  writeJson("expected.json", { largeInteger, cases: [row] });
  writeJson("fixtures.json", trusted.policies);

  const cli = fileURLToPath(new URL("../pedigree-verify.mjs", import.meta.url));
  const run = () => spawnSync(process.execPath, [cli, "--dir", dir, "--fixtures", join(dir, "fixtures.json")],
    { encoding: "utf8" });
  const lines = (result) => result.stdout.trimEnd().split("\n").map((line) => JSON.parse(line));
  const pass = { id, presentation: 1, expected: "permit", got: "permit", trusted_inputs_used: allLabels, status: "PASS" };
  const result = run();
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(lines(result), [pass]);

  writeJson("expected.json", { cases: [row, { ...row, presentation: 2 }] });
  const missing = run();
  assert.equal(missing.status, 1, missing.stderr);
  assert.deepEqual(lines(missing), [pass, {
    id, presentation: 2, expected: "permit", got: null, trusted_inputs_used: [], status: "FAIL",
  }]);

  caseData.at = "2026-10-18T08:00:15.0009Z";
  caseData.consent.push({ ...caseData.consent[0], active: false });
  caseData.consent[0].valid_at = "2026-10-18T09:00:15.000900000+01:00";
  writeCase();
  writeJson("expected.json", { cases: [row] });
  const precise = run();
  assert.equal(precise.status, 0, precise.stderr);
  assert.deepEqual(lines(precise), [pass]);

  caseData.at = "2026-10-18T08:00:15.0009";
  writeCase();
  const invalid = run();
  assert.equal(invalid.status, 2, invalid.stderr);
  assert.deepEqual(lines(invalid), [{ ...pass, got: null, trusted_inputs_used: [], status: "FAIL" }]);
});

test("B:verify step 11 orders grant, mandate and ceiling decisions using exact fixture inputs", () => {
  check("scope_not_granted", allLabels, { changeInvocation: (p) => { p.action = "delete"; } });
  check("mandate_denied", allLabels, {
    changeInputs: (_p, t) => {
      t.policies.decisions = t.policies.decisions.filter((row) => row.policy_id === "mandate");
      t.policies.decisions[0].decision = "deny";
    },
  });
  check("ceiling_denied", allLabels, {
    changeInputs: (_p, t) => { t.policies.decisions.find((r) => r.policy_id === fixtures.ceiling_ref).decision = "deny"; },
  });
  check("unsupported_fixture_policy", allLabels, { changeInputs: (_p, t) => { t.policies.decisions = []; } });
  check("permit", allLabels, { changeChild: (p) => { p.mandate.policy_set.reverse(); } });
});

test("B:verify records policy use after consent and WPT when a mandate-free grant passes", () => {
  const changeChild = (p) => { delete p.mandate; };
  const labels = [...allLabels.slice(1), "policy_fixture"];
  check("permit", labels, { changeChild });
  const changeInvocation = (p) => { p.action = "delete"; };
  check("scope_not_granted", allLabels.slice(1), { changeChild, changeInvocation });
  check("scope_not_granted", allLabels.slice(1), {
    changeChild,
    changeInvocation,
    changeInputs: (_p, t) => { t.policies.ceiling = []; },
  });
  check("ceiling_denied", labels, {
    changeChild,
    changeInputs: (_p, t) => { t.policies.decisions.find((r) => r.policy_id === fixtures.ceiling_ref).decision = "deny"; },
  });
  check("unsupported_fixture_policy", labels, { changeChild, changeInputs: (_p, t) => { t.policies.decisions = []; } });
  check("permit", allLabels);
});

test("B:verify skips policy access for mandate-free refusals at steps 8 and 10 and the step 11 grant check", () => {
  const changeChild = (p) => { delete p.mandate; };
  const forbidPolicyAccess = (t) => {
    Object.defineProperty(t, "policies", { get: () => assert.fail("Unexpected policy fixture access") });
  };
  check("status_unknown", ["consent_fixture"], {
    changeChild,
    changeInputs: (_p, t) => { forbidPolicyAccess(t); t.consent = []; },
  });
  check("invocation_invalid", allLabels.slice(1), {
    changeChild,
    changeInputs: (p, t) => { forbidPolicyAccess(t); p.invocation = ""; },
  });
  check("scope_not_granted", allLabels.slice(1), {
    changeChild,
    changeInvocation: (p) => { p.action = "delete"; },
    changeInputs: (_p, t) => { forbidPolicyAccess(t); },
  });
});
