import { Buffer } from "node:buffer";
import { createHash, timingSafeEqual } from "node:crypto";
import { types } from "node:util";
import { decodeB64url, decodeStdB64, encodeB64url } from "./b64url.mjs";
import { verifyEd25519 } from "./ed25519.mjs";
import { parseFixtureInstant } from "./fixture-instant.mjs";
import { indexDecisions } from "./fixtures.mjs";
import { parseIJSON } from "./ijson.mjs";
import { canonicalize } from "./jcs.mjs";
import { okpThumbprint } from "./thumbprint.mjs";

const claims = new Set([
  "iss", "sub", "client_id", "aud", "jti", "iat", "exp", "nbf", "cnf",
  "del_depth", "par_hash", "parent_chain", "grants", "mandate", "narrowing_proof",
  "consent_chain", "ceiling_ref", "completion_bindable", "status", "act",
]);
const invocationClaims = ["iss", "aud", "jti", "iat", "exp", "tok", "action", "resource", "args"];
const privateMembers = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
const jwkStringMembers = ["kid", "alg", "use", "x5u", "x5t", "x5t#S256"];
const jwkStringArrayMembers = ["key_ops", "x5c"];
const object = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const has = Object.hasOwn;
const setHas = Set.prototype.has;
const setAdd = Set.prototype.add;
const replayMethods = ["has", "add", "delete", "clear"];
const text = (v) => typeof v === "string" && v.length > 0;
const strings = (v) => Array.isArray(v) && v.every((item) => typeof item === "string");
const nonemptyStrings = (v) => strings(v) && v.length > 0;
const exactMembers = (v, names) => object(v) && Object.keys(v).length === names.length &&
  names.every((name) => has(v, name));
const sameArray = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
const audience = (value) => Array.isArray(value) ? value : [value];
const sha256 = (bytes) => createHash("sha256").update(bytes).digest();
const sha256Hex = (v) => typeof v === "string" && /^sha256:[0-9a-f]{64}$/.test(v) &&
  v.length === 71;
const unsupported = "unsupported_fixture_policy";

class NonCanonical extends Error {}

function requireShape(condition) {
  if (!condition) throw new TypeError("Invalid JWS shape");
}

function digestBytes(value) {
  const bytes = decodeB64url(value);
  requireShape(bytes.length === 32);
  return bytes;
}

function absoluteUri(value) {
  // RFC 3986 Section 4.3. Compare the original spelling wherever the URI is used.
  if (!text(value) || /[^A-Za-z0-9:/?\[\]@!$&'()*+,;=._~%-]/.test(value) ||
      /%(?![0-9A-Fa-f]{2})/.test(value)) return false;
  const uri = /^[A-Za-z][A-Za-z0-9+.-]*:([^?]*)(?:\?(.*))?$/.exec(value);
  if (!uri) return false;
  const [, hierPart, query = ""] = uri;
  if (/[\[\]]/.test(query)) return false;
  if (!hierPart.startsWith("//")) return !/[\[\]]/.test(hierPart);
  const authorityEnd = hierPart.indexOf("/", 2);
  const authority = hierPart.slice(2, authorityEnd < 0 ? undefined : authorityEnd);
  if (authorityEnd >= 0 && /[\[\]]/.test(hierPart.slice(authorityEnd))) return false;
  const host = /^(?:[^\[\]@]*@)?(\[[^\]]+\]|[^\[\]@:]*)(?::[0-9]*)?$/.exec(authority);
  if (!host) return false;
  if (!host[1].startsWith("[")) return true;
  if (/^\[v[0-9a-f]+\.[A-Za-z0-9._~!$&'()*+,;=:-]+\]$/i.test(host[1])) return true;
  try {
    return new URL("http://" + host[1]).hostname.startsWith("[");
  } catch {
    return false;
  }
}

function parseCompact(compact) {
  requireShape(typeof compact === "string");
  const parts = compact.split(".");
  requireShape(parts.length === 3 && parts[0] && parts[1]);
  const [headerBytes, payloadBytes, sig] = parts.map(decodeB64url);
  const header = parseIJSON(headerBytes);
  const payload = parseIJSON(payloadBytes);
  requireShape(object(header) && object(payload));
  if (!headerBytes.equals(Buffer.from(canonicalize(header))) ||
      !payloadBytes.equals(Buffer.from(canonicalize(payload)))) {
    throw new NonCanonical();
  }
  return { header, payload, sig, input: Buffer.from(parts[0] + "." + parts[1], "ascii") };
}

function checkHeader(header, type, child = false) {
  const names = child ? ["typ", "alg", "kid", "jwk"] : ["typ", "alg", "kid"];
  // This profile implements no JOSE critical extension parameters.
  requireShape(Object.keys(header).every((name) => names.includes(name)) &&
    header.typ === type && text(header.alg) && (!has(header, "kid") || typeof header.kid === "string"));
}

function temporalClaims(payload) {
  return text(payload.iss) && typeof payload.jti === "string" &&
    Number.isFinite(payload.iat) && Number.isFinite(payload.exp);
}

function parseChainToken(compact, index) {
  const token = parseCompact(compact);
  const { header, payload: p } = token;
  checkHeader(header, "pedigree+jwt", index > 0);
  if (index > 0) {
    const { jwk } = header;
    requireShape(object(jwk) && jwk.kty === "OKP" && jwk.crv === "Ed25519" &&
      !privateMembers.some((name) => has(jwk, name)) &&
      jwkStringMembers.every((name) => !has(jwk, name) || typeof jwk[name] === "string") &&
      jwkStringArrayMembers.every((name) => !has(jwk, name) || strings(jwk[name])));
    token.key = digestBytes(jwk.x);
    token.parentDigest = digestBytes(p.par_hash);
  } else {
    requireShape(!has(p, "par_hash") && !has(p, "narrowing_proof"));
  }

  requireShape(Object.keys(p).every((name) => claims.has(name)) && temporalClaims(p) &&
    text(p.sub) && text(p.client_id) && audience(p.aud).length > 0 && audience(p.aud).every(text) &&
    Number.isInteger(p.del_depth) && p.del_depth >= 0 && strings(p.parent_chain) &&
    nonemptyStrings(p.consent_chain) && exactMembers(p.cnf, ["jkt"]) && sha256Hex(p.ceiling_ref));
  digestBytes(p.cnf.jkt);

  requireShape(Array.isArray(p.grants) && p.grants.length > 0);
  const resources = new Set();
  for (const grant of p.grants) {
    requireShape(exactMembers(grant, ["resource", "scopes"]) && absoluteUri(grant.resource) &&
      nonemptyStrings(grant.scopes) && !resources.has(grant.resource));
    resources.add(grant.resource);
  }

  if (has(p, "mandate")) {
    requireShape(exactMembers(p.mandate, ["format", "policy_set"]) &&
      p.mandate.format === "cedar" && nonemptyStrings(p.mandate.policy_set));
  }
  if (has(p, "narrowing_proof")) {
    requireShape(p.mandate && exactMembers(p.narrowing_proof, ["format", "hash"]) &&
      typeof p.narrowing_proof.format === "string" && sha256Hex(p.narrowing_proof.hash));
  }
  requireShape((!has(p, "nbf") || Number.isFinite(p.nbf)) &&
    (!has(p, "completion_bindable") || typeof p.completion_bindable === "boolean") &&
    (!has(p, "act") || (object(p.act) && p.act.sub === p.client_id)));
  return token;
}

function validSignature(token, key) {
  return token.header.alg === "Ed25519" && verifyEd25519(key, token.input, token.sig).ok;
}

function compareNumericDate(now, date) {
  const whole = Math.floor(date);
  const seconds = BigInt(whole);
  if (now.seconds < seconds) return -1;
  if (now.seconds > seconds) return 1;
  return now.fraction - (date - whole);
}

function atInstant(p, now) {
  return compareNumericDate(now, p.iat) >= 0 && compareNumericDate(now, p.exp) < 0 &&
    (!has(p, "nbf") || compareNumericDate(now, p.nbf) >= 0);
}

function dateInstant(milliseconds) {
  if (!Number.isInteger(milliseconds)) return null;
  const elapsed = BigInt(milliseconds);
  const withinSecond = ((elapsed % 1000n) + 1000n) % 1000n;
  return {
    seconds: (elapsed - withinSecond) / 1000n,
    fraction: withinSecond.toString().padStart(3, "0").replace(/0+$/, ""),
    leapSecond: false,
  };
}

function coversGrant(grants, resource, scopes) {
  return grants.some((g) => g.resource === resource && scopes.every((s) => g.scopes.includes(s)));
}

function attenuation(payloads, mandates, policies) {
  const effect = (entry) => policies?.effects && has(policies.effects, entry) &&
    policies.effects[entry];
  if (mandates.some((mandate) => mandate?.some((entry) =>
    !["permit", "forbid"].includes(effect(entry))))) return unsupported;
  for (let i = 1; i < payloads.length; i++) {
    if (payloads[i].grants.some((g) => !coversGrant(payloads[i - 1].grants, g.resource, g.scopes))) {
      return "scope_widened";
    }
  }
  for (let i = 1; i < mandates.length; i++) {
    const parent = mandates[i - 1];
    const child = mandates[i];
    if (!parent) continue;
    if (!child ||
        child.some((entry) => policies.effects[entry] === "permit" && !parent.includes(entry)) ||
        parent.some((entry) => policies.effects[entry] === "forbid" && !child.includes(entry))) {
      return "mandate_not_narrower";
    }
  }
}

function parseInvocation(compact) {
  const token = parseCompact(compact);
  const p = token.payload;
  checkHeader(token.header, "pedigree-inv+jwt");
  requireShape(exactMembers(p, invocationClaims) && temporalClaims(p) && text(p.aud) &&
    typeof p.action === "string" && absoluteUri(p.resource) && object(p.args));
  token.leafDigest = digestBytes(p.tok);
  return token;
}

function recordInvocation(config, key) {
  try {
    const replay = config.replay;
    if (replay?.available !== true) return "replay_unknown";
    const seen = replay.seen;
    if (!types.isSet(seen) || types.isProxy(seen) || Object.getPrototypeOf(seen) !== Set.prototype ||
        replayMethods.some((name) => has(seen, name))) {
      return "replay_unknown";
    }
    if (setHas.call(seen, key)) return "invocation_replayed";
    setAdd.call(seen, key);
  } catch {
    return "replay_unknown";
  }
}

function invocationCheck(presentation, trusted, config, maxLifetime, now, leaf, used) {
  const { payload: p } = leaf;
  const bindingFailed = { failure: "holder_binding_failed" };
  let coversInvocation;
  let holderKey;
  try {
    const wpt = trusted?.wpt;
    if (wpt?.fresh !== true) return bindingFailed;
    const assumedCovers = wpt.covers;
    const covers = Array.isArray(assumedCovers)
      ? ["Pedigree", "Pedigree-Invocation"].filter((field) => assumedCovers.includes(field))
      : [];
    coversInvocation = covers.includes("Pedigree-Invocation");
    used.push("wpt_assumed:fresh,covers=" + covers.join("+"));
    holderKey = decodeStdB64(wpt.holder_key);
    if (!covers.includes("Pedigree") || holderKey.length !== 32 ||
        okpThumbprint(encodeB64url(holderKey)) !== p.cnf.jkt) return bindingFailed;
  } catch {
    return bindingFailed;
  }
  const invalid = { failure: "invocation_invalid" };
  let request;
  try {
    const compact = presentation.invocation;
    if (!compact) return invalid;
    if (!coversInvocation) return bindingFailed;

    const invocation = parseInvocation(compact);
    request = invocation.payload;
    if (!validSignature(invocation, holderKey)) return invalid;
    if (request.iss !== p.client_id || !timingSafeEqual(invocation.leafDigest, sha256(leaf.input)) ||
        !config.verifierIds.includes(request.aud) || !audience(p.aud).includes(request.aud)) return invalid;
    if (!atInstant(request, now) || request.exp > p.exp ||
        request.exp - request.iat > maxLifetime) return invalid;
  } catch {
    return invalid;
  }

  const replayKey = JSON.stringify([request.aud, p.cnf.jkt, request.jti]);
  const failure = recordInvocation(config, replayKey);
  if (failure) return { failure };

  // Request arguments go directly to JCS. I-JSON parsing applies to the JOSE segments.
  let args;
  try {
    const suppliedArgs = presentation.args;
    requireShape(object(suppliedArgs));
    args = canonicalize(suppliedArgs);
    if (!exactMembers(request.args, ["sha256"]) ||
        !timingSafeEqual(digestBytes(request.args.sha256), sha256(args))) return invalid;
  } catch {
    return invalid;
  }
  return { request, args };
}

function consentFailure(trusted, root, instant) {
  try {
    const answers = trusted?.consent ?? [];
    for (const id of root.consent_chain) {
      let active = false;
      let revoked = false;
      for (const row of answers) {
        if (!object(row)) return "status_unknown";
        if (row.trust_anchor_kid !== root.iss || row.consent_id !== id) continue;
        const validAt = parseFixtureInstant(row.valid_at);
        if (!validAt) return "status_unknown";
        if (validAt.seconds !== instant.seconds || validAt.fraction !== instant.fraction ||
            validAt.leapSecond !== instant.leapSecond) continue;
        const value = has(row, "active") ? row.active : undefined;
        if (value === false) revoked = true;
        else if (value === true) active = true;
        else return "status_unknown";
      }
      if (revoked) return "revoked";
      if (!active) return "status_unknown";
    }
  } catch {
    return "status_unknown";
  }
}

function decide(payloads, policies, ceiling, request, args) {
  const lookup = indexDecisions(policies?.decisions);
  if (!Buffer.from(canonicalize(policies.ceiling)).equals(ceiling)) return unsupported;
  const leaf = payloads.at(-1);
  const { action, resource } = request;

  const fixtureMandate = new Set(policies.mandate);
  for (const { mandate } of payloads) {
    if (!mandate) continue;
    const entries = new Set(mandate.policy_set);
    if (entries.size !== fixtureMandate.size || [...entries].some((entry) => !fixtureMandate.has(entry))) {
      return unsupported;
    }
    const decision = lookup("mandate", action, resource, args);
    if (decision === undefined) return unsupported;
    if (decision !== "permit") return "mandate_denied";
  }
  const decision = lookup(leaf.ceiling_ref, action, resource, args);
  if (decision === undefined) return unsupported;
  return decision === "permit" ? "permit" : "ceiling_denied";
}

function readLimit(config, name) {
  let limit;
  try {
    limit = config?.[name];
  } catch (cause) {
    throw new TypeError("Cannot read " + name, { cause });
  }
  if (!Number.isSafeInteger(limit) || limit <= 0) {
    throw new TypeError(name + " must be a positive safe integer");
  }
  return limit;
}

/**
 * Verify one presentation at the supplied instant under the fixture profile.
 * The evaluation instant may be RFC 3339 text or a Date-like object with integer milliseconds.
 * Returns the first refusal or permit and the trusted inputs consumed in order.
 * Throws TypeError if any configured limit is missing, invalid or unreadable.
 * The caller owns config.replay and shares it across applicable presentations.
 */
export function verify(presentation, trusted, config, at) {
  const maxTokens = readLimit(config, "maxTokens");
  const maxBytes = readLimit(config, "maxBytes");
  const maxInvocationLifetimeSeconds = readLimit(config, "maxInvocationLifetimeSeconds");
  const trustedInputsUsed = [];
  const result = (outcome) => ({ outcome, trustedInputsUsed });

  // 1. Parse every token and enforce limits before signature work.
  const chain = [];
  try {
    const suppliedChain = presentation?.chain;
    if (!Array.isArray(suppliedChain)) return result("malformed");
    const count = suppliedChain.length;
    if (!Number.isSafeInteger(count) || count <= 0 || count > maxTokens) return result("malformed");
    let size = 0;
    for (let i = 0; i < count; i++) {
      const compact = suppliedChain[i];
      if (typeof compact !== "string") return result("malformed");
      size += Buffer.byteLength(compact);
      if (size > maxBytes) return result("malformed");
      chain.push(compact);
    }
  } catch {
    return result("malformed");
  }
  let tokens;
  try {
    tokens = chain.map(parseChainToken);
  } catch (error) {
    return result(error instanceof NonCanonical ? "non_canonical" : "malformed");
  }
  const payloads = tokens.map((token) => token.payload);
  const root = payloads[0];
  const anchorId = root.iss;

  // 2. Verify the root and the signer of every child.
  try {
    if (!has(config.trustAnchors, anchorId) ||
        !validSignature(tokens[0], decodeStdB64(config.trustAnchors[anchorId]))) {
      return result("signature_invalid");
    }
  } catch {
    return result("signature_invalid");
  }
  for (let i = 1; i < tokens.length; i++) {
    const parent = payloads[i - 1];
    const token = tokens[i];
    if (token.payload.iss !== parent.client_id || okpThumbprint(token.header.jwk.x) !== parent.cnf.jkt ||
        !validSignature(token, token.key)) return result("signature_invalid");
  }

  // 3. Bind each child to its parent and check the ordered chain positions.
  if (root.parent_chain.length !== 0 || root.del_depth !== 0) return result("linkage_invalid");
  for (let i = 1; i < tokens.length; i++) {
    const parent = payloads[i - 1];
    const child = payloads[i];
    if (!timingSafeEqual(tokens[i].parentDigest, sha256(tokens[i - 1].input))) {
      return result("par_hash_mismatch");
    }
    if (child.del_depth !== parent.del_depth + 1 || child.parent_chain.length !== child.del_depth ||
        !sameArray(child.parent_chain, [...parent.parent_chain, parent.jti])) return result("linkage_invalid");
  }

  // 4. Check principal and consent invariance.
  if (payloads.some((p) => p.sub !== root.sub)) return result("principal_altered");
  if (payloads.some((p) => !sameArray(p.consent_chain, root.consent_chain))) return result("consent_altered");

  // 5. Check fixture effects, grant coverage and mandate narrowing.
  const mandates = payloads.map((p) => p.mandate?.policy_set);
  const hasMandate = mandates.some(Boolean);
  if (hasMandate) trustedInputsUsed.push("policy_fixture");
  try {
    const widened = attenuation(payloads, mandates, hasMandate ? trusted?.policies : undefined);
    if (widened) return result(widened);
  } catch {
    return result(unsupported);
  }

  // 6. Check the time window and time attenuation of every hop.
  let instant;
  try {
    instant = typeof at === "string" ? parseFixtureInstant(at) : dateInstant(at?.getTime());
  } catch {
    return result("expired");
  }
  if (!instant) return result("expired");
  const nanoseconds = Number(instant.fraction.slice(0, 9).padEnd(9, "0"));
  const now = { seconds: instant.seconds, fraction: nanoseconds / 1e9 };
  if (payloads.some((p, i) => !atInstant(p, now) ||
      (i > 0 && (p.exp > payloads[i - 1].exp || p.iat < payloads[i - 1].iat)))) {
    return result("expired");
  }

  // 7. Validate the configured ceiling bytes and check every token's reference.
  try {
    const ceilings = config.ceilings;
    if (!object(ceilings)) return result(unsupported);
    for (const ref of Object.getOwnPropertyNames(ceilings)) {
      const bytes = ceilings[ref];
      if (!types.isUint8Array(bytes) || ref !== "sha256:" + sha256(bytes).toString("hex")) {
        return result(unsupported);
      }
    }
    if (payloads.some((p) => !has(ceilings, p.ceiling_ref))) return result("ceiling_unknown");
  } catch {
    return result(unsupported);
  }

  // 8. Refuse unresolved token status before consulting consent.
  if (payloads.some((p) => has(p, "status"))) return result("status_unknown");
  trustedInputsUsed.push("consent_fixture");
  const status = consentFailure(trusted, root, instant);
  if (status) return result(status);

  // 9. Inspect the leaf's audience.
  const leaf = tokens.at(-1);
  try {
    if (!audience(leaf.payload.aud).some((id) => config.verifierIds.includes(id))) return result("audience_mismatch");
  } catch {
    return result("audience_mismatch");
  }

  // 10. Bind the holder and validate the invocation.
  const { failure, request, args } = invocationCheck(
    presentation, trusted, config, maxInvocationLifetimeSeconds, now, leaf, trustedInputsUsed,
  );
  if (failure) return result(failure);

  // 11. Check the leaf grant before consulting the fixture for a decision.
  if (!coversGrant(leaf.payload.grants, request.resource, [request.action])) {
    return result("scope_not_granted");
  }
  if (!hasMandate) trustedInputsUsed.push("policy_fixture");
  try {
    return result(decide(payloads, trusted?.policies, config.ceilings[leaf.payload.ceiling_ref], request, args));
  } catch {
    return result(unsupported);
  }
}
