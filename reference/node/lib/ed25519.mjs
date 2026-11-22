import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import { encodeB64url } from "./b64url.mjs";

const P = (1n << 255n) - 19n;
const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const mod = (n) => ((n % P) + P) % P;

function pow(base, exponent) {
  let result = 1n;
  for (let n = exponent; n > 0n; n >>= 1n) {
    if (n & 1n) result = mod(result * base);
    base = mod(base * base);
  }
  return result;
}

const D = mod(-121665n * pow(121666n, P - 2n));
const SQRT_MINUS_ONE = pow(2n, (P - 1n) / 4n);

function littleEndian(bytes) {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    value = (value << 8n) | BigInt(bytes[i]);
  }
  return value;
}

function decodePoint(bytes) {
  const encoded = littleEndian(bytes);
  const sign = encoded >> 255n;
  const y = encoded & ((1n << 255n) - 1n);
  if (y >= P) return { reason: "noncanonical_y" };

  // RFC 8032 Section 5.1.3 square-root ratio for x² = u/v.
  const u = mod(y * y - 1n);
  const v = mod(D * y * y + 1n);
  const v3 = mod(v * v * v);
  let x = mod(u * v3 * pow(mod(u * v3 * v3 * v), (P - 5n) / 8n));
  if (mod(v * x * x - u) !== 0n) x = mod(x * SQRT_MINUS_ONE);
  if (mod(v * x * x - u) !== 0n) return { reason: "no_point" };
  if (x === 0n && sign === 1n) return { reason: "zero_x_sign" };
  if ((x & 1n) !== sign) x = P - x;
  return { x, y };
}

function isSmallOrder({ x, y }) {
  // Double three times in homogeneous coordinates. For affine points,
  // the two denominators are y² - x² and 2 - y² + x² by the curve equation.
  let z = 1n;
  for (let i = 0; i < 3; i++) {
    const xx = mod(x * x);
    const yy = mod(y * y);
    const dx = mod(yy - xx);
    const dy = mod(2n * z * z - dx);
    [x, y, z] = [mod(2n * x * y * dy), mod((yy + xx) * dx), mod(dx * dy)];
  }
  return x === 0n && y === z;
}

/** Check a raw Ed25519 public key's length, point encoding and order. */
export function checkPublicKey(raw) {
  if (raw.length !== 32) return { ok: false, reason: "key_length" };
  const point = decodePoint(raw);
  if (point.reason) return { ok: false, reason: point.reason };
  if (isSmallOrder(point)) return { ok: false, reason: "small_order" };
  return { ok: true };
}

/** Verify Ed25519 after encoding checks and report whether crypto.verify ran. */
export function verifyEd25519(raw, msg, sig) {
  const key = checkPublicKey(raw);
  if (!key.ok) return { ...key, backendCalled: false };
  const refuse = (reason) => ({ ok: false, reason, backendCalled: false });
  if (sig.length !== 64) return refuse("signature_length");
  const point = decodePoint(sig.subarray(0, 32));
  if (point.reason) return refuse("r_" + point.reason);
  if (littleEndian(sig.subarray(32)) >= L) return refuse("s_range");

  let backendCalled = false;
  try {
    const publicKey = createPublicKey({
      key: { kty: "OKP", crv: "Ed25519", x: encodeB64url(raw) },
      format: "jwk",
    });
    backendCalled = true;
    if (cryptoVerify(null, msg, publicKey, sig)) return { ok: true, backendCalled };
    return { ok: false, reason: "signature_invalid", backendCalled };
  } catch {
    return { ok: false, reason: "backend_error", backendCalled };
  }
}
