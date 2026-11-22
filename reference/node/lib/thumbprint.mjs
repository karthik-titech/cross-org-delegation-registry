import { createHash } from "node:crypto";

/** Compute the RFC 7638 thumbprint of an Ed25519 OKP JWK's x value. */
export function okpThumbprint(xB64url) {
  const members = JSON.stringify({ crv: "Ed25519", kty: "OKP", x: xB64url });
  return createHash("sha256").update(members).digest("base64url");
}
