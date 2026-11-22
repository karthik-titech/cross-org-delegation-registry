import { Buffer } from "node:buffer";

/** Error thrown when a base64url or standard base64 string is refused. */
export class B64Error extends Error {
  constructor(message) {
    super(message);
    this.name = "B64Error";
  }
}

function decode(s, encoding, invalid) {
  if (typeof s !== "string" || invalid.test(s)) {
    throw new B64Error("Invalid " + encoding + " alphabet");
  }
  const bytes = Buffer.from(s, encoding);
  if (bytes.toString(encoding) !== s) {
    throw new B64Error("Noncanonical " + encoding + " spelling");
  }
  return bytes;
}

/** Decode canonical unpadded base64url, or throw B64Error. */
export function decodeB64url(s) {
  return decode(s, "base64url", /[^A-Za-z0-9_-]/);
}

/** Encode bytes as unpadded base64url. */
export function encodeB64url(b) {
  return Buffer.from(b).toString("base64url");
}

/** Decode canonical standard base64, including required padding, or throw B64Error. */
export function decodeStdB64(s) {
  return decode(s, "base64", /[^A-Za-z0-9+/=]/);
}
