import { TextDecoder } from "node:util";

/** A refused I-JSON value with a stable failure reason. */
export class IJSONError extends Error {
  constructor(reason, message) {
    super(message === undefined ? reason : message);
    this.name = "IJSONError";
    this.reason = reason;
  }
}

const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const numberToken = /-?(0|[1-9][0-9]*)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?/y;
const stringToken = /"(?:[^"\\\u0000-\u001f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"/y;
const loneSurrogate = /[\ud800-\udfff]/u;
const firstUnsafeInteger = "9007199254740992";

function numberValue(match) {
  const [, whole, fraction = "", exponent = "0"] = match;
  const digits = (whole + fraction).replace(/^0+/, "");
  let end = digits.length;
  while (digits[end - 1] === "0") end--;
  const significant = digits.slice(0, end);
  const shift = Number(exponent) - fraction.length + digits.length - end;
  // Check the exact decimal's integrality and magnitude before rounding.
  if (significant && shift >= 0) {
    const length = significant.length + shift;
    if (length > firstUnsafeInteger.length ||
        (length === firstUnsafeInteger.length &&
         significant.padEnd(length, "0") >= firstUnsafeInteger)) {
      throw new IJSONError("int_range");
    }
  }
  const value = Number(match[0]);
  if (!Number.isFinite(value)) throw new IJSONError("syntax", "Non-finite number");
  return value;
}

/** Parse one I-JSON value from UTF-8 bytes, or throw IJSONError. */
export function parseIJSON(bytes) {
  let source;
  try {
    source = decoder.decode(bytes);
  } catch {
    throw new IJSONError("utf8");
  }

  let pos = 0;
  const stack = [];
  const whitespace = /[ \t\r\n]*/y;

  function skipWhitespace() {
    whitespace.lastIndex = pos;
    whitespace.exec(source);
    pos = whitespace.lastIndex;
  }

  function take(character) {
    if (source[pos] !== character) return false;
    pos++;
    return true;
  }

  function readString() {
    stringToken.lastIndex = pos;
    const match = stringToken.exec(source);
    if (!match) throw new IJSONError("syntax", "Invalid JSON string");
    pos = stringToken.lastIndex;
    const value = JSON.parse(match[0]);
    if (loneSurrogate.test(value)) throw new IJSONError("surrogate");
    for (const character of value) {
      const codePoint = character.codePointAt(0);
      if ((codePoint & 0xffff) >= 0xfffe || (codePoint >= 0xfdd0 && codePoint <= 0xfdef)) {
        throw new IJSONError("syntax", "Unicode noncharacter");
      }
    }
    return value;
  }

  function readValue() {
    skipWhitespace();
    if (take("{")) {
      const value = {};
      stack.push({ value, object: true, end: "}", first: true });
      return value;
    }
    if (take("[")) {
      const value = [];
      stack.push({ value, object: false, end: "]", first: true });
      return value;
    }
    if (source[pos] === '"') return readString();
    for (const [literal, value] of [["true", true], ["false", false], ["null", null]]) {
      if (source.startsWith(literal, pos)) {
        pos += literal.length;
        return value;
      }
    }
    numberToken.lastIndex = pos;
    const match = numberToken.exec(source);
    if (!match) throw new IJSONError("syntax", "Expected a JSON value");
    pos = numberToken.lastIndex;
    return numberValue(match);
  }

  const root = readValue();
  while (stack.length > 0) {
    const frame = stack.at(-1);
    skipWhitespace();
    if (take(frame.end)) {
      stack.pop();
      continue;
    }
    if (!frame.first && !take(",")) throw new IJSONError("syntax", "Expected a comma");
    frame.first = false;
    if (frame.object) {
      skipWhitespace();
      const key = readString();
      if (Object.hasOwn(frame.value, key)) throw new IJSONError("duplicate");
      skipWhitespace();
      if (!take(":")) throw new IJSONError("syntax", "Expected a colon");
      Object.defineProperty(frame.value, key, {
        value: readValue(), enumerable: true, writable: true, configurable: true,
      });
    } else {
      frame.value.push(readValue());
    }
  }
  skipWhitespace();
  if (pos !== source.length) throw new IJSONError("trailing");
  return root;
}
