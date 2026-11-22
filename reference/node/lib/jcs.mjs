const loneSurrogate = /[\ud800-\udfff]/u;

function quote(value) {
  if (loneSurrogate.test(value)) throw new TypeError("Lone surrogate");
  return JSON.stringify(value);
}

/** Serialize a JSON value in JCS form, rejecting non-finite numbers. */
export function canonicalize(value) {
  const output = [];
  const ancestors = new Set();
  // Iterate container frames so the JSON depth need not fit the JS call stack.
  const frames = [];
  function emit(item) {
    if (item === null || typeof item === "boolean") {
      output.push(String(item));
    } else if (typeof item === "string") {
      output.push(quote(item));
    } else if (typeof item === "number" && Number.isFinite(item)) {
      output.push(String(item));
    } else if (item !== null && typeof item === "object") {
      if (ancestors.has(item)) throw new TypeError("Circular JSON value");
      const array = Array.isArray(item);
      ancestors.add(item);
      output.push(array ? "[" : "{");
      const keys = array ? null : Object.keys(item).sort();
      frames.push({ item, array, keys, length: array ? item.length : keys.length, index: 0 });
    } else {
      throw new TypeError("Value cannot be serialized as JCS");
    }
  }

  emit(value);
  while (frames.length > 0) {
    const frame = frames.at(-1);
    if (frame.index === frame.length) {
      output.push(frame.array ? "]" : "}");
      ancestors.delete(frame.item);
      frames.pop();
      continue;
    }
    if (frame.index > 0) output.push(",");
    const key = frame.array ? frame.index : frame.keys[frame.index];
    frame.index++;
    if (!frame.array) output.push(quote(key), ":");
    emit(frame.item[key]);
  }
  return output.join("");
}
