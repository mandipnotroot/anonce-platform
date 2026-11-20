// SPDX-License-Identifier: AGPL-3.0-only

// Inspection only, not canonical base64url validation. Include decoded plaintext
// as well as JSON, with at most five encoded layers beyond the original text.
export function* decodedTexts(text, depth = 0) {
  yield text;
  if (depth >= 5) return;
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    return;
  }
  function* visit(item) {
    if (typeof item === "string" && /^[A-Za-z0-9_-]+$/.test(item)) {
      const decoded = Buffer.from(item, "base64url").toString("utf8");
      if (decoded.startsWith("{") || decoded.startsWith("["))
        yield* decodedTexts(decoded, depth + 1);
      else yield decoded;
    } else if (item && typeof item === "object")
      for (const child of Object.values(item)) yield* visit(child);
  }
  yield* visit(value);
}
