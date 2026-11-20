// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import test from "node:test";
import { decodedTexts } from "./encoded-payloads.mjs";

const encode = (text) => Buffer.from(text).toString("base64url");

test("walks nested objects and arrays in order", () => {
  const text = JSON.stringify({
    nested: [null, 42, { payload: encode("first marker") }],
    other: [[encode("second marker")]],
  });
  assert.deepEqual(
    [...decodedTexts(text)],
    [text, "first marker", "second marker"],
  );
});

test("recurses through multiple encoded JSON layers", () => {
  const inner = JSON.stringify([encode("plain marker")]);
  const middle = JSON.stringify({ payload: encode(inner) });
  const outer = JSON.stringify([encode(middle)]);
  assert.deepEqual(
    [...decodedTexts(outer)],
    [outer, middle, inner, "plain marker"],
  );
});

test("retains non-JSON originals without decoding them", () => {
  for (const text of ["", "plain marker", "{invalid", encode("plain marker")])
    assert.deepEqual([...decodedTexts(text)], [text]);
});

test("ignores empty and nonmatching strings and tolerates invalid decoded JSON", () => {
  const invalid = "{invalid";
  const text = JSON.stringify([
    "",
    "%%%",
    "YWJj=",
    "has space",
    encode(invalid),
  ]);
  assert.deepEqual([...decodedTexts(text)], [text, invalid]);
});

test("includes encoded plaintext markers without recursing into plaintext", () => {
  const marker = "secret marker";
  const encoded = encode(marker);
  const text = JSON.stringify({ payload: encoded });
  assert.deepEqual([...decodedTexts(text)], [text, marker]);
  const double = JSON.stringify({ payload: encode(encoded) });
  assert.deepEqual([...decodedTexts(double)], [double, encoded]);
});

test("includes exactly five decoded layers and does not inspect the sixth", () => {
  const layers = ["boundary marker"];
  for (let i = 0; i < 6; i++)
    layers.push(JSON.stringify({ payload: encode(layers.at(-1)) }));
  assert.deepEqual([...decodedTexts(layers[5])], layers.slice(0, 6).reverse());
  assert.deepEqual([...decodedTexts(layers[6])], layers.slice(1, 7).reverse());
});
