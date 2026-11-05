// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import {createReceiptQRCanvas, decodeReceiptPNG} from './receipt-qr.js';

test('QR rejects oversized UTF-8 before canvas allocation', async () => {
  await assert.rejects(createReceiptQRCanvas({receipt: {text: 'é'.repeat(800)}}), /1600/);
});
test('PNG rejects malformed and oversized files before image allocation', async () => {
  for (const file of [new Blob(['bad']), new Blob([new Uint8Array(33)]), new Blob([new Uint8Array(4194305)])]) {
    await assert.rejects(decodeReceiptPNG({file}), /PNG/);
  }
});
test('PNG rejects IHDR and dimension limits before image allocation', async () => {
  for (const [width, height] of [[0, 1], [4097, 1], [4096, 4096]]) {
    const bytes = new Uint8Array(33);
    bytes.set([137, 80, 78, 71, 13, 10, 26, 10]);
    const view = new DataView(bytes.buffer);
    view.setUint32(8, 13);
    view.setUint32(12, 0x49484452);
    view.setUint32(16, width);
    view.setUint32(20, height);
    await assert.rejects(decodeReceiptPNG({file: new Blob([bytes])}), /dimensions/);
    view.setUint32(8, 12);
    await assert.rejects(decodeReceiptPNG({file: new Blob([bytes])}), /IHDR/);
  }
});

test('PNG closes bitmap after dimension mismatch and canvas failure', async t => {
  const bytes = new Uint8Array(33);
  bytes.set([137, 80, 78, 71, 13, 10, 26, 10]);
  const view = new DataView(bytes.buffer);
  view.setUint32(8, 13);
  view.setUint32(12, 0x49484452);
  view.setUint32(16, 1);
  view.setUint32(20, 1);
  const file = new Blob([bytes], {type: 'image/png'});
  let closed = 0;
  let bitmapWidth = 2;
  for (const name of ['createImageBitmap', 'document']) {
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, name);
    t.after(() => {
      if (descriptor) Object.defineProperty(globalThis, name, descriptor);
      else delete globalThis[name];
    });
  }
  globalThis.createImageBitmap = async source => {
    assert.equal(source, file);
    return {width: bitmapWidth, height: 1, close() {closed++;}};
  };
  await assert.rejects(decodeReceiptPNG({file}), /dimensions mismatch/);
  assert.equal(closed, 1);
  bitmapWidth = 1;
  const canvas = {width: 0, height: 0, getContext() {return null;}};
  globalThis.document = {createElement() {return canvas;}};
  await assert.rejects(decodeReceiptPNG({file}), /Canvas is unavailable/);
  assert.equal(closed, 2);
  assert.equal(canvas.width, 0);
  assert.equal(canvas.height, 0);
});
