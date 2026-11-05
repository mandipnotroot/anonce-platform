// SPDX-License-Identifier: AGPL-3.0-only
import QRCode from "qrcode/lib/browser.js";
import jsQR from "jsqr";

export async function createReceiptQRCanvas({ receipt }) {
  const text = JSON.stringify(receipt);
  if (typeof text !== "string" || new TextEncoder().encode(text).length > 1600)
    throw new Error("Receipt QR payload exceeds 1600 UTF-8 bytes");
  const modules = QRCode.create(text, { errorCorrectionLevel: "Q" }).modules
    .size;
  return QRCode.toCanvas(document.createElement("canvas"), text, {
    errorCorrectionLevel: "Q",
    margin: 4,
    scale: Math.max(8, Math.ceil(512 / (modules + 8))),
    color: { dark: "#000000ff", light: "#ffffffff" },
  });
}

export async function decodeReceiptPNG({ file }) {
  if (
    !file ||
    !Number.isSafeInteger(file.size) ||
    file.size < 33 ||
    file.size > 4 * 1024 * 1024
  )
    throw new Error("Invalid PNG file size (maximum 4 MiB)");
  if (file.type && file.type !== "image/png")
    throw new Error("Only PNG images are supported");
  const header = new Uint8Array(await file.slice(0, 33).arrayBuffer());
  if (
    header.length !== 33 ||
    ![137, 80, 78, 71, 13, 10, 26, 10].every((byte, i) => header[i] === byte)
  )
    throw new Error("Invalid PNG signature");
  const view = new DataView(
    header.buffer,
    header.byteOffset,
    header.byteLength,
  );
  if (view.getUint32(8) !== 13 || view.getUint32(12) !== 0x49484452)
    throw new Error("Invalid PNG IHDR");
  const width = view.getUint32(16),
    height = view.getUint32(20);
  if (
    !width ||
    !height ||
    width > 4096 ||
    height > 4096 ||
    width * height > 16_000_000
  )
    throw new Error("PNG dimensions exceed limits");
  const image = await createImageBitmap(file);
  let canvas;
  try {
    if (image.width !== width || image.height !== height)
      throw new Error("PNG dimensions mismatch");
    canvas = document.createElement("canvas");
    canvas.width = width;
    canvas.height = height;
    const context = canvas.getContext("2d", { willReadFrequently: true });
    if (!context) throw new Error("Canvas is unavailable");
    context.fillStyle = "#fff";
    context.fillRect(0, 0, width, height);
    context.drawImage(image, 0, 0);
    const pixels = context.getImageData(0, 0, width, height);
    const result = jsQR(pixels.data, width, height, {
      inversionAttempts: "dontInvert",
    });
    if (!result) throw new Error("No QR code found in PNG");
    if (result.binaryData.length > 1600)
      throw new Error("Receipt QR payload exceeds 1600 UTF-8 bytes");
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
      new Uint8Array(result.binaryData),
    );
  } finally {
    image.close();
    if (canvas) canvas.width = canvas.height = 0;
  }
}
