// SPDX-License-Identifier: AGPL-3.0-only
import { createReceiptQRCanvas } from "./receipt-qr.bundle.js";

export async function renderReceiptPNG({ receipt }) {
  if (!receipt || typeof receipt !== "object")
    throw new Error("Receipt unavailable.");
  const qr = await createReceiptQRCanvas({ receipt });
  if (!(qr instanceof HTMLCanvasElement))
    throw new Error("Receipt QR could not be created.");

  return new Promise((resolve, reject) => {
    qr.toBlob(
      (blob) =>
        blob
          ? resolve(blob)
          : reject(new Error("Receipt PNG could not be created.")),
      "image/png",
    );
  });
}
