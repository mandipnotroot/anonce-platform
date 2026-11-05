// SPDX-License-Identifier: AGPL-3.0-only
import { createReceiptQRCanvas } from "./receipt-qr.bundle.js";

const rounded = (ctx, x, y, width, height, radius) => {
  ctx.beginPath();
  ctx.roundRect(x, y, width, height, radius);
};

export async function renderReceiptPNG({ receipt }) {
  if (!receipt || typeof receipt !== "object") throw new Error("Receipt unavailable.");
  const qr = await createReceiptQRCanvas({ receipt });
  if (!(qr instanceof HTMLCanvasElement)) throw new Error("Receipt QR could not be created.");
  if (qr.width > 992 || qr.height > 992) throw new Error("Receipt QR is too large for this card. Receipt PNG download is unavailable.");

  const canvas = document.createElement("canvas");
  canvas.width = 1200;
  const qrSize = Math.max(qr.width, qr.height);
  canvas.height = 620 + qrSize + 210;
  const ctx = canvas.getContext("2d");
  if (!ctx) throw new Error("Receipt card could not be rendered.");
  ctx.fillStyle = "#f3f5f2";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = "#173d36";
  rounded(ctx, 56, 56, 1088, canvas.height - 112, 36);
  ctx.fill();
  ctx.fillStyle = "#fffdf8";
  rounded(ctx, 76, 76, 1048, canvas.height - 152, 25);
  ctx.fill();

  ctx.fillStyle = "#dc6d48";
  rounded(ctx, 118, 122, 56, 56, 16);
  ctx.fill();
  ctx.fillStyle = "#fffdf8";
  ctx.font = "700 34px Georgia, serif";
  ctx.textAlign = "center";
  ctx.fillText("A", 146, 161);
  ctx.textAlign = "left";
  ctx.fillStyle = "#173d36";
  ctx.font = "700 34px Georgia, serif";
  ctx.fillText("Anonce", 194, 160);
  ctx.fillStyle = "#547069";
  ctx.font = "600 18px Arial, sans-serif";
  ctx.fillText("RESPONSE RECEIPT", 118, 236);
  ctx.fillStyle = "#173d36";
  ctx.font = "700 48px Georgia, serif";
  ctx.fillText("Response accepted", 118, 300);

  ctx.fillStyle = "#edf3ef";
  rounded(ctx, 118, 340, 964, 148, 18);
  ctx.fill();
  ctx.fillStyle = "#547069";
  ctx.font = "600 18px Arial, sans-serif";
  ctx.fillText("ACCEPTED", 150, 386);
  ctx.fillStyle = "#173d36";
  ctx.font = "600 26px Arial, sans-serif";
  ctx.fillText(formatTime(receipt.accepted_at), 150, 431);
  ctx.fillStyle = "#547069";
  ctx.font = "600 18px Arial, sans-serif";
  ctx.fillText("RECEIPT ID", 150, 467);
  ctx.fillStyle = "#173d36";
  ctx.font = "500 19px monospace";
  ctx.fillText(String(receipt.receipt_id ?? "Unavailable"), 320, 467, 720);

  const qrX = Math.round((canvas.width - qr.width) / 2);
  ctx.fillStyle = "#ffffff";
  rounded(ctx, qrX - 28, 532, qr.width + 56, qr.height + 56, 18);
  ctx.fill();
  ctx.drawImage(qr, qrX, 560, qr.width, qr.height);
  const captionY = 600 + qr.height;
  ctx.textAlign = "center";
  ctx.fillStyle = "#173d36";
  ctx.font = "700 24px Arial, sans-serif";
  ctx.fillText("Scan to verify this receipt", 600, captionY);
  ctx.textAlign = "left";
  ctx.fillStyle = "#547069";
  ctx.font = "500 18px Arial, sans-serif";
  ctx.fillText("Acceptance only. This does not prove response contents or storage.", 118, captionY + 58);
  ctx.fillText("Verify at this site: Anonce / Verify receipt", 118, captionY + 92);

  return new Promise((resolve, reject) => {
    canvas.toBlob((blob) => blob ? resolve(blob) : reject(new Error("Receipt PNG could not be created.")), "image/png");
  });
}

function formatTime(value) {
  if (typeof value !== "string" || !/^(0|[1-9]\d*)$/.test(value)) return "Acceptance time unavailable";
  const seconds = BigInt(value);
  if (seconds > 8640000000000n) return `Unix time ${value} (outside display range)`;
  const date = new Date(Number(seconds) * 1000);
  return Number.isNaN(date.getTime()) ? `Unix time ${value}` : date.toLocaleString();
}
