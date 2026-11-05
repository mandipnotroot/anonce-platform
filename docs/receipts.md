<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Save and verify a receipt

## After submitting a response

The accepted screen appears after the browser verifies the signed receipt
against your pending encrypted response and its signed review descriptor.
Download and keep the PNG receipt card. Its QR code contains the complete signed
receipt, not your response contents or private keys. You do not need to open or
edit JSON. Technical receipt data remains available in the optional disclosure.
Keep the original image: cropping, resizing, or editing its QR code can make it
unreadable. The card's printed text is not proof of authenticity.

If delivery is uncertain, use **Check status**. You can return to the original
signed-in browser to recover pending responses. Do not create a new response
merely because a network request failed; retry the saved pending response.

## Check a saved receipt

1. Choose **Verify receipt** in the navigation (`#/verify-receipt`). Sign-in is
   not required.
2. Choose your downloaded PNG receipt card. The browser reads its QR code locally.
   PNG files must be at most 4 MiB, no more than 4096 pixels in either dimension,
   and no more than 16 million pixels total. Camera scanning is not enabled.
3. The default uses this site's public signing keys. To use a configuration
   obtained through an independently trusted channel, open **Choose which public
   signing keys to trust** and select the independent configuration option.
   Configuration files have a 64 KiB limit. Never trust a key merely because it
   accompanies a receipt or appears in an image.
4. Choose **Verify receipt**. Receipt checking runs locally without uploading
   either file. Loading the website and its current public signing keys still
   requires network requests. An independently obtained configuration can be
   imported if the current site's keys cannot be loaded.

Use **Download this site’s public configuration** inside the signing-key options
to retain trusted public keys for later checks. Keep the configuration's origin and authenticity in mind when
sharing it; its contents are public, but substituting them changes whom you trust.

## Interpret the result

| Result or check | What it establishes |
| --- | --- |
| **Receipt signature verified** | A key in the selected trust configuration signed the deployment's acceptance statement. Historical keys work only while retained in that trusted configuration. |
| Receipt file alone | Signature authenticity, not a match to an independently held original submission. |
| Live submission and reviewer checks | Also bind the encrypted response hash and review context. |
| Signed acceptance time | A server assertion, not an independently trusted timestamp. Other displayed timestamps are not necessarily signed. |

No receipt proves correct answers, permanent storage, complete results, or anonymity. Verification trusts the browser and served code; it does not protect against hostile JavaScript, operators, or network/timing correlation. Database tampering can delete or replay records, roll back history, or remove spend state and reuse stored authorizations through the signing service. A valid receipt does not establish complete database integrity.

If verification fails, check the file and trusted configuration. Do not bypass
failure by trusting a replacement key from an untrusted receipt sender. Current
code supports receipt v2 only; there is no legacy receipt import path.

See [protocol.md](protocol.md) for receipt v2 fields and signature bytes, and [architecture.md](architecture.md) for system trust boundaries.
