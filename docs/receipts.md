<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Save and verify a receipt

## After submitting a response

The accepted screen appears after the browser verifies the signed receipt
against your pending encrypted response and its signed review descriptor.
Choose **Download receipt** and keep the JSON file. **Technical details (JSON)**
shows the complete machine-readable receipt without placing it in the main view.

If delivery is uncertain, use **Check status**. You can return to the original
signed-in browser to recover pending responses. Do not create a new response
merely because a network request failed; retry the saved pending response.

## Check a saved receipt

1. Open **Verify a receipt** (`#/verify-receipt`). Sign-in is not required.
2. Choose your receipt file or paste its JSON. The limit is 64 KiB.
3. Choose this deployment's public configuration, or import a configuration
   obtained through an independently trusted channel. Configuration files also
   have a 64 KiB limit. Never trust a key merely because it accompanies a receipt.
4. Choose **Verify receipt**. Receipt checking runs locally without uploading
   either file. Loading the website initially still requires its served assets
   and configuration.

Use **Download current public configuration** to retain trusted public keys for
later checks. Keep the configuration's origin and authenticity in mind when
sharing it; its contents are public, but substituting them changes whom you trust.

## Interpret the result

**Signature verified** means a key in the selected trust configuration signed
the acceptance statement for that deployment. A historical signing key works
only if the trusted configuration retains it. The displayed time is asserted by
the signing server, not independently timestamped.

Checking a receipt file alone does not match it to an independently held original
submission. The live submission and reviewer flows additionally verify the
encrypted response hash and review context. Neither check proves correct
answers, permanent storage, complete results, or anonymity. Verification also
trusts the browser and the code served by the site.

If verification fails, check the file and trusted configuration. Do not bypass
failure by trusting a replacement key from an untrusted receipt sender. Current
code supports receipt v2 only; there is no legacy receipt import path.
