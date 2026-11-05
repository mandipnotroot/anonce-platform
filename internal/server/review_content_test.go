// SPDX-License-Identifier: AGPL-3.0-only
package server

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/mandipnotroot/anonce-platform/internal/protocol"
)

func fakeContent() encryptedContent {
	return encryptedContent{V: 1, Nonce: protocol.B64(protocol.Random(12)), Ciphertext: protocol.B64(protocol.Random(32))}
}

func fakeReviewCreate(max int64) map[string]any {
	id := protocol.ID()
	o := fakeObject()
	o.ID = id
	return map[string]any{"request_id": protocol.ID(), "review_id": id, "encrypted_content": fakeContent(), "max_responses": max, "vault_write": vaultWrite{"0", o}}
}

func TestEncryptedContentFraming(t *testing.T) {
	for _, n := range []int{0, 15, 16, 32784, 32785} {
		c := fakeContent()
		c.Ciphertext = protocol.B64(make([]byte, n))
		if c.valid() != (n >= 16 && n <= 32784) {
			t.Errorf("ciphertext length %d", n)
		}
	}
	c := fakeContent()
	c.V = 2
	if c.valid() {
		t.Fatal("accepted unsupported envelope version")
	}
	c = fakeContent()
	c.Nonce = protocol.B64(make([]byte, 11))
	if c.valid() {
		t.Fatal("accepted short nonce")
	}
	c = fakeContent()
	c.Ciphertext += "="
	if c.valid() {
		t.Fatal("accepted padded base64url")
	}
	for _, b := range []string{
		`{"v":1,"nonce":"","ciphertext":"","title":"secret"}`,
		`{"v":1,"v":1,"nonce":"","ciphertext":""}`,
	} {
		if protocol.StrictJSON([]byte(b), &c) == nil {
			t.Fatal("accepted unknown or duplicate envelope field")
		}
	}
}

func TestEncryptedReviewViewPrivacy(t *testing.T) {
	v := &review{Content: fakeContent()}
	b, err := json.Marshal(v.view())
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{`"title"`, `"description"`, `"questions"`} {
		if bytes.Contains(b, []byte(marker)) {
			t.Fatalf("review view leaked plaintext field %s", marker)
		}
	}
	if !bytes.Contains(b, []byte(`"encrypted_content"`)) {
		t.Fatal("missing ciphertext")
	}
	var d descriptor
	if protocol.StrictJSON([]byte(`{"v":1,"title":"secret","questions":[]}`), &d) == nil {
		t.Fatal("accepted legacy plaintext descriptor")
	}
}

func TestDescriptorFraming(t *testing.T) {
	d := descriptor{V: 2, Content: fakeContent()}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeDescriptor(b); err != nil {
		t.Fatalf("valid descriptor framing: %v", err)
	}
	d.V = 1
	legacy, _ := json.Marshal(d)
	if _, err := decodeDescriptor(legacy); err == nil {
		t.Fatal("accepted v1 descriptor")
	}
	var fields map[string]any
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "opens_at")
	missing, _ := json.Marshal(fields)
	if _, err := decodeDescriptor(missing); err == nil {
		t.Fatal("accepted missing descriptor field")
	}
	if _, err := decodeDescriptor(append(b, bytes.Repeat([]byte(" "), 65537-len(b))...)); err == nil {
		t.Fatal("accepted oversized descriptor")
	}
}
