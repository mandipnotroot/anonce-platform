// SPDX-License-Identifier: AGPL-3.0-only
package server

import (
	"bytes"
	"encoding/json"
	"maps"
	"slices"
	"testing"

	"github.com/mandipnotroot/anonce-platform/internal/protocol"
)

func fakeContent() encryptedContent {
	return encryptedContent{V: 1, Nonce: protocol.B64(protocol.Random(12)), Ciphertext: protocol.B64(protocol.Random(32))}
}

func mustReviewContent(t *testing.T, view map[string]any) encryptedContent {
	t.Helper()
	b, err := json.Marshal(view["encrypted_content"])
	if err != nil {
		t.Fatal(err)
	}
	var content encryptedContent
	if err := json.Unmarshal(b, &content); err != nil {
		t.Fatal(err)
	}
	return content
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
	b, err := json.Marshal(v.view(""))
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
	d := descriptor{V: 3, Content: fakeContent()}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeDescriptor(b); err != nil {
		t.Fatalf("valid descriptor framing: %v", err)
	}
	d.V = 2
	legacy, _ := json.Marshal(d)
	if _, err := decodeDescriptor(legacy); err == nil {
		t.Fatal("accepted v2 descriptor")
	}
	var fields map[string]any
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"reviewer_account_id", "max_responses", "opens_at", "closes_at", "extra"} {
		fields[name] = nil
		extra, _ := json.Marshal(fields)
		if _, err := decodeDescriptor(extra); err == nil {
			t.Fatalf("accepted extra descriptor field %s", name)
		}
		delete(fields, name)
	}
	delete(fields, "reviewer_certificate")
	missing, _ := json.Marshal(fields)
	if _, err := decodeDescriptor(missing); err == nil {
		t.Fatal("accepted missing descriptor field")
	}
	if _, err := decodeDescriptor(append(b, bytes.Repeat([]byte(" "), 65537-len(b))...)); err == nil {
		t.Fatal("accepted oversized descriptor")
	}
	if _, err := decodeDescriptor(append(b, bytes.Repeat([]byte(" "), 65536-len(b))...)); err != nil {
		t.Fatalf("rejected maximum descriptor size: %v", err)
	}
}

func TestReviewViewFieldAllowlist(t *testing.T) {
	v := &review{ID: "review", Org: "org", Account: "creator", Membership: "member", Content: fakeContent(), Max: 7, Revision: 3, Issued: 4, Accepted: 2, Opens: new(int64(100)), Closes: new(int64(200)), Descriptor: []byte("descriptor"), Signature: []byte("signature")}
	common := []string{"id", "org_id", "is_creator", "encrypted_content", "content_key_envelope", "state", "issuer_public_key", "issuer_key_id"}
	for _, account := range []string{"creator", "other"} {
		t.Run(account, func(t *testing.T) {
			view := v.view(account)
			want := slices.Clone(common)
			if account == "creator" {
				want = append(want, "revision", "max_responses", "opens_at", "closes_at", "issued_count", "accepted_count")
			}
			slices.Sort(want)
			if got := slices.Sorted(maps.Keys(view)); !slices.Equal(got, want) {
				t.Fatalf("view fields %v, want %v", got, want)
			}
			if view["is_creator"] != (account == "creator") {
				t.Fatal("incorrect creator flag")
			}
		})
	}
}
