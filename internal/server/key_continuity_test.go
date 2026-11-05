// SPDX-License-Identifier: AGPL-3.0-only
package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"testing"

	"github.com/mandipnotroot/anonce-platform/internal/protocol"
)

func TestServerKeyContinuity(t *testing.T) {
	master := bytes.Repeat([]byte{0x31}, 32)
	deployment := bytes.Repeat([]byte{0x52}, 32)
	first := &Server{master: bytes.Clone(master), deployment: bytes.Clone(deployment)}
	for _, label := range []string{"ca", "receipt", "issuer/synthetic-review"} {
		t.Run(label, func(t *testing.T) {
			plaintext := []byte("synthetic private key fixture, not a deployed key")
			sealed, err := first.crypt(label, plaintext, false)
			if err != nil {
				t.Fatal(err)
			}
			restarted := &Server{master: bytes.Clone(master), deployment: bytes.Clone(deployment)}
			got, err := restarted.crypt(label, sealed, true)
			if err != nil || !bytes.Equal(got, plaintext) {
				t.Fatalf("same master and deployment failed to decrypt: %v", err)
			}
			for _, tc := range []struct {
				name   string
				server *Server
				label  string
				sealed []byte
			}{
				{"wrong master", &Server{master: bytes.Repeat([]byte{0x32}, 32), deployment: deployment}, label, sealed},
				{"wrong deployment", &Server{master: master, deployment: bytes.Repeat([]byte{0x53}, 32)}, label, sealed},
				{"wrong label", restarted, label + "/different", sealed},
				{"empty ciphertext", restarted, label, nil},
				{"truncated nonce", restarted, label, sealed[:1]},
				{"truncated tag", restarted, label, sealed[:len(sealed)-1]},
			} {
				t.Run(tc.name, func(t *testing.T) {
					got, err := tc.server.crypt(tc.label, tc.sealed, true)
					if err == nil || len(got) != 0 {
						t.Fatal("invalid key context or ciphertext returned plaintext")
					}
				})
			}
			tampered := bytes.Clone(sealed)
			tampered[len(tampered)-1] ^= 1
			if got, err := restarted.crypt(label, tampered, true); err == nil || len(got) != 0 {
				t.Fatal("tampered ciphertext returned plaintext")
			}
		})
	}
}

// This checks reopening the same disposable database, not backup restoration.
func TestIntegrationServerKeyRestartContinuity(t *testing.T) {
	s := testServer(t) // Existing explicit opt-in disposable PostgreSQL convention.
	ctx := t.Context()
	h := s.Handler()
	u := newUser(t, s, h)
	orgEnv := signed(t, s, h, u, "org-create", map[string]string{"request_id": protocol.ID(), "name": "Key continuity fixture"}, false)
	org := result(t, request(h, "POST", "/api/member/orgs", orgEnv, u), 201)["id"].(string)
	env := signed(t, s, h, u, "review-create", fakeReviewCreate(1), false)
	v := result(t, request(h, "POST", "/api/member/orgs/"+org+"/reviews", env, u), 201)
	id := v["id"].(string)
	var encrypted, public []byte
	if err := s.member.QueryRow(ctx, "SELECT issuer_private,issuer_public FROM member.reviews WHERE id=$1", id).Scan(&encrypted, &public); err != nil {
		t.Fatal(err)
	}
	before, err := s.crypt("issuer/"+id, encrypted, true)
	if err != nil {
		t.Fatal(err)
	}
	ca := bytes.Clone(s.ca.Public().(ed25519.PublicKey))
	receipt := bytes.Clone(s.receipt.Public().(ed25519.PublicKey))
	receiptID := bytes.Clone(s.receiptID)
	deployment := bytes.Clone(s.deployment)
	certificate := bytes.Clone(s.caDER)
	cfg := s.cfg
	s.Close()
	restarted, err := New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restarted.Close)
	if !bytes.Equal(ca, restarted.ca.Public().(ed25519.PublicKey)) ||
		!bytes.Equal(receipt, restarted.receipt.Public().(ed25519.PublicKey)) ||
		!bytes.Equal(receiptID, restarted.receiptID) ||
		!bytes.Equal(deployment, restarted.deployment) ||
		!bytes.Equal(certificate, restarted.caDER) {
		t.Fatal("persisted signing identity or deployment changed on restart")
	}
	var persisted []byte
	if err := restarted.member.QueryRow(ctx, "SELECT issuer_private FROM member.reviews WHERE id=$1", id).Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encrypted, persisted) {
		t.Fatal("persisted issuer ciphertext changed on restart")
	}
	after, err := restarted.crypt("issuer/"+id, persisted, true)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("existing issuer key failed continuity check: %v", err)
	}
	issuer, err := x509.ParsePKCS1PrivateKey(after)
	if err != nil {
		t.Fatal("decrypted issuer key is not a valid RSA private key")
	}
	if err := issuer.Validate(); err != nil {
		t.Fatal("decrypted issuer private key failed validation")
	}
	gotPublic, err := x509.MarshalPKIXPublicKey(&issuer.PublicKey)
	if err != nil || !bytes.Equal(public, gotPublic) {
		t.Fatal("decrypted issuer key does not match persisted public key")
	}
}
