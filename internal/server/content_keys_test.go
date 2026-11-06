// SPDX-License-Identifier: AGPL-3.0-only
package server

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/mandipnotroot/anonce-platform/internal/protocol"
)

func bindRegistration(t *testing.T, s *Server, u *testUser, p *registration) {
	t.Helper()
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p.Encryption = protocol.B64(private.PublicKey().Bytes())
	p.EncryptionSignature = protocol.B64(ed25519.Sign(u.member, protocol.E("member-encryption-key", s.deployment, mustDecode(p.Account), mustDecode(p.Membership), private.PublicKey().Bytes(), protocol.U64(1))))
}

func testContentEnvelopes(t *testing.T, h http.Handler, u *testUser, id string) []contentKeyEnvelope {
	t.Helper()
	directory := result(t, request(h, "GET", "/api/member/reviews/"+id+"/content-recipients", nil, u), 200)
	envelopes := []contentKeyEnvelope{}
	for _, raw := range directory["items"].([]any) {
		item := raw.(map[string]any)
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		envelopes = append(envelopes, contentKeyEnvelope{1, item["membership_id"].(string), protocol.B64(protocol.Hash(mustDecode(item["encryption_public_key"].(string)))), protocol.B64(key.PublicKey().Bytes()), protocol.B64(protocol.Random(48))})
	}
	return envelopes
}

func TestRegistrationEncryptionBinding(t *testing.T) {
	s := &Server{deployment: protocol.Random(16)}
	_, member, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u := &testUser{id: protocol.ID(), member: member}
	p := registration{Account: u.id, Membership: protocol.B64(member.Public().(ed25519.PublicKey))}
	bindRegistration(t, s, u, &p)
	if _, err = s.registrationEncryption(p, mustDecode(p.Membership)); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*registration){
		"missing":      func(p *registration) { p.Encryption = "" },
		"noncanonical": func(p *registration) { p.Encryption += "=" },
		"low-order":    func(p *registration) { p.Encryption = protocol.B64(make([]byte, 32)) },
		"account":      func(p *registration) { p.Account = protocol.ID() },
		"signature":    func(p *registration) { p.EncryptionSignature = protocol.B64(protocol.Random(64)) },
		"substitution": func(p *registration) {
			key, _ := ecdh.X25519().GenerateKey(rand.Reader)
			p.Encryption = protocol.B64(key.PublicKey().Bytes())
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := p
			mutate(&changed)
			if _, err := s.registrationEncryption(changed, mustDecode(p.Membership)); err == nil {
				t.Fatal("accepted invalid binding")
			}
		})
	}
	other := &Server{deployment: protocol.Random(16)}
	if _, err = other.registrationEncryption(p, mustDecode(p.Membership)); err == nil {
		t.Fatal("accepted other deployment")
	}
	// Even a genuine identity signature cannot authorize unusable X25519 input.
	lowOrder := p
	lowOrder.Encryption = protocol.B64(make([]byte, 32))
	lowOrder.EncryptionSignature = protocol.B64(ed25519.Sign(member, protocol.E("member-encryption-key", s.deployment, mustDecode(p.Account), mustDecode(p.Membership), make([]byte, 32), protocol.U64(1))))
	if _, err = s.registrationEncryption(lowOrder, mustDecode(p.Membership)); err == nil {
		t.Fatal("accepted signed low-order key")
	}
}

func TestContentKeyEnvelopeValidation(t *testing.T) {
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope := contentKeyEnvelope{1, protocol.ID(), protocol.B64(protocol.Random(32)), protocol.B64(private.PublicKey().Bytes()), protocol.B64(protocol.Random(48))}
	if !envelope.valid() {
		t.Fatal("valid envelope rejected")
	}
	envelope.Enc = protocol.B64(make([]byte, 32))
	if envelope.valid() {
		t.Fatal("low-order encapsulation accepted")
	}
}

func TestIntegrationContentKeyDelivery(t *testing.T) {
	s := testServer(t)
	h := s.Handler()
	owner := newUser(t, s, h)
	member := newUser(t, s, h)
	later := newUser(t, s, h)
	org := result(t, request(h, "POST", "/api/member/orgs", signed(t, s, h, owner, "org-create", map[string]string{"request_id": protocol.ID(), "name": "Content keys"}, false), owner), 201)["id"].(string)
	add := func(u *testUser) string {
		p := map[string]string{"request_id": protocol.ID(), "email": "user-" + u.id + "@example.test", "role": "respondent"}
		// Account email normalization uses lowercase canonical addresses.
		p["email"] = "user-" + strings.ToLower(u.id) + "@example.test"
		return result(t, request(h, "POST", "/api/member/orgs/"+org+"/members", signed(t, s, h, owner, "member-add", p, false), owner), 201)["id"].(string)
	}
	memberID := add(member)
	created := result(t, request(h, "POST", "/api/member/orgs/"+org+"/reviews", signed(t, s, h, owner, "review-create", fakeReviewCreate(1), false), owner), 201)
	id := created["id"].(string)
	path := "/api/member/reviews/" + id
	result(t, request(h, "GET", path+"/content-recipients", nil, member), 403)
	result(t, request(h, "GET", path+"/content-recipients?after=bad", nil, owner), 400)
	envelopes := testContentEnvelopes(t, h, owner, id)
	cert := result(t, request(h, "GET", "/api/member/orgs/"+org+"/certificate", nil, owner), 200)
	contentBytes, _ := json.Marshal(created["encrypted_content"])
	var content encryptedContent
	if err := json.Unmarshal(contentBytes, &content); err != nil {
		t.Fatal(err)
	}
	d := descriptor{V: 3, Deployment: protocol.B64(s.deployment), Review: id, Org: org, Membership: cert["membership_id"].(string), Certificate: cert["certificate"].(string), Content: content, Recipient: envelopes[0].Enc, Issuer: created["issuer_key_id"].(string), Public: created["issuer_public_key"].(string)}
	raw, _ := json.Marshal(d)
	payload := map[string]any{"request_id": protocol.ID(), "expected_revision": "1", "descriptor": protocol.B64(raw), "descriptor_signature": protocol.B64(ed25519.Sign(owner.member, protocol.E("review-descriptor", raw))), "content_key_envelopes": envelopes[:1]}
	result(t, request(h, "POST", path+"/publish", signed(t, s, h, owner, "review-publish", payload, false), owner), 409)
	var count int
	if err := s.member.QueryRow(t.Context(), "SELECT count(*) FROM member.review_content_keys WHERE review_id=$1", id).Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial envelopes: %d %v", count, err)
	}
	duplicates := []contentKeyEnvelope{envelopes[0], envelopes[0]}
	payload["content_key_envelopes"] = duplicates
	result(t, request(h, "POST", path+"/publish", signed(t, s, h, owner, "review-publish", payload, false), owner), 409)
	wrongKey := append([]contentKeyEnvelope(nil), envelopes...)
	wrongKey[0].Key = protocol.B64(protocol.Random(32))
	payload["content_key_envelopes"] = wrongKey
	result(t, request(h, "POST", path+"/publish", signed(t, s, h, owner, "review-publish", payload, false), owner), 409)
	foreign := append([]contentKeyEnvelope(nil), envelopes...)
	foreign[0].Membership = protocol.ID()
	payload["content_key_envelopes"] = foreign
	result(t, request(h, "POST", path+"/publish", signed(t, s, h, owner, "review-publish", payload, false), owner), 409)
	payload["content_key_envelopes"] = envelopes
	payload["request_id"] = protocol.ID()
	// An approval holding the organization lock must precede a blocked publication.
	racing := newUser(t, s, h)
	racingID := protocol.ID()
	racingCert, err := s.cert(org, racingID, racing.member.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	stale := signed(t, s, h, owner, "review-publish", payload, false)
	tx, err := s.member.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, err = tx.Exec(t.Context(), "SELECT id FROM member.orgs WHERE id=$1 FOR UPDATE", org); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(t.Context(), "INSERT INTO member.memberships(id,org_id,account_id,role,state,certificate) VALUES($1,$2,$3,'respondent','approved',$4)", racingID, org, racing.id, racingCert); err != nil {
		t.Fatal(err)
	}
	response := make(chan *httptest.ResponseRecorder, 1)
	go func() { response <- request(h, "POST", path+"/publish", stale, owner) }()
	if err = tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	conflict := result(t, <-response, 409)
	if conflict["error"].(map[string]any)["code"] != "recipient_set_conflict" {
		t.Fatal(conflict)
	}
	envelopes = testContentEnvelopes(t, h, owner, id)
	payload["content_key_envelopes"] = envelopes
	payload["request_id"] = protocol.ID()
	env := signed(t, s, h, owner, "review-publish", payload, false)
	result(t, request(h, "POST", path+"/publish", env, owner), 200)
	result(t, request(h, "POST", path+"/publish", env, owner), 200)
	payload["content_key_envelopes"] = duplicates
	result(t, request(h, "POST", path+"/publish", signed(t, s, h, owner, "review-publish", payload, false), owner), 409)
	own := result(t, request(h, "GET", path, nil, member), 200)["content_key_envelope"].(map[string]any)
	if own["membership_id"] != memberID {
		t.Fatal("returned another member's envelope")
	}
	listed := result(t, request(h, "GET", "/api/member/orgs/"+org+"/reviews", nil, member), 200)["items"].([]any)[0].(map[string]any)["content_key_envelope"].(map[string]any)
	if listed["membership_id"] != memberID {
		t.Fatal("list returned another envelope")
	}
	add(later)
	if got := result(t, request(h, "GET", path, nil, later), 200)["content_key_envelope"]; got != nil {
		t.Fatal("later member obtained historical key")
	}
	revoke := signed(t, s, h, owner, "member-revoke", map[string]string{"request_id": protocol.ID()}, false)
	result(t, request(h, "POST", "/api/member/orgs/"+org+"/members/"+memberID+"/revoke", revoke, owner), 200)
	result(t, request(h, "GET", path, nil, member), 403)
	if _, err := s.anonymous.Exec(t.Context(), "SELECT * FROM member.review_content_keys"); err == nil {
		t.Fatal("anonymous role read envelopes")
	}
	if _, err := s.member.Exec(t.Context(), "UPDATE member.accounts SET encryption_public=$1 WHERE id=$2", protocol.Random(32), owner.id); err == nil {
		t.Fatal("changed immutable key")
	}
	vault := result(t, request(h, "GET", "/api/member/vault", nil, owner), 200)
	if _, err := protocol.Decode(vault["encryption_public_key"].(string), 32); err != nil {
		t.Fatal(err)
	}
	if _, err := protocol.Decode(vault["encryption_key_signature"].(string), 64); err != nil {
		t.Fatal(err)
	}
	// Seed synthetic members without issuing hundreds of HTTP challenges.
	public := mustDecode(vault["encryption_public_key"].(string))
	for range 101 {
		account, membership := protocol.ID(), protocol.ID()
		binding := ed25519.Sign(owner.member, protocol.E("member-encryption-key", s.deployment, mustDecode(account), owner.member.Public().(ed25519.PublicKey), public, protocol.U64(1)))
		if _, err := s.member.Exec(t.Context(), "INSERT INTO member.accounts(id,email,password_public,recovery_public,membership_public,encryption_public,encryption_key_signature,password_kdf,recovery_salt,vault) SELECT $1,$2,password_public,recovery_public,membership_public,encryption_public,$3,password_kdf,recovery_salt,vault FROM member.accounts WHERE id=$4", account, "fixture-"+strings.ToLower(account)+"@example.test", binding, owner.id); err != nil {
			t.Fatal(err)
		}
		certificate, err := s.cert(org, membership, owner.member.Public().(ed25519.PublicKey))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.member.Exec(t.Context(), "INSERT INTO member.memberships(id,org_id,account_id,role,state,certificate) VALUES($1,$2,$3,'respondent','approved',$4)", membership, org, account, certificate); err != nil {
			t.Fatal(err)
		}
	}
	first := result(t, request(h, "GET", path+"/content-recipients", nil, owner), 200)
	if len(first["items"].([]any)) != 100 || first["next"] == nil {
		t.Fatal("directory truncated first page")
	}
	second := result(t, request(h, "GET", path+"/content-recipients?after="+first["next"].(string), nil, owner), 200)
	if len(second["items"].([]any)) != 4 || second["next"] != nil {
		t.Fatal("directory truncated final page")
	}
	ids := []string{}
	for _, page := range []map[string]any{first, second} {
		for _, item := range page["items"].([]any) {
			ids = append(ids, item.(map[string]any)["membership_id"].(string))
		}
	}
	if !slices.IsSorted(ids) {
		t.Fatal("directory order is not bytewise")
	}
	for i := 1; i < len(ids); i++ {
		if ids[i] == ids[i-1] {
			t.Fatal("duplicate directory member")
		}
	}
}
