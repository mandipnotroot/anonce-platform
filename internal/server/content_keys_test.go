// SPDX-License-Identifier: AGPL-3.0-only
package server

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

func testContentEnvelopes(t *testing.T, h http.Handler, u *testUser, id, publication string) []contentKeyEnvelope {
	t.Helper()
	envelopes := []contentKeyEnvelope{}
	after := ""
	for {
		directory := result(t, request(h, "GET", "/api/member/reviews/"+id+"/content-recipients?publication_id="+publication+"&after="+after, nil, u), 200)
		for _, raw := range directory["items"].([]any) {
			item := raw.(map[string]any)
			key, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			envelopes = append(envelopes, contentKeyEnvelope{1, item["membership_id"].(string), protocol.B64(protocol.Hash(mustDecode(item["encryption_public_key"].(string)))), protocol.B64(key.PublicKey().Bytes()), protocol.B64(protocol.Random(48))})
		}
		if directory["next"] == nil {
			break
		}
		after = directory["next"].(string)
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
	if _, err := (&Server{deployment: protocol.Random(16)}).registrationEncryption(p, mustDecode(p.Membership)); err == nil {
		t.Fatal("accepted other deployment")
	}
	p.Encryption = protocol.B64(make([]byte, 32))
	p.EncryptionSignature = protocol.B64(ed25519.Sign(member, protocol.E("member-encryption-key", s.deployment, mustDecode(p.Account), mustDecode(p.Membership), make([]byte, 32), protocol.U64(1))))
	if _, err := s.registrationEncryption(p, mustDecode(p.Membership)); err == nil {
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

func startTestPublication(t *testing.T, s *Server, h http.Handler, u *testUser, created map[string]any) (string, map[string]any) {
	t.Helper()
	id, org := created["id"].(string), created["org_id"].(string)
	cert := result(t, request(h, "GET", "/api/member/orgs/"+org+"/certificate", nil, u), 200)
	contentBytes, _ := json.Marshal(created["encrypted_content"])
	var content encryptedContent
	if err := json.Unmarshal(contentBytes, &content); err != nil {
		t.Fatal(err)
	}
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	d := descriptor{V: 3, Deployment: protocol.B64(s.deployment), Review: id, Org: org, Membership: cert["membership_id"].(string), Certificate: cert["certificate"].(string), Content: content, Recipient: protocol.B64(key.PublicKey().Bytes()), Issuer: created["issuer_key_id"].(string), Public: created["issuer_public_key"].(string)}
	raw, _ := json.Marshal(d)
	payload := map[string]any{"request_id": protocol.ID(), "expected_revision": created["revision"], "descriptor": protocol.B64(raw), "descriptor_signature": protocol.B64(ed25519.Sign(u.member, protocol.E("review-descriptor", raw)))}
	snapshot := result(t, request(h, "POST", "/api/member/reviews/"+id+"/publication", signed(t, s, h, u, "review-publication-start", payload, false), u), 200)
	return snapshot["publication_id"].(string), payload
}

func TestIntegrationContentKeyDelivery(t *testing.T) {
	s := testServer(t)
	h := s.Handler()
	owner, member, later := newUser(t, s, h), newUser(t, s, h), newUser(t, s, h)
	org := result(t, request(h, "POST", "/api/member/orgs", signed(t, s, h, owner, "org-create", map[string]string{"request_id": protocol.ID(), "name": "Content keys"}, false), owner), 201)["id"].(string)
	add := func(u *testUser) string {
		return result(t, request(h, "POST", "/api/member/orgs/"+org+"/members", signed(t, s, h, owner, "member-add", map[string]string{"request_id": protocol.ID(), "email": "user-" + strings.ToLower(u.id) + "@example.test", "role": "respondent"}, false), owner), 201)["id"].(string)
	}
	memberID := add(member)
	created := result(t, request(h, "POST", "/api/member/orgs/"+org+"/reviews", signed(t, s, h, owner, "review-create", fakeReviewCreate(1), false), owner), 201)
	id := created["id"].(string)
	path := "/api/member/reviews/" + id
	result(t, request(h, "GET", path+"/content-recipients", nil, member), 403)
	result(t, request(h, "GET", path+"/content-recipients", nil, owner), 400)
	publication, payload := startTestPublication(t, s, h, owner, created)
	retry := result(t, request(h, "POST", path+"/publication", signed(t, s, h, owner, "review-publication-start", payload, false), owner), 200)
	if retry["publication_id"] != publication {
		t.Fatal("start retry changed snapshot")
	}
	payload["request_id"] = protocol.ID()
	result(t, request(h, "POST", path+"/publication", signed(t, s, h, owner, "review-publication-start", payload, false), owner), 409)
	envelopes := testContentEnvelopes(t, h, owner, id, publication)
	add(later)
	if got := testContentEnvelopes(t, h, owner, id, publication); len(got) != len(envelopes) {
		t.Fatal("approval changed snapshot")
	}
	upload := func(envs []contentKeyEnvelope, code int) {
		t.Helper()
		p := map[string]any{"request_id": protocol.ID(), "publication_id": publication, "content_key_envelopes": envs}
		result(t, request(h, "POST", path+"/publication/envelopes", signed(t, s, h, owner, "review-publication-envelopes", p, false), owner), code)
	}
	upload([]contentKeyEnvelope{envelopes[0], envelopes[0]}, 409)
	wrong := append([]contentKeyEnvelope(nil), envelopes...)
	wrong[1].Key = protocol.B64(protocol.Random(32))
	upload(wrong, 409)
	var count int
	if err := s.member.QueryRow(t.Context(), "SELECT count(*) FROM member.publication_recipients WHERE publication_id=$1 AND enc IS NOT NULL", publication).Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial batch: %d %v", count, err)
	}
	foreign := append([]contentKeyEnvelope(nil), envelopes...)
	foreign[0].Membership = protocol.ID()
	upload(foreign, 409)
	upload(make([]contentKeyEnvelope, 101), 400)
	finalPayload := map[string]any{"request_id": protocol.ID(), "expected_revision": "1", "publication_id": publication}
	result(t, request(h, "POST", path+"/publish", signed(t, s, h, owner, "review-publish", finalPayload, false), owner), 409)
	upload(envelopes[:1], 200)
	finalPayload["request_id"] = protocol.ID()
	result(t, request(h, "POST", path+"/publish", signed(t, s, h, owner, "review-publish", finalPayload, false), owner), 409)
	if got := result(t, request(h, "GET", path, nil, owner), 200)["content_key_envelope"]; got != nil {
		t.Fatal("staging visible")
	}
	upload(envelopes, 409)
	remaining := map[string]any{"request_id": protocol.ID(), "publication_id": publication, "content_key_envelopes": envelopes[1:]}
	batch := signed(t, s, h, owner, "review-publication-envelopes", remaining, false)
	batchResponses := make(chan *httptest.ResponseRecorder, 2)
	for range 2 {
		go func() { batchResponses <- request(h, "POST", path+"/publication/envelopes", batch, owner) }()
	}
	result(t, <-batchResponses, 200)
	result(t, <-batchResponses, 200)
	remaining["content_key_envelopes"] = envelopes[:1]
	result(t, request(h, "POST", path+"/publication/envelopes", signed(t, s, h, owner, "review-publication-envelopes", remaining, false), owner), 409)
	finalPayload["request_id"] = protocol.ID()
	env := signed(t, s, h, owner, "review-publish", finalPayload, false)
	responses := make(chan *httptest.ResponseRecorder, 2)
	for range 2 {
		go func() { responses <- request(h, "POST", path+"/publish", env, owner) }()
	}
	result(t, <-responses, 200)
	result(t, <-responses, 200)
	own := result(t, request(h, "GET", path, nil, member), 200)["content_key_envelope"].(map[string]any)
	if own["membership_id"] != memberID {
		t.Fatal("wrong envelope")
	}
	if got := result(t, request(h, "GET", path, nil, later), 200)["content_key_envelope"]; got != nil {
		t.Fatal("later member received historical key")
	}
	result(t, request(h, "POST", "/api/member/orgs/"+org+"/members/"+memberID+"/revoke", signed(t, s, h, owner, "member-revoke", map[string]string{"request_id": protocol.ID()}, false), owner), 200)
	result(t, request(h, "GET", path, nil, member), 403)
	if _, err := s.anonymous.Exec(t.Context(), "SELECT * FROM member.publication_recipients"); err == nil {
		t.Fatal("anonymous role read staging")
	}
	if _, err := s.member.Exec(t.Context(), "UPDATE member.accounts SET encryption_public=$1 WHERE id=$2", protocol.Random(32), owner.id); err == nil {
		t.Fatal("changed immutable key")
	}
}
