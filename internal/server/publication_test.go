// SPDX-License-Identifier: AGPL-3.0-only
package server

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/mandipnotroot/anonce-platform/internal/protocol"
)

func TestIntegrationPublicationLifecycle(t *testing.T) {
	s := testServer(t)
	h := s.Handler()
	u := newUser(t, s, h)
	org := result(t, request(h, "POST", "/api/member/orgs", signed(t, s, h, u, "org-create", map[string]string{"request_id": protocol.ID(), "name": "Publication lifecycle"}, false), u), 201)["id"].(string)
	create := func() map[string]any {
		return result(t, request(h, "POST", "/api/member/orgs/"+org+"/reviews", signed(t, s, h, u, "review-create", fakeReviewCreate(1), false), u), 201)
	}
	t.Run("expiry replacement stale revision delete", func(t *testing.T) {
		v := create()
		id := v["id"].(string)
		path := "/api/member/reviews/" + id
		pub, payload := startTestPublication(t, s, h, u, v)
		if _, err := s.member.Exec(t.Context(), "UPDATE member.review_publications SET expires_at=now()-interval '1 second' WHERE id=$1", pub); err != nil {
			t.Fatal(err)
		}
		result(t, request(h, "GET", path+"/content-recipients?publication_id="+pub, nil, u), 409)
		result(t, request(h, "POST", path+"/publication/envelopes", signed(t, s, h, u, "review-publication-envelopes", map[string]any{"request_id": protocol.ID(), "publication_id": pub, "content_key_envelopes": []contentKeyEnvelope{}}, false), u), 409)
		result(t, request(h, "POST", path+"/publish", signed(t, s, h, u, "review-publish", map[string]any{"request_id": protocol.ID(), "expected_revision": "1", "publication_id": pub}, false), u), 409)
		payload["request_id"] = protocol.ID()
		replacement := result(t, request(h, "POST", path+"/publication", signed(t, s, h, u, "review-publication-start", payload, false), u), 200)["publication_id"].(string)
		if replacement == pub {
			t.Fatal("expired snapshot not replaced")
		}
		content := fakeContent()
		updated := result(t, request(h, "PUT", path, signed(t, s, h, u, "review-update", map[string]any{"request_id": protocol.ID(), "expected_revision": "1", "encrypted_content": content, "max_responses": 1, "opens_at": nil, "closes_at": nil}, false), u), 200)
		result(t, request(h, "GET", path+"/content-recipients?publication_id="+replacement, nil, u), 409)
		pub, _ = startTestPublication(t, s, h, u, updated)
		result(t, request(h, "DELETE", path, signed(t, s, h, u, "review-delete", revisionRequest{protocol.ID(), "2"}, false), u), 200)
		var n int
		if err := s.member.QueryRow(t.Context(), "SELECT count(*) FROM member.publication_recipients WHERE publication_id=$1", pub).Scan(&n); err != nil || n != 0 {
			t.Fatalf("staging survived deletion: %d %v", n, err)
		}
	})
	t.Run("expired signing certificate blocks finalize", func(t *testing.T) {
		v := create()
		id := v["id"].(string)
		path := "/api/member/reviews/" + id
		pub, payload := startTestPublication(t, s, h, u, v)
		envelopes := testContentEnvelopes(t, h, u, id, pub)
		result(t, request(h, "POST", path+"/publication/envelopes", signed(t, s, h, u, "review-publication-envelopes", map[string]any{"request_id": protocol.ID(), "publication_id": pub, "content_key_envelopes": envelopes}, false), u), 200)
		// Simulate a signing leaf expiring between start and finalize without
		// waiting for wall-clock expiration; retain a genuine signature.
		var d descriptor
		if err := json.Unmarshal(mustDecode(payload["descriptor"].(string)), &d); err != nil {
			t.Fatal(err)
		}
		d.Certificate = expiredCert(t, s, org, d.Membership, u.member.Public().(ed25519.PublicKey))
		raw, _ := json.Marshal(d)
		sig := ed25519.Sign(u.member, protocol.E("review-descriptor", raw))
		if _, err := s.member.Exec(t.Context(), "UPDATE member.review_publications SET descriptor=$1,descriptor_signature=$2 WHERE id=$3", raw, sig, pub); err != nil {
			t.Fatal(err)
		}
		result(t, request(h, "POST", path+"/publish", signed(t, s, h, u, "review-publish", map[string]any{"request_id": protocol.ID(), "expected_revision": "1", "publication_id": pub}, false), u), 400)
		var n int
		if err := s.member.QueryRow(t.Context(), "SELECT count(*) FROM member.review_content_keys WHERE review_id=$1", id).Scan(&n); err != nil || n != 0 {
			t.Fatalf("expired cert promoted keys: %d %v", n, err)
		}
	})
}

func TestIntegrationPublicationFrozenPages(t *testing.T) {
	s := testServer(t)
	h := s.Handler()
	u := newUser(t, s, h)
	org := result(t, request(h, "POST", "/api/member/orgs", signed(t, s, h, u, "org-create", map[string]string{"request_id": protocol.ID(), "name": "Frozen pagination"}, false), u), 201)["id"].(string)
	prefix := protocol.ID()[:18]
	// Storage fixtures only: no test HTTP signatures depend on these identities.
	_, err := s.member.Exec(t.Context(), `INSERT INTO member.accounts(id,email,password_public,recovery_public,membership_public,encryption_public,encryption_key_signature,password_kdf,recovery_salt,vault)
 SELECT $1||lpad(i::text,3,'0')||'A',lower($1||i)||'@page.test',password_public,recovery_public,membership_public,encryption_public,encryption_key_signature,password_kdf,recovery_salt,vault FROM member.accounts CROSS JOIN generate_series(1,101) i WHERE id=$2`, prefix, u.id)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.member.Exec(t.Context(), `INSERT INTO member.memberships(id,org_id,account_id,role,state,certificate) SELECT $1||lpad(i::text,3,'0')||'A',$2,$1||lpad(i::text,3,'0')||'A','respondent','approved',certificate FROM member.memberships CROSS JOIN generate_series(1,101) i WHERE account_id=$3 AND org_id=$2`, prefix, org, u.id)
	if err != nil {
		t.Fatal(err)
	}
	v := result(t, request(h, "POST", "/api/member/orgs/"+org+"/reviews", signed(t, s, h, u, "review-create", fakeReviewCreate(1), false), u), 201)
	id := v["id"].(string)
	path := "/api/member/reviews/" + id
	// Start waits behind an organization mutation and freezes the committed
	// roster, rather than reading a pre-lock directory.
	started := make(chan *httptest.ResponseRecorder, 2)
	pub, payload := startTestPublication(t, s, h, u, v)
	if _, err = s.member.Exec(t.Context(), "UPDATE member.review_publications SET expires_at=now()-interval '1 second' WHERE id=$1", pub); err != nil {
		t.Fatal(err)
	}
	payload["request_id"] = protocol.ID()
	env := signed(t, s, h, u, "review-publication-start", payload, false)
	tx, err := s.member.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, err = tx.Exec(t.Context(), "SELECT id FROM member.orgs WHERE id=$1 FOR UPDATE", org); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(t.Context(), "UPDATE member.memberships SET state='revoked' WHERE id=$1", prefix+"001A"); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		go func() { started <- request(h, "POST", path+"/publication", env, u) }()
	}
	if err = tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	frozen := result(t, <-started, 200)
	pub = frozen["publication_id"].(string)
	if retry := result(t, <-started, 200); retry["publication_id"] != pub {
		t.Fatal("concurrent start retry changed snapshot")
	}
	if frozen["recipient_count"] != float64(101) {
		t.Fatal(frozen)
	}
	first := result(t, request(h, "GET", path+"/content-recipients?publication_id="+pub, nil, u), 200)
	if len(first["items"].([]any)) != 100 || first["next"] == nil {
		t.Fatal("missing first page")
	}
	second := result(t, request(h, "GET", path+"/content-recipients?publication_id="+pub+"&after="+first["next"].(string), nil, u), 200)
	if len(second["items"].([]any)) != 1 || second["next"] != nil {
		t.Fatal("wrong final page")
	}
	ids := []string{}
	for _, page := range []map[string]any{first, second} {
		for _, raw := range page["items"].([]any) {
			ids = append(ids, raw.(map[string]any)["membership_id"].(string))
		}
	}
	if !slices.IsSorted(ids) || len(slices.Compact(ids)) != 101 {
		t.Fatal("unstable cursor order")
	}
}
