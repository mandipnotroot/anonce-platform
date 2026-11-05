// SPDX-License-Identifier: AGPL-3.0-only
package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"github.com/cloudflare/circl/blindsign/blindrsa"
	"github.com/mandipnotroot/anonce-platform/internal/protocol"
	"maps"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"
)

func TestIntegrationQuotaPerMemberTwoAndCloseRace(t *testing.T) {
	s := testServer(t)
	h := s.Handler()
	u := newUser(t, s, h)
	other := newUser(t, s, h)
	ctx := context.Background()
	orgEnv := signed(t, s, h, u, "org-create", map[string]string{"request_id": protocol.ID(), "name": "Quota"}, false)
	org := result(t, request(h, "POST", "/api/member/orgs", orgEnv, u), 201)["id"].(string)
	env := signed(t, s, h, u, "review-create", fakeReviewCreate(2), false)
	v := result(t, request(h, "POST", "/api/member/orgs/"+org+"/reviews", env, u), 201)
	id := v["id"].(string)
	path := "/api/member/reviews/" + id
	// Seed immutable public material directly; descriptor publication is exercised
	// by WholeFlow. This fixture isolates quota/close ordering with two accounts.
	creatorCert := result(t, request(h, "GET", "/api/member/orgs/"+org+"/certificate", nil, u), 200)
	desc, err := json.Marshal(descriptor{V: 3, Deployment: protocol.B64(s.deployment), Review: id, Org: org, Membership: creatorCert["membership_id"].(string), Certificate: creatorCert["certificate"].(string), Content: mustReviewContent(t, v), Recipient: protocol.B64(protocol.Random(32)), Issuer: v["issuer_key_id"].(string), Public: v["issuer_public_key"].(string)})
	if err != nil {
		t.Fatal(err)
	}
	if _, e := s.member.Exec(ctx, "UPDATE member.reviews SET state='published',descriptor=$2 WHERE id=$1", id, desc); e != nil {
		t.Fatal(e)
	}
	if _, e := s.member.Exec(ctx, "INSERT INTO anon.reviews(id,issuer_key_id,issuer_public,descriptor,descriptor_hash,descriptor_signature,state) VALUES($1,$2,$3,$4,$5,$6,'published')", id, v["issuer_key_id"], mustDecode(v["issuer_public_key"].(string)), desc, protocol.Hash(desc), protocol.Random(64)); e != nil {
		t.Fatal(e)
	}
	member := protocol.ID()
	cert, e := s.cert(org, member, other.member.Public().(ed25519.PublicKey))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.member.Exec(ctx, "INSERT INTO member.memberships VALUES($1,$2,$3,'respondent','approved',$4)", member, org, other.id, cert); e != nil {
		t.Fatal(e)
	}
	for _, actor := range []*testUser{u, other} {
		get := result(t, request(h, "GET", path, nil, actor), 200)
		list := result(t, request(h, "GET", "/api/member/orgs/"+org+"/reviews", nil, actor), 200)
		items := list["items"].([]any)
		if len(items) != 1 {
			t.Fatalf("review list length %d", len(items))
		}
		for _, view := range []map[string]any{get, items[0].(map[string]any)} {
			want := []string{"id", "org_id", "is_creator", "encrypted_content", "state", "issuer_public_key", "issuer_key_id"}
			if actor == u {
				want = append(want, "revision", "max_responses", "opens_at", "closes_at", "issued_count", "accepted_count")
			}
			slices.Sort(want)
			if got := slices.Sorted(maps.Keys(view)); !slices.Equal(got, want) || view["is_creator"] != (actor == u) {
				t.Fatalf("unexpected member review view: %v", view)
			}
		}
	}
	pub, e := x509.ParsePKIXPublicKey(mustDecode(v["issuer_public_key"].(string)))
	if e != nil {
		t.Fatal(e)
	}
	client, e := blindrsa.NewClient(blindrsa.SHA384PSSRandomized, pub.(*rsa.PublicKey))
	if e != nil {
		t.Fatal(e)
	}
	prepared, e := client.Prepare(rand.Reader, []byte("quota-test"))
	if e != nil {
		t.Fatal(e)
	}
	blinded, _, e := client.Blind(rand.Reader, prepared)
	if e != nil {
		t.Fatal(e)
	}
	// Operational windows remain enforced without publishing them in descriptors.
	for _, window := range []struct{ opens, closes *int64 }{
		{opens: new(time.Now().Unix() + 3600)},
		{closes: new(time.Now().Unix() - 3600)},
	} {
		if _, e := s.member.Exec(ctx, "UPDATE member.reviews SET opens_at=$2,closes_at=$3 WHERE id=$1", id, window.opens, window.closes); e != nil {
			t.Fatal(e)
		}
		p := map[string]any{"request_id": protocol.ID(), "issuer_key_id": v["issuer_key_id"], "blinded_message": protocol.B64(blinded), "pending_state": vaultWrite{"0", fakeObject()}}
		result(t, request(h, "POST", path+"/issuances", signed(t, s, h, other, "issue", p, false), other), 410)
	}
	if _, e := s.member.Exec(ctx, "UPDATE member.reviews SET opens_at=NULL,closes_at=NULL WHERE id=$1", id); e != nil {
		t.Fatal(e)
	}
	type job struct {
		u   *testUser
		env envelope
	}
	jobs := []job{}
	for _, actor := range []*testUser{u, other} {
		for range 3 {
			p := map[string]any{"request_id": protocol.ID(), "issuer_key_id": v["issuer_key_id"], "blinded_message": protocol.B64(blinded), "pending_state": vaultWrite{"0", fakeObject()}}
			jobs = append(jobs, job{actor, signed(t, s, h, actor, "issue", p, false)})
		}
	}
	responses := make([]*httptest.ResponseRecorder, len(jobs))
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Go(func() { responses[i] = request(h, "POST", path+"/issuances", j.env, j.u) })
	}
	wg.Wait()
	success := map[string]int{}
	for i, w := range responses {
		if w.Code == 200 {
			success[jobs[i].u.id]++
		} else if w.Code != 409 {
			t.Fatalf("quota %d %s", w.Code, w.Body.String())
		}
	}
	if success[u.id] != 2 || success[other.id] != 2 {
		t.Fatalf("quotas %v", success)
	}
	v = result(t, request(h, "GET", path, nil, u), 200)
	if v["issued_count"] != "4" || v["accepted_count"] != "0" {
		t.Fatalf("counters %v", v)
	}
	// Give one actor a spare slot solely for close-vs-issuance concurrency.
	if _, e = s.member.Exec(ctx, "UPDATE member.reviews SET max_responses=3 WHERE id=$1", id); e != nil {
		t.Fatal(e)
	}
	issueEnv := signed(t, s, h, u, "issue", map[string]any{"request_id": protocol.ID(), "issuer_key_id": v["issuer_key_id"], "blinded_message": protocol.B64(blinded), "pending_state": vaultWrite{"0", fakeObject()}}, false)
	closeEnv := signed(t, s, h, u, "review-close", revisionRequest{protocol.ID(), "1"}, false)
	var issueResponse, closeResponse *httptest.ResponseRecorder
	wg.Go(func() { issueResponse = request(h, "POST", path+"/issuances", issueEnv, u) })
	wg.Go(func() { closeResponse = request(h, "POST", path+"/close", closeEnv, u) })
	wg.Wait()
	result(t, closeResponse, 200)
	if issueResponse.Code != 200 && issueResponse.Code != 410 {
		t.Fatalf("close/issue %d %s", issueResponse.Code, issueResponse.Body.String())
	}
}
