// SPDX-License-Identifier: AGPL-3.0-only
package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mandipnotroot/anonce-platform/internal/protocol"
)

func TestIntegrationReviewCreationRoles(t *testing.T) {
	s := testServer(t)
	h := s.Handler()
	owner := newUser(t, s, h)
	org := result(t, request(h, "POST", "/api/member/orgs", signed(t, s, h, owner, "org-create", map[string]string{"request_id": protocol.ID(), "name": "Review creation roles"}, false), owner), 201)["id"].(string)
	path := "/api/member/orgs/" + org + "/reviews"
	for _, tc := range []struct {
		name, role, state string
		status            int
	}{
		{"owner", "owner", "approved", 201},
		{"admin", "admin", "approved", 201},
		{"reviewer", "reviewer", "approved", 201},
		{"respondent", "respondent", "approved", 403},
		{"pending", "reviewer", "pending", 403},
		{"revoked", "reviewer", "revoked", 403},
		{"nonmember", "", "", 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := owner
			if tc.name != "owner" {
				u = newUser(t, s, h)
				if tc.role != "" {
					if _, err := s.member.Exec(t.Context(), "INSERT INTO member.memberships(id,org_id,account_id,role,state) VALUES($1,$2,$3,$4,$5)", protocol.ID(), org, u.id, tc.role, tc.state); err != nil {
						t.Fatal(err)
					}
				}
			}
			p := fakeReviewCreate(1)
			env := signed(t, s, h, u, "review-create", p, false)
			result(t, request(h, "POST", path, env, u), tc.status)
			if tc.status == 201 {
				result(t, request(h, "POST", path, env, u), 200)
				return
			}
			var clean bool
			if err := s.member.QueryRow(t.Context(), "SELECT NOT EXISTS(SELECT 1 FROM member.reviews WHERE id=$1) AND NOT EXISTS(SELECT 1 FROM member.vault_objects WHERE account_id=$2 AND id=$1) AND NOT EXISTS(SELECT 1 FROM member.operations WHERE account_id=$2 AND request_id=$3)", p["review_id"], u.id, p["request_id"]).Scan(&clean); err != nil || !clean {
				t.Fatalf("denied creation left state: clean=%v error=%v", clean, err)
			}
		})
	}
}

func TestIntegrationReviewCreationDemotion(t *testing.T) {
	s := testServer(t)
	h := s.Handler()
	owner, reviewer := newUser(t, s, h), newUser(t, s, h)
	org := result(t, request(h, "POST", "/api/member/orgs", signed(t, s, h, owner, "org-create", map[string]string{"request_id": protocol.ID(), "name": "Creation demotion"}, false), owner), 201)["id"].(string)
	members := "/api/member/orgs/" + org + "/members"
	add := map[string]string{"request_id": protocol.ID(), "email": "user-" + strings.ToLower(reviewer.id) + "@example.test", "role": "reviewer"}
	member := result(t, request(h, "POST", members, signed(t, s, h, owner, "member-add", add, false), owner), 201)["id"].(string)
	path := "/api/member/orgs/" + org + "/reviews"
	p := fakeReviewCreate(1)
	env := signed(t, s, h, reviewer, "review-create", p, false)
	created := result(t, request(h, "POST", path, env, reviewer), 201)
	stale := fakeReviewCreate(1)
	staleEnv := signed(t, s, h, reviewer, "review-create", stale, false)
	role := map[string]string{"request_id": protocol.ID(), "role": "respondent"}
	result(t, request(h, "POST", members+"/"+member+"/role", signed(t, s, h, owner, "member-role", role, false), owner), 200)
	result(t, request(h, "POST", path, staleEnv, reviewer), 403)
	result(t, request(h, "POST", path, env, reviewer), 403)

	// Exercise the transactional check directly so a preflight role check cannot
	// mask an authorization regression before an idempotent result is returned.
	r := httptest.NewRequest(http.MethodPost, path, nil)
	r.SetPathValue("org", org)
	r.AddCookie(&http.Cookie{Name: cookieName, Value: reviewer.cookie})
	a, err := s.session(r)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := s.member.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	x := &verified{Session: a, Account: a.Account, Epoch: a.Epoch, Payload: mustDecode(env.Payload), Proof: env.Proof}
	old, err := operation(r, tx, x, p["request_id"].(string))
	var denied problem
	if old != nil || !errors.As(err, &denied) || denied != (problem{403, "forbidden"}) {
		t.Fatalf("demoted cached creation: result=%s error=%v", old, err)
	}
	// Respondents retain transactional authorization for response issuance.
	issue := httptest.NewRequest(http.MethodPost, "/api/member/reviews/"+created["id"].(string)+"/issuances", nil)
	issue.SetPathValue("id", created["id"].(string))
	if err := transactionAuthorization(issue, tx, x); err != nil {
		t.Fatalf("respondent issuance authorization: %v", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	var clean bool
	if err := s.member.QueryRow(t.Context(), "SELECT NOT EXISTS(SELECT 1 FROM member.reviews WHERE id=$1) AND NOT EXISTS(SELECT 1 FROM member.operations WHERE account_id=$2 AND request_id=$3)", stale["review_id"], reviewer.id, stale["request_id"]).Scan(&clean); err != nil || !clean {
		t.Fatalf("demoted creation left state: clean=%v error=%v", clean, err)
	}
	// Creation demotion does not revoke access to an existing creator's draft.
	result(t, request(h, "GET", "/api/member/reviews/"+created["id"].(string), nil, reviewer), 200)
}
