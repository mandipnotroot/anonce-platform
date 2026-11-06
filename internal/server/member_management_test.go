// SPDX-License-Identifier: AGPL-3.0-only
package server

import (
	"crypto/ed25519"
	"github.com/mandipnotroot/anonce-platform/internal/protocol"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestNormalizeEmail(t *testing.T) {
	for _, value := range []string{" User+Tag@Example.TEST ", "user+tag@example.test"} {
		got, e := normalizeEmail(value)
		if e != nil || got != "user+tag@example.test" {
			t.Fatalf("normalize %q: %q %v", value, got, e)
		}
	}
	for _, value := range []string{"", "user", "user@", "user@localhost", "Name <user@example.test>", "a b@example.test", "a@@example.test", "a..b@example.test", "ü@example.test", "a@-example.test", "a@example..test", strings.Repeat("a", 255) + "@example.test"} {
		if _, e := normalizeEmail(value); e == nil {
			t.Errorf("accepted %q", value)
		}
	}
}

func TestIntegrationMemberManagement(t *testing.T) {
	s := testServer(t)
	h := s.Handler()
	owner, admin, member, other := newUser(t, s, h), newUser(t, s, h), newUser(t, s, h), newUser(t, s, h)
	email := "user-" + strings.ToLower(owner.id) + "@example.test"
	result(t, request(h, "POST", "/api/member/auth/params", map[string]string{"email": " " + strings.ToUpper(email) + " "}, nil), 200)
	if got := result(t, request(h, "GET", "/api/member/me", nil, owner), 200)["email"]; got != email {
		t.Fatalf("email %v", got)
	}
	duplicate := &testUser{id: protocol.ID(), pw: owner.pw, re: owner.re, member: owner.member}
	p := registration{Request: protocol.ID(), Account: duplicate.id, Email: " " + strings.ToUpper(email) + " ", KDF: kdf{19, protocol.B64(protocol.Random(16)), 65536, 3, 1, 32}, Password: protocol.B64(owner.pw.Public().(ed25519.PublicKey)), RecoverySalt: protocol.B64(protocol.Random(32)), Recovery: protocol.B64(owner.re.Public().(ed25519.PublicKey)), Membership: protocol.B64(owner.member.Public().(ed25519.PublicKey)), PasswordWrap: fakeWrapper(), RecoveryWrap: fakeWrapper()}
	bindRegistration(t, s, duplicate, &p)
	v := result(t, request(h, "POST", "/api/member/register", signed(t, s, h, duplicate, "register", p, true), nil), 409)
	if v["error"].(map[string]any)["code"] != "email_exists" {
		t.Fatal(v)
	}
	org := result(t, request(h, "POST", "/api/member/orgs", signed(t, s, h, owner, "org-create", map[string]string{"request_id": protocol.ID(), "name": "Roles"}, false), owner), 201)["id"].(string)
	path := "/api/member/orgs/" + org + "/members"
	missing := signed(t, s, h, owner, "member-add", map[string]string{"request_id": protocol.ID(), "email": "missing@example.test", "role": "respondent"}, false)
	result(t, request(h, "POST", path, missing, owner), 404)
	add := func(actor *testUser, target *testUser, role string, status int) map[string]any {
		p := map[string]string{"request_id": protocol.ID(), "email": " USER-" + strings.ToUpper(target.id) + "@EXAMPLE.TEST ", "role": role}
		env := signed(t, s, h, actor, "member-add", p, false)
		v := result(t, request(h, "POST", path, env, actor), status)
		if status == 201 {
			result(t, request(h, "POST", path, env, actor), 200)
		}
		return v
	}
	a := add(owner, admin, "admin", 201)
	m := add(admin, member, "respondent", 201)
	add(admin, other, "admin", 403)
	add(member, other, "respondent", 403)
	add(other, other, "respondent", 403)
	add(owner, member, "reviewer", 409)
	result(t, request(h, "GET", path, nil, admin), 200)
	result(t, request(h, "GET", path, nil, member), 403)
	for _, target := range []string{a["id"].(string), m["id"].(string)} {
		env := signed(t, s, h, admin, "member-role", map[string]string{"request_id": protocol.ID(), "role": "admin"}, false)
		result(t, request(h, "POST", path+"/"+target+"/role", env, admin), 403)
	}
	env := signed(t, s, h, admin, "member-revoke", map[string]string{"request_id": protocol.ID()}, false)
	result(t, request(h, "POST", path+"/"+a["id"].(string)+"/revoke", env, admin), 403)
	env = signed(t, s, h, owner, "member-role", map[string]string{"request_id": protocol.ID(), "role": "admin"}, false)
	result(t, request(h, "POST", path+"/"+m["id"].(string)+"/role", env, owner), 200)
	// Concurrent adds cannot overwrite an approved membership or return a false ID.
	racing := newUser(t, s, h)
	ownerAdd := signed(t, s, h, owner, "member-add", map[string]string{"request_id": protocol.ID(), "email": "user-" + strings.ToLower(racing.id) + "@example.test", "role": "admin"}, false)
	adminAdd := signed(t, s, h, admin, "member-add", map[string]string{"request_id": protocol.ID(), "email": "user-" + strings.ToLower(racing.id) + "@example.test", "role": "respondent"}, false)
	var responses [2]*httptest.ResponseRecorder
	var wg sync.WaitGroup
	wg.Go(func() { responses[0] = request(h, "POST", path, ownerAdd, owner) })
	wg.Go(func() { responses[1] = request(h, "POST", path, adminAdd, admin) })
	wg.Wait()
	var storedID, storedRole string
	if e := s.member.QueryRow(t.Context(), "SELECT id,role FROM member.memberships WHERE org_id=$1 AND account_id=$2", org, racing.id).Scan(&storedID, &storedRole); e != nil {
		t.Fatal(e)
	}
	winners := 0
	for _, response := range responses {
		if response.Code == 201 {
			winners++
			got := result(t, response, 201)
			if got["id"] != storedID || got["role"] != storedRole {
				t.Fatal("concurrent add overwritten", got, storedID, storedRole)
			}
		} else {
			result(t, response, 409)
		}
	}
	if winners != 1 {
		t.Fatalf("add winners %d", winners)
	}
	// A previously signed administrator write must fail after demotion.
	stale := signed(t, s, h, admin, "member-add", map[string]string{"request_id": protocol.ID(), "email": "user-" + strings.ToLower(other.id) + "@example.test", "role": "respondent"}, false)
	env = signed(t, s, h, owner, "member-role", map[string]string{"request_id": protocol.ID(), "role": "respondent"}, false)
	result(t, request(h, "POST", path+"/"+a["id"].(string)+"/role", env, owner), 200)
	result(t, request(h, "POST", path, stale, admin), 403)
}
