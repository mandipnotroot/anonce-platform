// SPDX-License-Identifier: AGPL-3.0-only
package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mandipnotroot/anonce-platform/internal/protocol"
)

func TestRateLimitWindows(t *testing.T) {
	s := &Server{}
	now := time.Now()
	for _, verified := range []bool{false, true} {
		for range 1200 {
			if !s.allowRequest(verified, now) {
				t.Fatal("early rejection", verified)
			}
		}
		for range 2000 {
			if s.allowRequest(verified, now.Add(time.Minute)) {
				t.Fatal("accepted at exact boundary", verified)
			}
		}
	}
	if s.publicRate.requests != 1200 || s.sessionRate.requests != 1200 {
		t.Fatal("rejections changed saturated counters")
	}
	for _, verified := range []bool{false, true} {
		if !s.allowRequest(verified, now.Add(time.Minute+time.Nanosecond)) {
			t.Fatal("window did not reset", verified)
		}
	}
}

func TestRateLimitConcurrent(t *testing.T) {
	s := &Server{}
	now := time.Now()
	for _, verified := range []bool{false, true} {
		var accepted atomic.Int64
		var wg sync.WaitGroup
		for range 2400 {
			wg.Go(func() {
				if s.allowRequest(verified, now) {
					accepted.Add(1)
				}
			})
		}
		wg.Wait()
		if accepted.Load() != 1200 {
			t.Fatalf("accepted %d requests", accepted.Load())
		}
	}
}

func TestRateLimitPublicWithoutDatabase(t *testing.T) {
	s := &Server{cfg: Config{Origin: "https://anonce.test"}}
	h := s.Handler()
	for range 1200 {
		result(t, request(h, "GET", "/api/public/config", nil, nil), 200)
	}
	result(t, request(h, "GET", "/api/public/config", nil, nil), 429)
	if s.sessionRate.requests != 0 {
		t.Fatal("public requests spent session capacity")
	}
}

func TestRateLimitInvalidChallengeChargedOnce(t *testing.T) {
	s := &Server{cfg: Config{Origin: "https://anonce.test"}}
	r := httptest.NewRequest("POST", "/api/member/challenges", strings.NewReader("{"))
	r.Header.Set("Origin", s.cfg.Origin)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 400 || s.publicRate.requests != 1 || s.sessionRate.requests != 0 {
		t.Fatalf("status %d, public %d, session %d", w.Code, s.publicRate.requests, s.sessionRate.requests)
	}
}

func TestRateLimitCachedSessionPartition(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, body string
	}{
		{"logout", "DELETE", "/api/member/session", "{}"},
		{"challenge", "POST", "/api/member/challenges", `{"account_id":"AAAAAAAAAAAAAAAAAAAAAA","action":"vault-write","payload_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{cfg: Config{Origin: "https://anonce.test"}}
			s.publicRate = rateWindow{1200, time.Now()}
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			r.Header.Set("Origin", s.cfg.Origin)
			r.Header.Set("Content-Type", "application/json")
			// Only tests seed the private cache; production fills it from session lookup.
			r = r.WithContext(context.WithValue(r.Context(), sessionCacheKey{}, &sessionLookup{
				value: &session{Account: "different-account", CSRF: "required-token"},
			}))
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != 403 || s.sessionRate.requests != 1 || s.publicRate.requests != 1200 {
				t.Fatalf("status %d, session %d, public %d", w.Code, s.sessionRate.requests, s.publicRate.requests)
			}
		})
	}
}

func TestRateLimitCachedSessionPreauthStaysPublic(t *testing.T) {
	for _, action := range []string{"register", "login-password", "login-recovery"} {
		t.Run(action, func(t *testing.T) {
			s := &Server{cfg: Config{Origin: "https://anonce.test"}}
			s.publicRate = rateWindow{1199, time.Now()}
			for _, wantStatus := range []int{400, 429} {
				// An invalid account stops the first request before any database work.
				r := httptest.NewRequest("POST", "/api/member/challenges", strings.NewReader(`{"action":"`+action+`"}`))
				r.Header.Set("Origin", s.cfg.Origin)
				r.Header.Set("Content-Type", "application/json")
				r = r.WithContext(context.WithValue(r.Context(), sessionCacheKey{}, &sessionLookup{
					value: &session{Account: "trusted-test-session"},
				}))
				w := httptest.NewRecorder()
				s.Handler().ServeHTTP(w, r)
				if w.Code != wantStatus || s.publicRate.requests != 1200 || s.sessionRate.requests != 0 {
					t.Fatalf("status %d want %d, public %d, session %d", w.Code, wantStatus, s.publicRate.requests, s.sessionRate.requests)
				}
			}
		})
	}
}

func TestRateLimitSessionExhaustionLeavesPublicAvailable(t *testing.T) {
	s := &Server{cfg: Config{Origin: "https://anonce.test"}}
	h := s.Handler()
	for i := range 1201 {
		r := httptest.NewRequest("DELETE", "/api/member/session", strings.NewReader("{}"))
		r.Header.Set("Origin", s.cfg.Origin)
		r.Header.Set("Content-Type", "application/json")
		r = r.WithContext(context.WithValue(r.Context(), sessionCacheKey{}, &sessionLookup{
			value: &session{CSRF: "required-token"},
		}))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		want := 403
		if i == 1200 {
			want = 429
		}
		if w.Code != want {
			t.Fatalf("request %d status %d want %d", i, w.Code, want)
		}
	}
	result(t, request(h, "GET", "/api/public/config", nil, nil), 200)
	if s.sessionRate.requests != 1200 || s.publicRate.requests != 1 {
		t.Fatalf("session %d, public %d", s.sessionRate.requests, s.publicRate.requests)
	}
}

func TestRateLimitSessionFailureCache(t *testing.T) {
	s := &Server{}
	r := httptest.NewRequest("GET", "/api/member/me", nil)
	if _, err := s.session(r); err == nil {
		t.Fatal("missing cookie accepted")
	}
	cached := r.Context().Value(sessionCacheKey{}).(*sessionLookup)
	// Changing the cookie must not invalidate this request's cached failure.
	r.Header.Set("Cookie", cookieName+"="+protocol.B64(make([]byte, 32)))
	if value, err := s.session(r); value != nil || err != cached.err {
		t.Fatal("cached failure not reused")
	}
	if r.Context().Value(sessionCacheKey{}) != cached {
		t.Fatal("session lookup replaced the failure cache")
	}
}

func TestRateLimitRegisteredMemberRoutes(t *testing.T) {
	s := &Server{}
	m := http.NewServeMux()
	s.authRoutes(m)
	s.orgRoutes(m)
	s.reviewRoutes(m)
	for _, pattern := range []string{
		"DELETE /api/member/session", "GET /api/member/me", "GET /api/member/vault",
		"PUT /api/member/vault/objects/{id}", "POST /api/member/credentials/password",
		"POST /api/member/credentials/recovery", "POST /api/member/credentials/reset",
		"GET /api/member/orgs", "POST /api/member/orgs",
		"GET /api/member/orgs/{org}/members", "POST /api/member/orgs/{org}/members",
		"POST /api/member/orgs/{org}/members/{member}/role", "POST /api/member/orgs/{org}/invites",
		"POST /api/member/invites/accept", "POST /api/member/orgs/{org}/members/{member}/approve",
		"POST /api/member/orgs/{org}/members/{member}/revoke", "GET /api/member/orgs/{org}/certificate",
		"POST /api/member/orgs/{org}/certificate/renew", "GET /api/member/orgs/{org}/reviews",
		"POST /api/member/orgs/{org}/reviews", "GET /api/member/reviews/{id}",
		"GET /api/member/reviews/{id}/content-recipients", "PUT /api/member/reviews/{id}",
		"DELETE /api/member/reviews/{id}", "POST /api/member/reviews/{id}/publish",
		"POST /api/member/reviews/{id}/close", "POST /api/member/reviews/{id}/issuances",
		"GET /api/member/reviews/{id}/issuances/{request}", "GET /api/member/reviews/{id}/submissions",
	} {
		method, path, _ := strings.Cut(pattern, " ")
		path = strings.NewReplacer("{id}", "id", "{org}", "org", "{member}", "member", "{request}", "request").Replace(path)
		_, matched := m.Handler(httptest.NewRequest(method, path, nil))
		if matched != pattern || !memberRateRoute(matched) {
			t.Errorf("route %q matched %q, eligible %v", pattern, matched, memberRateRoute(matched))
		}
	}
	for _, action := range []string{
		"vault-write", "password-change", "recovery-rotate", "credential-reset", "org-create",
		"member-add", "member-role", "invite-create", "invite-accept", "member-approve",
		"member-revoke", "certificate-renew", "review-create", "review-update", "review-delete",
		"review-publish", "review-close", "issue",
	} {
		if !sessionChallenge(action) {
			t.Errorf("session action %q not eligible", action)
		}
	}
	for _, action := range []string{"register", "login-password", "login-recovery", "unknown", ""} {
		if sessionChallenge(action) {
			t.Errorf("public action %q eligible", action)
		}
	}
}

func TestRateLimitClassification(t *testing.T) {
	for _, tc := range []struct{ method, path, body, cookie string }{
		{"GET", "/api/public/config", "", ""},
		{"GET", "/api/public/config", "", protocol.B64(make([]byte, 32))},
		{"POST", "/api/anon/submissions", "{}", protocol.B64(make([]byte, 32))},
		{"GET", "/api/member/unknown", "", protocol.B64(make([]byte, 32))},
		{"GET", "/api/member/me", "", "invalid"},
		{"GET", "/api/member/me", "", protocol.B64(make([]byte, 32))},
		{"POST", "/api/member/auth/params", "{}", ""},
		{"POST", "/api/member/register", "{}", ""},
		{"POST", "/api/member/session", "{}", ""},
		{"POST", "/api/member/challenges", "{", ""},
		{"POST", "/api/member/challenges", `{"action":"register"}`, ""},
		{"POST", "/api/member/challenges", `{"action":"login-password"}`, ""},
		{"POST", "/api/member/challenges", `{"action":"login-recovery"}`, ""},
		{"POST", "/api/member/challenges", `{"action":"unknown"}`, ""},
	} {
		t.Run(tc.method+tc.path+tc.body+tc.cookie, func(t *testing.T) {
			s := &Server{cfg: Config{Origin: "https://anonce.test"}}
			s.publicRate = rateWindow{1200, time.Now()}
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			r.Header.Set("Origin", s.cfg.Origin)
			r.Header.Set("Content-Type", "application/json")
			if tc.cookie != "" {
				r.Header.Set("Cookie", cookieName+"="+tc.cookie)
			}
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != 429 || s.sessionRate.requests != 0 {
				t.Fatalf("status %d, session count %d", w.Code, s.sessionRate.requests)
			}
			_, cached := r.Context().Value(sessionCacheKey{}).(*sessionLookup)
			wantLookup := tc.path == "/api/member/me"
			if cached != wantLookup {
				t.Fatalf("session lookup %v, want %v", cached, wantLookup)
			}
		})
	}
}

func TestRateLimitIntegrationVerifiedSession(t *testing.T) {
	s := testServer(t)
	h := s.Handler()
	u := newUser(t, s, h)
	s.publicRate = rateWindow{1200, time.Now()}
	s.sessionRate = rateWindow{}
	result(t, request(h, "GET", "/api/member/me", nil, u), 200)
	for _, action := range []string{"register", "login-password", "login-recovery"} {
		result(t, request(h, "POST", "/api/member/challenges", map[string]string{"action": action}, u), 429)
	}
	challenge := map[string]string{"account_id": u.id, "action": "vault-write", "payload_hash": protocol.B64(make([]byte, 32))}
	result(t, request(h, "POST", "/api/member/challenges", challenge, u), 200)
	result(t, request(h, "GET", "/api/member/me", nil, &testUser{cookie: protocol.B64(make([]byte, 32))}), 429)
	if _, err := s.member.Exec(context.Background(), "UPDATE member.sessions SET expires_at=now()-interval '1 second' WHERE id_hash=$1", protocol.Hash(mustDecode(u.cookie))); err != nil {
		t.Fatal(err)
	}
	result(t, request(h, "GET", "/api/member/me", nil, u), 429)
	if _, err := s.member.Exec(context.Background(), "UPDATE member.sessions SET expires_at=now()+interval '1 hour' WHERE id_hash=$1", protocol.Hash(mustDecode(u.cookie))); err != nil {
		t.Fatal(err)
	}
	if _, err := s.member.Exec(context.Background(), "UPDATE member.accounts SET epoch=epoch+1 WHERE id=$1", u.id); err != nil {
		t.Fatal(err)
	}
	result(t, request(h, "GET", "/api/member/me", nil, u), 429)
	if s.sessionRate.requests != 2 {
		t.Fatalf("session count %d", s.sessionRate.requests)
	}
}
