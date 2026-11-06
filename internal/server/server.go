// SPDX-License-Identifier: AGPL-3.0-only
package server

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mandipnotroot/anonce-platform/db"
	"github.com/mandipnotroot/anonce-platform/internal/protocol"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Config struct{ DatabaseURL, AnonymousURL, Origin, KeyFile, WebDir, SourceURL, ReceiptTrustFile string }
type Server struct {
	member, anonymous                    *pgxpool.Pool
	cfg                                  Config
	master, deployment, caDER, receiptID []byte
	ca, receipt                          ed25519.PrivateKey
	receiptTrust                         protocol.ReceiptTrust
	mu                                   sync.Mutex
	publicRate, sessionRate              rateWindow
}

type rateWindow struct {
	requests int
	start    time.Time
}

func (s *Server) allowRequest(verified bool, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	w := &s.publicRate
	if verified {
		w = &s.sessionRate
	}
	if now.Sub(w.start) > time.Minute {
		w.requests, w.start = 0, now
	}
	if w.requests >= 1200 {
		return false
	}
	w.requests++
	return true
}

// Only registered member operations may spend verified-session capacity.
func memberRateRoute(pattern string) bool {
	switch pattern {
	case "DELETE /api/member/session", "GET /api/member/me", "GET /api/member/vault",
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
		"GET /api/member/reviews/{id}/issuances/{request}", "GET /api/member/reviews/{id}/submissions":
		return true
	}
	return false
}

func sessionChallenge(action string) bool {
	switch action {
	case "vault-write", "password-change", "recovery-rotate", "credential-reset",
		"org-create", "member-add", "member-role", "invite-create", "invite-accept",
		"member-approve", "member-revoke", "certificate-renew", "review-create",
		"review-update", "review-delete", "review-publish", "review-close", "issue":
		return true
	}
	return false
}

func New(ctx context.Context, c Config) (*Server, error) {
	u, e := url.Parse(c.Origin)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("ANONCE_ORIGIN must be an HTTPS origin")
	}
	if c.SourceURL == "" || c.AnonymousURL == "" || c.DatabaseURL == c.AnonymousURL {
		return nil, errors.New("source URL and distinct database URLs required")
	}
	master, e := readMasterKey(c.KeyFile)
	if e != nil {
		return nil, e
	}
	s := &Server{cfg: c, master: master}
	s.member, e = pgxpool.New(ctx, c.DatabaseURL)
	if e != nil {
		return nil, e
	}
	fail := func(e error) (*Server, error) { s.Close(); return nil, e }
	var role string
	var super bool
	if e = s.member.QueryRow(ctx, "SELECT current_user,rolsuper FROM pg_roles WHERE rolname=current_user").Scan(&role, &super); e != nil {
		return fail(e)
	}
	if role != "anonce_member" || super {
		return fail(errors.New("member connection must use non-superuser anonce_member"))
	}
	if e = db.Migrate(ctx, s.member); e != nil {
		return fail(e)
	}
	s.anonymous, e = pgxpool.New(ctx, c.AnonymousURL)
	if e != nil {
		return fail(e)
	}
	if e = s.anonymous.QueryRow(ctx, "SELECT current_user,rolsuper FROM pg_roles WHERE rolname=current_user").Scan(&role, &super); e != nil {
		return fail(e)
	}
	if role != "anonce_anon" || super {
		return fail(errors.New("anonymous connection must use non-superuser anonce_anon"))
	}
	var access bool
	if e = s.anonymous.QueryRow(ctx, "SELECT has_schema_privilege(current_user,'member','USAGE')").Scan(&access); e != nil || access {
		return fail(errors.New("anonymous role can access member schema"))
	}
	if e = s.initKeys(ctx); e != nil {
		return fail(e)
	}
	if e = s.initReceiptTrust(); e != nil {
		return fail(e)
	}
	return s, nil
}
func (s *Server) Close() {
	if s.member != nil {
		s.member.Close()
	}
	if s.anonymous != nil {
		s.anonymous.Close()
	}
}
func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

type problem struct {
	status int
	code   string
}

func (p problem) Error() string { return p.code }
func bad(code string) error     { return problem{400, code} }
func fail(w http.ResponseWriter, e error) {
	status, code := 500, "internal_error"
	var p problem
	if errors.As(e, &p) {
		status, code = p.status, p.code
	}
	var pg *pgconn.PgError
	if errors.As(e, &pg) {
		switch pg.Code {
		case "23505":
			status, code = 409, "conflict"
			if pg.ConstraintName == "accounts_email_key" {
				code = "email_exists"
			}
		case "P0002":
			status, code = 404, "not_found"
		case "55000":
			status, code = 410, "closed"
		}
	}
	write(w, status, map[string]any{"error": map[string]string{"code": code, "message": strings.ReplaceAll(code, "_", " ")}})
}
func body(r *http.Request, v any) error {
	b, e := io.ReadAll(r.Body)
	if e != nil {
		var max *http.MaxBytesError
		if errors.As(e, &max) {
			return problem{413, "body_too_large"}
		}
		return bad("invalid_body")
	}
	if e = protocol.StrictJSON(b, v); e != nil {
		return bad("invalid_json")
	}
	return nil
}
func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { write(w, 200, map[string]string{"status": "ok"}) })
	m.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, c := context.WithTimeout(r.Context(), 2*time.Second)
		defer c()
		if e := s.member.Ping(ctx); e != nil {
			fail(w, problem{503, "unavailable"})
			return
		}
		if e := s.anonymous.Ping(ctx); e != nil {
			fail(w, problem{503, "unavailable"})
			return
		}
		write(w, 200, map[string]string{"status": "ready"})
	})
	m.HandleFunc("GET /api/public/config", func(w http.ResponseWriter, r *http.Request) {
		write(w, 200, map[string]any{"v": 2, "deployment_id": protocol.B64(s.deployment), "origin": s.cfg.Origin, "ca_certificate": protocol.B64(s.caDER), "receipt_keys": s.receiptTrust.ReceiptKeys, "receipt_key_id": protocol.B64(s.receiptID), "source_url": s.cfg.SourceURL})
	})
	m.HandleFunc("GET /api/public/reviews/{id}", s.publicReview)
	m.HandleFunc("POST /api/anon/submissions", s.submit)
	m.HandleFunc("POST /api/anon/receipts/lookup", s.lookup)
	s.authRoutes(m)
	s.orgRoutes(m)
	s.reviewRoutes(m)
	m.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { fail(w, problem{404, "not_found"}) })
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "HEAD" {
			fail(w, problem{405, "method_not_allowed"})
			return
		}
		p := strings.TrimPrefix(filepath.Clean("/"+r.URL.Path), "/")
		if p == "" {
			p = "index.html"
		}
		if !fs.ValidPath(p) {
			http.NotFound(w, r)
			return
		}
		f := filepath.Join(s.cfg.WebDir, p)
		st, e := os.Stat(f)
		if e != nil || st.IsDir() {
			f = filepath.Join(s.cfg.WebDir, "index.html")
		}
		http.ServeFile(w, r, f)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			// Gate failures spend public capacity without inspecting credentials.
			reject := func(e error) {
				if !s.allowRequest(false, time.Now()) {
					e = problem{429, "rate_limited"}
				}
				fail(w, e)
			}
			limit := int64(512 * 1024)
			if strings.HasPrefix(r.URL.Path, "/api/member/") {
				limit = 2304 * 1024
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
			if strings.HasPrefix(r.URL.Path, "/api/anon/") || strings.HasPrefix(r.URL.Path, "/api/public/") {
				if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
					reject(problem{400, "credentials_forbidden"})
					return
				}
			}
			if r.Method != "GET" && r.Method != "HEAD" {
				if r.Header.Get("Origin") != s.cfg.Origin {
					reject(problem{403, "origin_required"})
					return
				}
				media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
				if err != nil || media != "application/json" {
					reject(problem{415, "json_required"})
					return
				}
			}
			_, pattern := m.Handler(r)
			eligible := memberRateRoute(pattern)
			if pattern == "POST /api/member/challenges" {
				// Parse only the bounded body, then restore it for the existing handler.
				b, e := io.ReadAll(r.Body)
				if e != nil {
					var max *http.MaxBytesError
					if errors.As(e, &max) {
						reject(problem{413, "body_too_large"})
					} else {
						reject(bad("invalid_body"))
					}
					return
				}
				var p struct {
					Account string `json:"account_id"`
					Action  string `json:"action"`
					Hash    string `json:"payload_hash"`
				}
				if e = protocol.StrictJSON(b, &p); e != nil {
					reject(bad("invalid_json"))
					return
				}
				r.Body = ioBody(b)
				eligible = sessionChallenge(p.Action)
			}
			verified := false
			if eligible {
				_, e := s.session(r)
				verified = e == nil
			}
			if !s.allowRequest(verified, time.Now()) {
				fail(w, problem{429, "rate_limited"})
				return
			}
		}
		m.ServeHTTP(w, r)
	})
}
